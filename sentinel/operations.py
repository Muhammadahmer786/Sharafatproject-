"""Local operator controls. No remote administration or hosting is configured."""
from contextlib import contextmanager, closing
from pathlib import Path
from datetime import datetime, timezone
import os
import secrets
import sqlite3
import subprocess
import logging
import tempfile
from logging.handlers import RotatingFileHandler
from sqlalchemy import text
from sqlalchemy.schema import CreateTable, CreateIndex
from sqlalchemy.dialects import sqlite
from .models import db, User, SchemaVersion, ReputationJob
from .database import sqlite_backup, SCHEMA_VERSION
from .container_runtime import docker_command, worker_timeout


@contextmanager
def server_lock(instance):
    path=Path(instance)/'.server.lock'
    path.parent.mkdir(parents=True,exist_ok=True)
    handle=path.open('a+b')
    try:
        if path.stat().st_size==0:
            handle.write(b'0'); handle.flush()
        handle.seek(0)
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError('The local server is running. Stop it before this operation.') from exc
        yield
    finally:
        handle.close()


def restore_database(backup,destination,instance):
    backup,destination=Path(backup).resolve(),Path(destination).resolve()
    if backup==destination or not backup.is_file() or backup.stat().st_size>256*1024*1024:
        raise ValueError('Choose a separate SQLite backup under 256 MiB.')
    stage=None
    try:
        with closing(sqlite3.connect(backup.as_uri()+'?mode=ro',uri=True)) as source:
            source.execute('PRAGMA trusted_schema=OFF')
            if source.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
                raise ValueError('Backup failed its integrity check.')
            version=source.execute('SELECT version FROM schema_version WHERE id=1').fetchone()
            if not version or version[0] not in (2,3,4,SCHEMA_VERSION):
                raise ValueError('Restore requires a schema-2, schema-3, schema-4 or schema-5 backup.')
            with server_lock(instance):
                # Fully validate and transform a separate database before touching live data.
                destination.parent.mkdir(parents=True,exist_ok=True)
                handle,name=tempfile.mkstemp(prefix='.restore-',suffix='.sqlite',dir=destination.parent)
                os.close(handle)
                stage=Path(name)
                with closing(sqlite3.connect(stage)) as staged:
                    source.backup(staged)
                    staged.execute('PRAGMA trusted_schema=OFF')
                    objects=staged.execute('SELECT name,type FROM sqlite_master').fetchall()
                    if any(kind in ('view','trigger') for _,kind in objects):
                        raise ValueError('Backup contains unsupported database objects.')
                    tables={name for name,kind in objects if kind=='table'}
                    added_tables=set()
                    if version[0]==2:
                        added_tables.add('external_check')
                    if version[0]<4:
                        added_tables.add('account_key')
                    if version[0]<5:
                        added_tables.add('ai_analysis')
                    for table in db.metadata.sorted_tables:
                        if table.name in added_tables and table.name not in tables:
                            staged.execute(str(CreateTable(table).compile(dialect=sqlite.dialect())))
                            for index in table.indexes:
                                staged.execute(str(CreateIndex(index).compile(dialect=sqlite.dialect())))
                            tables.add(table.name)
                        if table.name not in tables:
                            raise ValueError('Backup is missing a required table.')
                        columns={row[1]:row for row in staged.execute(f'PRAGMA table_info("{table.name}")')}
                        if version[0]<4 and table.name=='audit_event' and 'target_user_id' not in columns:
                            staged.execute('ALTER TABLE audit_event ADD COLUMN target_user_id VARCHAR(36) NULL REFERENCES user(id)')
                            staged.execute('CREATE INDEX ix_audit_event_target_user_id ON audit_event(target_user_id)')
                            columns={row[1]:row for row in staged.execute('PRAGMA table_info(audit_event)')}
                        for column in table.columns:
                            if column.name not in columns or bool(columns[column.name][5])!=column.primary_key:
                                raise ValueError('Backup has an incompatible table structure.')
                    if staged.execute('PRAGMA foreign_key_check').fetchone():
                        raise ValueError('Backup contains invalid references.')
                    if version[0]<SCHEMA_VERSION:
                        staged.execute('UPDATE schema_version SET version=? WHERE id=1',(SCHEMA_VERSION,))
                    staged.execute('UPDATE user SET security_version=security_version+1')
                    staged.execute('DELETE FROM password_reset')
                    staged.commit()
                    staged.execute('PRAGMA journal_mode=DELETE')
                    if staged.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
                        raise ValueError('Staged backup failed its integrity check.')
                if destination.exists():
                    sqlite_backup(destination,Path(instance)/'backups')
                    with closing(sqlite3.connect(destination)) as live:
                        checkpoint=live.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
                        if checkpoint[0]:
                            raise RuntimeError('Close every database connection before restoring.')
                        live.execute('PRAGMA journal_mode=DELETE')
                epoch=Path(instance)/'.session-epoch'
                temporary=epoch.with_suffix('.partial')
                temporary.write_text(secrets.token_hex(32),encoding='ascii')
                # Failure here leaves old records intact; a new epoch safely revokes sessions.
                temporary.replace(epoch)
                stage.replace(destination)
    except sqlite3.DatabaseError as exc:
        raise ValueError('This is not a valid Sentinel database backup.') from exc
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)


def backup_if_due(app):
    with app.app_context():
        if db.engine.dialect.name!='sqlite':
            return None
        directory=Path(app.instance_path)/'backups'
        recent=max((p.stat().st_mtime for p in directory.glob('sentinel-*.sqlite')),default=0)
        if datetime.now(timezone.utc).timestamp()-recent<24*3600:
            return None
        return sqlite_backup(db.engine.url.database,directory)


def worker_available(app):
    if app.config['PE_WORKER_MODE']!='docker':
        return False, 'Native parser mode is for demonstrations only'
    return image_available(app.config['PE_WORKER_IMAGE'])


def image_available(image):
    try:
        docker=docker_command()
        result=subprocess.run([*docker,'image','inspect',image],
            capture_output=True,timeout=worker_timeout(docker,5),creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        return (True,'Isolated local worker image available') if result.returncode==0 else (False,'Start Docker and build the local worker image')
    except ValueError as exc:
        return False,str(exc)
    except (OSError,subprocess.TimeoutExpired):
        return False,'Docker is not responding'


def readiness(app):
    checks=[]
    try:
        db.session.execute(text('SELECT 1'))
        version=db.session.get(SchemaVersion,1)
        checks.append({'name':'Database','ok':bool(version and version.version==SCHEMA_VERSION),'detail':'Schema version '+str(version.version if version else 'missing')})
        admins=db.session.execute(db.select(User).where(User.role=='admin',User.enabled.is_(True))).scalars().all()
        checks.append({'name':'Administrator','ok':bool(admins) and all(u.totp_secret for u in admins),'detail':'Create an administrator and enroll its authenticator'})
    except Exception:
        db.session.rollback()
        checks.append({'name':'Database','ok':False,'detail':'Database check failed'})
    ready,detail=worker_available(app)
    checks.append({'name':'File isolation','ok':ready,'detail':detail})
    openbin_ready,openbin_detail=image_available('sentinel-openbin-worker:local')
    checks.append({'name':'Local OpenBin','ok':openbin_ready,'detail':openbin_detail})
    from .local_ai import model_status
    ai_status=model_status(app.config)
    checks.append({'name':'Local AI model','ok':ai_status['available'],'detail':ai_status['message']})
    checks.append({'name':'Account provisioning','ok':not app.config['ALLOW_REGISTRATION'],'detail':'Self-registration should be closed for customer use'})
    backups=list((Path(app.instance_path)/'backups').glob('sentinel-*.sqlite'))
    recent=max((p.stat().st_mtime for p in backups),default=0)
    checks.append({'name':'Metadata backup','ok':datetime.now(timezone.utc).timestamp()-recent<48*3600,'detail':'A verified database snapshot is required at least every 48 hours'})
    return {'status':'ready' if all(c['ok'] for c in checks) else 'attention_required','checks':checks}


class SafeFormatter(logging.Formatter):
    def format(self,record):
        # No exception messages, request bodies, paths, credentials or provider payloads.
        return f'{datetime.now(timezone.utc).isoformat()} {record.levelname} {record.name} application event; inspect readiness and retry the operation'


def configure_logging(app):
    folder=Path(app.instance_path)/'logs'; folder.mkdir(exist_ok=True)
    handler=RotatingFileHandler(folder/'server.log',maxBytes=1024*1024,backupCount=5,encoding='utf-8')
    handler.setFormatter(SafeFormatter()); handler.setLevel(logging.WARNING)
    app.logger.handlers.clear(); app.logger.addHandler(handler); app.logger.propagate=False
