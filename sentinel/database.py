"""Small, explicit, additive schema upgrades for the local single-server deployment."""
from pathlib import Path
from contextlib import closing
import sqlite3
import secrets
from datetime import datetime, timezone
from sqlalchemy import event, inspect, text
from .models import db, SchemaVersion, ProviderQuota

SCHEMA_VERSION = 5


def configure_database():
    if db.engine.dialect.name == 'sqlite':
        @event.listens_for(db.engine, 'connect')
        def pragmas(connection, _):
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('PRAGMA busy_timeout=10000')
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA synchronous=FULL')


def sqlite_backup(source, directory):
    """SQLite's online backup API makes a consistent snapshot, including WAL data."""
    source, directory = Path(source).resolve(), Path(directory).resolve()
    if not source.is_file():
        raise ValueError('The database does not exist.')
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    destination = directory / f'sentinel-{stamp}-{secrets.token_hex(4)}.sqlite'
    temporary = destination.with_suffix('.partial')
    try:
        with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=10)) as original:
            with closing(sqlite3.connect(temporary)) as copy:
                original.backup(copy)
                if copy.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('Backup integrity check failed.')
        temporary.replace(destination)
        return destination
    finally:
        temporary.unlink(missing_ok=True)


def ensure_schema(app):
    inspector = inspect(db.engine)
    existing = set(inspector.get_table_names())
    version = 0
    if 'schema_version' in existing:
        with db.engine.connect() as connection:
            version = connection.execute(text('SELECT version FROM schema_version WHERE id=1')).scalar() or 0
    if version > SCHEMA_VERSION:
        raise RuntimeError('Database is newer than this application. Do not downgrade it.')
    if version == SCHEMA_VERSION:
        return
    if existing and db.engine.dialect.name == 'sqlite' and not app.testing:
        sqlite_backup(db.engine.url.database, Path(app.instance_path) / 'backups')
    # create_all only creates missing tables. Legacy columns are upgraded explicitly below.
    db.create_all()
    columns = {c['name'] for c in inspect(db.engine).get_columns('user')}
    additions = {
        'security_version': 'INTEGER NOT NULL DEFAULT 1',
        'totp_secret': 'TEXT NULL', 'totp_pending': 'TEXT NULL',
        'totp_last_step': 'BIGINT NOT NULL DEFAULT -1',
    }
    with db.engine.begin() as connection:
        quote = db.engine.dialect.identifier_preparer.quote
        for name, sql_type in additions.items():
            if name not in columns:
                connection.execute(text(f'ALTER TABLE {quote("user")} ADD COLUMN {quote(name)} {sql_type}'))
        audit_columns={c['name'] for c in inspect(connection).get_columns('audit_event')}
        if 'target_user_id' not in audit_columns:
            connection.execute(text(f'ALTER TABLE {quote("audit_event")} ADD COLUMN {quote("target_user_id")} VARCHAR(36) NULL REFERENCES {quote("user")}(id)'))
        # v1 stored Python None as JSON null; SQL NULL is required for review filters.
        connection.execute(text("UPDATE scan SET reviewed_data=NULL WHERE reviewed_data='null'"))
    from .models import AuditEvent
    for index in AuditEvent.__table__.indexes:
        index.create(db.engine,checkfirst=True)
    row = db.session.get(SchemaVersion, 1)
    if row:
        row.version = SCHEMA_VERSION
    else:
        db.session.add(SchemaVersion(id=1, version=SCHEMA_VERSION))
    if not db.session.get(ProviderQuota, 'virustotal'):
        db.session.add(ProviderQuota(id='virustotal', next_at=0, day='', count=0))
    db.session.commit()
