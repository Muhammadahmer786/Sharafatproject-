from pathlib import Path
import sqlite3
import pytest
from sentinel.models import db, User, SchemaVersion


def test_online_backup_and_offline_restore_preserve_records_and_reject_live_restore(user,app,tmp_path):
    from sentinel.operations import server_lock, restore_database
    from sentinel.database import sqlite_backup
    source=Path(tmp_path)/'test.db'
    backup=sqlite_backup(source,tmp_path/'backups')
    with app.app_context():
        account=db.session.execute(db.select(User)).scalar_one()
        original_name=account.name
        account.name='Changed after backup'; db.session.commit()
        db.session.remove(); db.engine.dispose()
    with server_lock(tmp_path):
        with pytest.raises(RuntimeError,match='running'):
            restore_database(backup,source,tmp_path)
    restore_database(backup,source,tmp_path)
    with app.app_context():
        assert db.session.execute(db.select(User)).scalar_one().name==original_name
    assert (tmp_path/'.session-epoch').is_file()


def test_invalid_backup_never_changes_original_database(user,app,tmp_path):
    from sentinel.operations import restore_database
    bad=tmp_path/'bad.sqlite'; bad.write_bytes(b'not a database')
    with pytest.raises(ValueError):
        restore_database(bad,tmp_path/'test.db',tmp_path)
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(User))==1


def test_upgrade_preserves_legacy_user(tmp_path):
    from sentinel import create_app
    from werkzeug.security import generate_password_hash
    source=tmp_path/'legacy.db'
    with sqlite3.connect(source) as connection:
        connection.execute('CREATE TABLE user (id VARCHAR(36) PRIMARY KEY, name VARCHAR(80) NOT NULL, email VARCHAR(254) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role VARCHAR(20) NOT NULL, enabled BOOLEAN NOT NULL, created_at DATETIME NOT NULL)')
        connection.execute('INSERT INTO user VALUES (?,?,?,?,?,?,?)',('legacy-user','Legacy Name','legacy@example.test',generate_password_hash('Legacy-password-2026!'),'user',1,'2026-01-01 00:00:00'))
    app=create_app({'TESTING':True,'INSTANCE_PATH':str(tmp_path),'SECRET_KEY':'test','SQLALCHEMY_DATABASE_URI':'sqlite:///'+str(source)})
    with app.app_context():
        account=db.session.get(User,'legacy-user')
        assert account.name=='Legacy Name'
        assert account.check_password('Legacy-password-2026!')
        assert account.security_version==1
        assert db.session.get(SchemaVersion,1).version==5
        db.session.remove(); db.engine.dispose()


def test_health_checks_database_and_readiness_reports_native_parser(client,app):
    assert client.get('/health').json['status']=='ok'
    result=client.get('/ready')
    assert result.status_code==503
    assert result.json['status']=='attention_required'
    assert 'test-key' not in result.get_data(as_text=True)


def test_dashboard_does_not_claim_workers_ready_when_unavailable(user,monkeypatch):
    monkeypatch.setattr('sentinel.operations.worker_available',lambda app: (False,'Unavailable'))
    response=user.get('/')
    assert response.get_data(as_text=True).count('Setup required')==2


def test_readiness_checks_the_requested_local_openbin_image(app,monkeypatch):
    from sentinel.operations import readiness
    monkeypatch.setattr('sentinel.operations.worker_available',lambda app: (True,'Available'))
    monkeypatch.setattr('sentinel.container_runtime.shutil.which',lambda name: None)
    with app.app_context():
        checks=readiness(app)['checks']
    assert any(c['name']=='Local OpenBin' and not c['ok'] for c in checks)


@pytest.mark.parametrize('valid',[True,False])
def test_restore_schema_two_upgrades_staged_copy_only(user,app,tmp_path,valid):
    from sentinel.operations import restore_database
    from sentinel.database import sqlite_backup
    source=tmp_path/'test.db'
    backup=sqlite_backup(source,tmp_path/'backups')
    with sqlite3.connect(backup) as connection:
        connection.execute('DROP TABLE external_check')
        connection.execute('UPDATE schema_version SET version=2')
        if not valid: connection.execute('DROP TABLE password_reset')
    with app.app_context():
        account=db.session.execute(db.select(User)).scalar_one(); original=account.name
        account.name='After backup'; db.session.commit(); db.session.remove(); db.engine.dispose()
    if valid:
        restore_database(backup,source,tmp_path)
    else:
        with pytest.raises(ValueError): restore_database(backup,source,tmp_path)
    with sqlite3.connect(backup) as connection:
        assert connection.execute('SELECT version FROM schema_version').fetchone()[0]==2
    with app.app_context():
        assert db.session.get(SchemaVersion,1).version==5
        assert db.session.execute(db.select(User)).scalar_one().name==(original if valid else 'After backup')
        from sentinel.models import ExternalCheck
        assert db.session.query(ExternalCheck).count()==0
