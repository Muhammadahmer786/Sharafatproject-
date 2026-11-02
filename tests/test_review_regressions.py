"""Independent-review regressions: stale sessions, unsafe restores, stalled workers."""
from contextlib import closing
import sqlite3
import sys
import time
import pytest
from sqlalchemy.orm import Session
from sentinel.models import db, User


@pytest.mark.parametrize('action', ['password', 'revoke'])
def test_stale_security_changes_never_reuse_session_version(user, app, action):
    with app.app_context(), Session(db.engine) as first, Session(db.engine) as second:
        a=first.query(User).one(); b=second.get(User,a.id)
        initial=a.security_version
        for account, session in ((a,first),(b,second)):
            if action=='password':
                account.set_password('Unique-new-password-2026!')
            else:
                account.revoke_sessions()
            session.flush()
            issued=account.get_id()
            session.commit()
        assert b.security_version==initial+2
        assert issued==f'{b.id}:{initial+2}'
        first.refresh(a)
        assert a.security_version==initial+2


@pytest.mark.parametrize('damage', ['column','table'])
def test_structurally_invalid_restore_preserves_live_data(user, app, tmp_path, damage):
    from sentinel.database import sqlite_backup
    from sentinel.operations import restore_database
    source=tmp_path/'test.db'
    bad=sqlite_backup(source,tmp_path/'bad-backups')
    with closing(sqlite3.connect(bad)) as conn:
        if damage=='column':
            conn.execute('ALTER TABLE user DROP COLUMN security_version')
        else:
            conn.execute('DROP TABLE rate_bucket')
        conn.execute("UPDATE user SET name='Bad backup data'")
        conn.commit()
    with app.app_context():
        db.session.remove(); db.engine.dispose()
    with pytest.raises(ValueError):
        restore_database(bad,source,tmp_path)
    with closing(sqlite3.connect(source)) as conn:
        assert conn.execute('SELECT name FROM user').fetchone()[0]=='Ayesha'
        assert conn.execute('SELECT security_version FROM user').fetchone()[0]>=1
        assert conn.execute('SELECT count(*) FROM rate_bucket').fetchone()[0]>=0


def test_provider_parent_kills_a_stalled_child(monkeypatch, tmp_path):
    import sentinel.reputation as reputation
    from sentinel.worker_process import run_bounded
    child=tmp_path/'stalled.py'
    child.write_text('import time\ntime.sleep(30)\n')
    calls=[]
    def stalled(command,data,**kwargs):
        calls.append((command,data,kwargs))
        assert kwargs['timeout']<=20
        return run_bounded([sys.executable,'-I',str(child)],b'',timeout=.2)
    monkeypatch.setattr(reputation,'run_bounded',stalled,raising=False)
    start=time.monotonic()
    result=reputation.lookup_hash_bounded('a'*64,'private-test-key')
    assert result['status']=='unavailable'
    assert time.monotonic()-start<5
    command,data,options=calls[0]
    assert 'private-test-key' not in ' '.join(command)
    assert b'private-test-key' in data
    assert 'VIRUSTOTAL_API_KEY' not in options['env']


def test_backup_failure_does_not_starve_jobs(app,monkeypatch):
    import sentinel.jobs as jobs
    class Stop:
        waits=0
        def is_set(self): return self.waits>=2
        def wait(self,seconds): self.waits+=1
    stop=Stop(); calls={'backups':0,'jobs':0}
    def backup(_):
        calls['backups']+=1
        raise OSError('Disk unavailable')
    def job(_): calls['jobs']+=1
    monkeypatch.setattr('sentinel.operations.backup_if_due',backup)
    monkeypatch.setattr(jobs,'run_one_job',job)
    jobs.worker_loop(app,stop)
    assert calls=={'backups':1,'jobs':2}
