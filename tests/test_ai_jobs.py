import hashlib
import threading
import pytest
from sentinel.models import db, User, AIAnalysis
from sentinel.ai_jobs import AIJobManager, interrupt_pending


def owner_id(app):
    with app.app_context():
        return db.session.execute(db.select(User.id)).scalar_one()


def test_queue_is_bounded_memory_only_and_finishes(user, app, pe_bytes):
    calls = []
    def pipeline(data, filename, config, cancel, progress, identity):
        calls.append((data, filename))
        progress('analysing', 65)
        return {'verdict': 'inconclusive', 'findings': [], 'ai_model_ran': True}
    manager = AIJobManager(app, pipeline=pipeline)
    identities = [manager.submit(owner_id(app), pe_bytes, f'{i}.exe') for i in range(3)]
    with pytest.raises(ValueError, match='busy'):
        manager.submit(owner_id(app), pe_bytes, 'fourth.exe')
    assert manager.run_one()
    with app.app_context():
        row = db.session.get(AIAnalysis, identities[0])
        assert row.state == 'complete' and row.progress == 100
        assert row.result['ai_model_ran']
        assert row.sha256 == hashlib.sha256(pe_bytes).hexdigest()
        assert set(AIAnalysis.__table__.columns.keys()).isdisjoint({'data', 'bytes', 'upload'})
    assert calls == [(pe_bytes, '0.exe')]


def test_cancel_drops_queued_input_and_never_runs(user, app, pe_bytes):
    manager = AIJobManager(app, pipeline=lambda *a: pytest.fail('Cancelled input ran'))
    identity = manager.submit(owner_id(app), pe_bytes, 'sample.exe')
    assert manager.cancel(identity, owner_id(app))
    assert not manager.run_one()
    with app.app_context():
        assert db.session.get(AIAnalysis, identity).state == 'cancelled'
    assert not manager.pending


def test_running_cancel_wins_over_late_result(user, app, pe_bytes):
    entered, release = threading.Event(), threading.Event()
    def pipeline(*args):
        entered.set(); release.wait(5)
        return {'verdict': 'no_indicators'}
    manager = AIJobManager(app, pipeline=pipeline)
    identity = manager.submit(owner_id(app), pe_bytes, 'sample.exe')
    thread = threading.Thread(target=manager.run_one)
    thread.start()
    assert entered.wait(5)
    assert manager.cancel(identity, owner_id(app))
    release.set(); thread.join(5)
    assert not thread.is_alive()
    with app.app_context():
        row = db.session.get(AIAnalysis, identity)
        assert row.state == 'cancelled' and not row.result


def test_restart_interrupts_outstanding_jobs_only(user, app, pe_bytes):
    manager = AIJobManager(app)
    identity = manager.submit(owner_id(app), pe_bytes, 'sample.exe')
    with app.app_context():
        interrupt_pending()
        row = db.session.get(AIAnalysis, identity)
        assert row.state == 'interrupted'
        assert 'resubmit' in row.error.lower()


def test_failure_is_saved_without_inventing_verdict(user, app, pe_bytes):
    def fail(*args):
        raise ValueError('Test bounded worker failure')
    manager = AIJobManager(app, pipeline=fail)
    identity = manager.submit(owner_id(app), pe_bytes, 'sample.exe')
    assert manager.run_one()
    with app.app_context():
        row = db.session.get(AIAnalysis, identity)
        assert row.state == 'failed' and row.result == {}
        assert 'failure' in row.error


def test_other_owner_cannot_cancel(user, app, pe_bytes):
    manager = AIJobManager(app)
    identity = manager.submit(owner_id(app), pe_bytes, 'sample.exe')
    assert not manager.cancel(identity, 'another-user')
    assert identity in manager.pending


def test_shutdown_marks_running_work_interrupted(user, app, pe_bytes):
    entered = threading.Event()
    def pipeline(data, filename, config, cancel, *args):
        entered.set()
        assert cancel.wait(5)
        raise ValueError('Analysis cancelled')
    manager = AIJobManager(app, pipeline=pipeline)
    manager.start()
    identity = manager.submit(owner_id(app), pe_bytes, 'sample.exe')
    assert entered.wait(5)
    manager.stop()
    with app.app_context():
        assert db.session.get(AIAnalysis, identity).state == 'interrupted'


def test_startup_cleans_interrupted_containers_before_new_jobs(user, app, pe_bytes, monkeypatch):
    import sentinel.ai_jobs as jobs
    old = AIJobManager(app)
    identity = old.submit(owner_id(app), pe_bytes, 'sample.exe')
    cleaned = []
    monkeypatch.setattr(jobs, '_cleanup_job', lambda identity: cleaned.append(identity))
    manager = AIJobManager(app)
    manager.start(); manager.stop()
    assert cleaned == [identity]


def test_parent_death_stops_orphan_work_before_process_exit(monkeypatch):
    import sentinel.ai_jobs as jobs
    order = []
    class Parent:
        def is_alive(self): return False
    class Stop:
        def wait(self, seconds): return False
    class Exited(Exception): pass
    monkeypatch.setattr(jobs, '_cleanup_job', lambda identity: order.append(identity))
    def exit_process(code):
        order.append(code)
        raise Exited
    monkeypatch.setattr(jobs.os, '_exit', exit_process)
    with pytest.raises(Exited):
        jobs._watch_parent(Parent(), 'job-id', Stop())
    assert order == ['job-id', 1]


def test_shutdown_serializes_with_in_flight_submission(user, app, pe_bytes, monkeypatch):
    import sentinel.ai_jobs as jobs
    entered, release = threading.Event(), threading.Event()
    original = jobs.audit
    def pause_commit(*args):
        entered.set()
        assert release.wait(5)
        original(*args)
    monkeypatch.setattr(jobs, 'audit', pause_commit)
    manager = AIJobManager(app)
    identities = []
    owner = owner_id(app)
    submitter = threading.Thread(target=lambda: identities.append(manager.submit(owner, pe_bytes, 'sample.exe')))
    submitter.start(); assert entered.wait(5)
    stopping = threading.Thread(target=manager.stop)
    stopping.start()
    release.set(); submitter.join(5); stopping.join(5)
    assert not submitter.is_alive() and not stopping.is_alive()
    with app.app_context():
        assert db.session.get(AIAnalysis, identities[0]).state == 'interrupted'
