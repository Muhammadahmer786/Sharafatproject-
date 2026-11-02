import io
from datetime import timedelta
from sentinel.models import db, Scan, ReputationJob, ProviderQuota, utcnow


def enqueue(user, app, pe_bytes):
    app.config.update(VIRUSTOTAL_API_KEY='test-key', ASYNC_REPUTATION=True)
    response=user.post('/analyze', data={'file': (io.BytesIO(pe_bytes),'sample.exe'), 'hash_consent':'on'})
    assert response.status_code==302
    with app.app_context():
        return db.session.execute(db.select(Scan.id)).scalar_one()


def test_durable_lookup_waits_for_worker_and_survives_restart(user,app,pe_bytes,monkeypatch):
    monkeypatch.setattr('sentinel.reputation.lookup_hash_bounded',lambda *a: {'status':'available','stats':{'malicious':0}})
    scan_id=enqueue(user,app,pe_bytes)
    with app.app_context():
        job=db.session.get(ReputationJob,scan_id)
        assert job.status=='queued'
        assert db.session.get(Scan,scan_id).reputation['status']=='pending'
    from sentinel.jobs import run_one_job
    assert run_one_job(app) is True
    with app.app_context():
        assert db.session.get(Scan,scan_id).reputation['status']=='available'
        assert db.session.get(ReputationJob,scan_id).status=='done'
    assert run_one_job(app) is False


def test_worker_recovers_expired_lease_and_limits_retries(user,app,pe_bytes,monkeypatch):
    scan_id=enqueue(user,app,pe_bytes)
    from sentinel.jobs import run_one_job
    monkeypatch.setattr('sentinel.reputation.lookup_hash_bounded',lambda *a: {'status':'unavailable'})
    with app.app_context():
        job=db.session.get(ReputationJob,scan_id)
        job.status='running'; job.lease_until=utcnow()-timedelta(seconds=1)
        db.session.commit()
    for attempt in range(1,4):
        with app.app_context():
            db.session.get(ProviderQuota,'virustotal').next_at=0
            db.session.get(ReputationJob,scan_id).available_at=utcnow()-timedelta(seconds=1)
            db.session.commit()
        assert run_one_job(app)
        with app.app_context():
            job=db.session.get(ReputationJob,scan_id)
            assert job.attempts==attempt
            assert job.status==('done' if attempt==3 else 'queued')
    with app.app_context():
        assert db.session.get(Scan,scan_id).reputation['status']=='unavailable'


def test_deleting_scan_removes_queued_work(user,app,pe_bytes):
    scan_id=enqueue(user,app,pe_bytes)
    assert user.post(f'/scans/{scan_id}/delete').status_code==302
    with app.app_context():
        assert db.session.get(ReputationJob,scan_id) is None
    from sentinel.jobs import run_one_job
    assert not run_one_job(app)


def test_expired_local_job_cannot_exceed_attempt_budget(user,app,pe_bytes,monkeypatch):
    from sentinel.jobs import run_one_job
    import pytest
    scan_id=enqueue(user,app,pe_bytes)
    with app.app_context():
        job=db.session.get(ReputationJob,scan_id)
        job.status='running'; job.attempts=3; job.lease_until=utcnow()-timedelta(seconds=1)
        db.session.commit()
    monkeypatch.setattr('sentinel.reputation.lookup_hash_bounded',lambda *a:pytest.fail('Retry budget exhausted'))
    run_one_job(app)
    with app.app_context():
        assert db.session.get(ReputationJob,scan_id).status=='done'
        assert db.session.get(ProviderQuota,'virustotal').count==0


def test_scheduler_rotates_after_reservation_not_idle_ticks(app,monkeypatch):
    from sentinel.jobs import worker_loop
    from sentinel.routes import reserve_lookup
    clock=[1800000000]; calls=[]
    def ready_queue(name):
        def process(application):
            with application.app_context():
                if reserve_lookup(): calls.append(name)
        return process
    class Stop:
        ticks=0
        def is_set(self): return self.ticks>=80
        def wait(self,seconds): self.ticks+=1; clock[0]+=seconds
    monkeypatch.setattr('sentinel.routes.time.time',lambda:clock[0])
    monkeypatch.setattr('sentinel.operations.backup_if_due',lambda app:None)
    monkeypatch.setattr('sentinel.jobs.run_one_job',ready_queue('local'))
    monkeypatch.setattr('sentinel.intelligence.run_one_check',ready_queue('external'))
    worker_loop(app,Stop())
    assert calls==['local','external']*5
