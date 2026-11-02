"""Database-backed, restart-safe hash lookups. No sample bytes enter the queue."""
import threading
import time
import uuid
from datetime import timedelta
from sqlalchemy.exc import IntegrityError
from .models import db, Scan, ReputationJob, ProviderQuota, utcnow
from . import reputation


def enqueue_lookup(scan):
    job = db.session.get(ReputationJob, scan.id)
    if job and job.status in ('queued', 'running'):
        return
    if job:
        job.status = 'queued'; job.attempts = 0; job.available_at = utcnow()
        job.lease_token = None; job.lease_until = None
    else:
        db.session.add(ReputationJob(scan_id=scan.id))
    scan.reputation = {'status': 'pending', 'queried_at': utcnow().isoformat()}
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()


def run_one_job(app):
    from .routes import reserve_lookup
    with app.app_context():
        now = utcnow()
        eligible = db.or_(
            db.and_(ReputationJob.status == 'queued', ReputationJob.available_at <= now),
            db.and_(ReputationJob.status == 'running', ReputationJob.lease_until <= now))
        job = db.session.execute(db.select(ReputationJob).where(eligible).order_by(
            ReputationJob.created_at).limit(1)).scalar_one_or_none()
        if not job:
            return False
        scan_id, token = job.scan_id, str(uuid.uuid4())
        claimed = db.session.execute(db.update(ReputationJob).where(
            ReputationJob.scan_id == scan_id, eligible).values(
                status='running', lease_token=token, lease_until=now+timedelta(seconds=90)))
        db.session.commit()
        if claimed.rowcount != 1:
            return False
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return False
        if not scan.hash_consent or not app.config['VIRUSTOTAL_API_KEY']:
            result = {'status': 'not_configured' if scan.hash_consent else 'not_requested'}
        elif job.attempts>=3:
            result = {'status':'unavailable'}
        else:
            if not reserve_lookup():
                quota = db.session.get(ProviderQuota, 'virustotal')
                delay = 60 if quota.count < 500 else 3600
                db.session.execute(db.update(ReputationJob).where(
                    ReputationJob.scan_id==scan_id, ReputationJob.lease_token==token
                ).values(status='queued', available_at=utcnow()+timedelta(seconds=delay), lease_token=None, lease_until=None))
                db.session.commit()
                return True
            sha256 = scan.sha256
            changed=db.session.execute(db.update(ReputationJob).where(
                ReputationJob.scan_id==scan_id,ReputationJob.lease_token==token
            ).values(attempts=ReputationJob.attempts+1))
            db.session.commit()
            if not changed.rowcount: return True
            db.session.remove()
            result = reputation.lookup_hash_bounded(sha256, app.config['VIRUSTOTAL_API_KEY'])
        job = db.session.get(ReputationJob, scan_id)
        scan = db.session.get(Scan, scan_id)
        if not job or not scan or job.lease_token != token:
            return True
        attempts = job.attempts
        retry = result.get('status') in ('unavailable', 'rate_limited') and attempts < 3
        changed = db.session.execute(db.update(ReputationJob).where(
            ReputationJob.scan_id==scan_id, ReputationJob.lease_token==token).values(
                status='queued' if retry else 'done', attempts=attempts,
                available_at=utcnow()+timedelta(seconds=60*attempts), lease_until=None, lease_token=None))
        if changed.rowcount == 1:
            db.session.execute(db.update(Scan).where(Scan.id==scan_id).values(reputation=(
                {'status':'pending','queried_at':utcnow().isoformat(),'attempts':attempts} if retry else result)))
        db.session.commit()
        return True


def quota_reservations(app):
    with app.app_context():
        quota=db.session.get(ProviderQuota,'virustotal')
        return (quota.day,quota.count,quota.next_at) if quota else None


def worker_loop(app,stop):
    next_backup=0
    external_first=False
    while not stop.is_set():
        if time.monotonic()>=next_backup:
            try:
                from .operations import backup_if_due
                backup_if_due(app)
                next_backup=time.monotonic()+3600
            except Exception:
                next_backup=time.monotonic()+300
                app.logger.error('Scheduled backup failed; retrying in five minutes.')
        from .intelligence import run_one_check
        work=(run_one_check,run_one_job) if external_first else (run_one_job,run_one_check)
        for operation in work:
            before=None
            try:
                before=quota_reservations(app)
                operation(app)
            except Exception:
                app.logger.error('Provider worker failed; expired leases will be retried.')
            finally:
                try:
                    if before is not None and quota_reservations(app)!=before:
                        # Rotate on a reservation, not on idle two-second ticks.
                        external_first=operation is run_one_job
                except Exception:
                    app.logger.error('Provider quota state unavailable; retrying next cycle.')
        stop.wait(2)


def start_worker(app):
    stop = threading.Event()
    worker = threading.Thread(target=worker_loop,args=(app,stop),name='durable-reputation-worker', daemon=True)
    worker.start()
    return stop, worker
