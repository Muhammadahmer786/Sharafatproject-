"""Single-consumer local AI queue; uploaded bytes never enter persistent storage."""
from collections import OrderedDict
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import threading
import time
import uuid
from .models import AIAnalysis, User, audit, db, utcnow

ACTIVE = ('queued', 'running')
MAX_FILE = 10 * 1024 * 1024
CONFIG_KEYS = ('PE_WORKER_MODE', 'PE_WORKER_IMAGE', 'OPENBIN_WORKER_IMAGE',
               'LOCAL_AI_URL', 'LOCAL_AI_MODEL', 'LOCAL_AI_TIMEOUT')


def interrupt_pending():
    db.session.execute(db.update(AIAnalysis).where(AIAnalysis.state.in_(ACTIVE)).values(
        state='interrupted', stage='interrupted', updated_at=utcnow(),
        error='The server restarted before completion. Uploaded bytes were not saved; resubmit the file.'))
    db.session.commit()


def _child(connection, data, filename, config, identity):
    parent = multiprocessing.parent_process()
    finished = threading.Event()
    if parent is not None:
        threading.Thread(target=_watch_parent, args=(parent, identity, finished), daemon=True).start()
    def progress(stage, percent):
        connection.send_bytes(json.dumps({'type': 'progress', 'stage': stage, 'progress': percent}).encode())
    try:
        from .analysis import inspect_pe
        from .openbin_local import decompile_local
        from .local_ai import analyze_decompilation
        progress('inspecting', 10)
        inspected = inspect_pe(data, filename, mode=config['PE_WORKER_MODE'],
                               image=config['PE_WORKER_IMAGE'], job_id=identity)
        progress('decompiling', 30)
        code = decompile_local(data, filename, config['OPENBIN_WORKER_IMAGE'], job_id=identity)
        result = analyze_decompilation(code, inspected['sha256'], config, on_progress=progress)
        result['static'] = inspected
        connection.send_bytes(json.dumps({'type': 'result', 'result': result}).encode())
    except ValueError as exc:
        connection.send_bytes(json.dumps({'type': 'error', 'error': str(exc)[:500]}).encode())
    except Exception:
        connection.send_bytes(b'{"type":"error","error":"The local analysis worker stopped unexpectedly. Resubmit after checking the runtime."}')
    finally:
        finished.set()
        connection.close()


def _cleanup_job(identity):
    from .container_runtime import docker_command
    try:
        suffix = uuid.UUID(identity).hex
        subprocess.run([*docker_command(), 'rm', '-f', 'sentinel-pe-' + suffix,
                        'sentinel-openbin-' + suffix], capture_output=True, timeout=8,
                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (ValueError, OSError, subprocess.TimeoutExpired):
        pass


def _watch_parent(parent, identity, finished):
    # Windows does not kill spawned children when its server PID is force-stopped.
    while not finished.wait(1):
        if not parent.is_alive():
            _cleanup_job(identity)
            os._exit(1)


def run_pipeline(data, filename, config, cancel, progress, identity):
    """A disposable process gives requests/Ghidra a hard overall deadline."""
    context = multiprocessing.get_context('spawn')
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_child, args=(sender, data, filename, config, identity), daemon=True)
    deadline = time.monotonic() + min(1200, max(60, int(config['LOCAL_AI_TIMEOUT']))) + 420
    started = False
    try:
        process.start(); started = True; sender.close()
        while True:
            if cancel.is_set():
                raise ValueError('Analysis cancelled; no verdict was recorded.')
            if time.monotonic() >= deadline:
                raise ValueError('Local analysis exceeded its deadline. No verdict was recorded.')
            if receiver.poll(0.2):
                try:
                    message = json.loads(receiver.recv_bytes(2 * 1024 * 1024))
                except (EOFError, OSError, ValueError):
                    raise ValueError('The local analysis worker returned no usable result.') from None
                if message.get('type') == 'progress':
                    progress(message['stage'], message['progress'])
                elif message.get('type') == 'result':
                    return message['result']
                elif message.get('type') == 'error':
                    raise ValueError(message['error'])
            elif not process.is_alive():
                raise ValueError('The local analysis worker stopped before returning a result.')
    finally:
        receiver.close(); sender.close()
        if started:
            process.join(timeout=1)
            if process.is_alive():
                process.terminate(); process.join(timeout=5)
            process.close()
        # A terminated Windows parent can leave its WSL docker client behind.
        # Only containers named for this random job ID are eligible for cleanup.
        _cleanup_job(identity)


class AIJobManager:
    def __init__(self, app, pipeline=run_pipeline):
        self.app, self.pipeline = app, pipeline
        self.pending = OrderedDict()
        self.lock = threading.RLock()
        self.wake, self.stopping = threading.Event(), threading.Event()
        self.thread = None

    def submit(self, owner, data, filename):
        if not 256 <= len(data) <= MAX_FILE or not data.startswith(b'MZ') or Path(filename).suffix.lower() not in ('.exe', '.dll'):
            raise ValueError('Choose a native Windows EXE or DLL between 256 bytes and 10 MiB.')
        with self.lock:
            if self.stopping.is_set() or len(self.pending) >= 3:
                raise ValueError('The local AI queue is busy. Wait for a current analysis to finish.')
            with self.app.app_context():
                row = AIAnalysis(user_id=owner, filename=filename, sha256=hashlib.sha256(data).hexdigest(),
                                 size=len(data), model=self.app.config.get('LOCAL_AI_MODEL', 'qwen3:4b'))
                db.session.add(row); audit(owner, 'Local AI static analysis requested')
                db.session.commit(); identity = row.id
            self.pending[identity] = {'data': data, 'filename': filename, 'cancel': threading.Event(), 'running': False}
            self.wake.set()
            return identity

    def cancel(self, identity, owner):
        with self.lock, self.app.app_context():
            changed = db.session.execute(db.update(AIAnalysis).where(AIAnalysis.id == identity,
                AIAnalysis.user_id == owner, AIAnalysis.state.in_(ACTIVE)).values(
                    state='cancelled', stage='cancelled', updated_at=utcnow(),
                    error='Cancelled by the owner. No completed result is available.'))
            if changed.rowcount:
                audit(owner, 'Local AI analysis cancelled')
            db.session.commit()
            if changed.rowcount and identity in self.pending:
                item = self.pending[identity]
                item['cancel'].set()
                if not item['running']:
                    del self.pending[identity]
            return bool(changed.rowcount)

    def _progress(self, identity, stage, percent):
        if stage not in ('inspecting', 'decompiling', 'analysing', 'validating'):
            return
        with self.app.app_context():
            db.session.execute(db.update(AIAnalysis).where(AIAnalysis.id == identity,
                AIAnalysis.state == 'running').values(stage=stage, progress=max(0, min(95, int(percent))), updated_at=utcnow()))
            db.session.commit()

    def run_one(self):
        with self.lock:
            found = next(((key, value) for key, value in self.pending.items() if not value['running']), None)
            if not found:
                return False
            identity, item = found
            item['running'] = True
        try:
            with self.app.app_context():
                row = db.session.get(AIAnalysis, identity)
                account = db.session.get(User, row.user_id) if row else None
                if not row or row.state != 'queued':
                    return True
                if not account or not account.enabled:
                    row.state = 'interrupted'; row.stage = 'interrupted'
                    row.error = 'Account unavailable before processing; no analysis ran.'
                    row.updated_at = utcnow(); db.session.commit()
                    return True
                claimed = db.session.execute(db.update(AIAnalysis).where(AIAnalysis.id == identity,
                    AIAnalysis.state == 'queued').values(state='running', stage='inspecting',
                        progress=10, updated_at=utcnow()))
                db.session.commit()
                if not claimed.rowcount:
                    return True
            config = {key: self.app.config.get(key) for key in CONFIG_KEYS}
            result = self.pipeline(item['data'], item['filename'], config, item['cancel'],
                                   lambda stage, percent: self._progress(identity, stage, percent), identity)
            values = dict(state='complete', stage='complete', progress=100, result=result, error=None)
        except ValueError as exc:
            values = dict(state='failed', stage='failed', error=str(exc)[:500])
        except Exception:
            self.app.logger.exception('Local AI job failed: %s', identity)
            values = dict(state='failed', stage='failed', error='Local analysis could not complete. Check the local runtime and resubmit.')
        finally:
            with self.lock:
                self.pending.pop(identity, None)
        with self.app.app_context():
            db.session.execute(db.update(AIAnalysis).where(AIAnalysis.id == identity,
                AIAnalysis.state == 'running').values(**values, updated_at=utcnow()))
            db.session.commit()
        return True

    def start(self):
        with self.app.app_context():
            interrupted = db.session.execute(db.select(AIAnalysis.id).where(AIAnalysis.state.in_(ACTIVE))).scalars().all()
            interrupt_pending()
        for identity in interrupted:
            _cleanup_job(identity)
        def loop():
            while not self.stopping.is_set():
                try:
                    if self.run_one():
                        continue
                except Exception:
                    self.app.logger.exception('Local AI queue iteration failed')
                self.wake.wait(1); self.wake.clear()
        self.thread = threading.Thread(target=loop, name='sentinel-local-ai', daemon=True)
        self.thread.start()

    def stop(self):
        with self.lock:
            self.stopping.set(); self.wake.set()
            with self.app.app_context():
                interrupt_pending()
            for item in self.pending.values():
                item['cancel'].set()
        if self.thread:
            self.thread.join(timeout=20)
        with self.lock:
            self.pending.clear()


def get_manager(app):
    return app.extensions['local_ai_jobs']
