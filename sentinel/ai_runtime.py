"""Keep an installed local Ollama runtime alive for the local server.

No installation, model downloads, cloud calls or firewall changes happen here.
An existing runtime is reused; only processes started here are stopped here.
"""
import os
from pathlib import Path
import socket
import subprocess
import threading
import time


class LocalAIRuntime:
    def __init__(self, config, directory=None):
        self.directory = Path(directory or config.get('LOCAL_AI_RUNTIME_DIR', 'D:/SentinelRuntime/ai'))
        self.executable = self.directory / 'ollama-0.40.13' / 'ollama.exe'
        self.enabled = config.get('LOCAL_AI_URL', 'http://127.0.0.1:11434').rstrip('/') == 'http://127.0.0.1:11434'
        self.process = None
        self.logs = []
        self.retry_at = 0
        self.stopping = threading.Event()
        self.thread = None
        self.lock = threading.RLock()

    def environment(self):
        permitted = {'SYSTEMROOT', 'WINDIR', 'PATH', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'COMSPEC'}
        environment = {key: value for key, value in os.environ.items() if key.upper() in permitted}
        environment.update(OLLAMA_HOST='127.0.0.1:11434', OLLAMA_NO_CLOUD='1',
            OLLAMA_MODELS=str(self.directory / 'models'), OLLAMA_TMPDIR=str(self.directory / 'tmp'),
            TEMP=str(self.directory / 'tmp'), TMP=str(self.directory / 'tmp'),
            OLLAMA_NUM_PARALLEL='1', OLLAMA_MAX_LOADED_MODELS='1', OLLAMA_MAX_QUEUE='3',
            OLLAMA_KEEP_ALIVE='0', OLLAMA_CONTEXT_LENGTH='8192', CUDA_VISIBLE_DEVICES='-1')
        return environment

    def _healthy(self):
        # Only check port occupancy here, with a bounded connect to a literal IP.
        # The application's model_status validates the actual service and model.
        # Do not consume an HTTP body that could extend the shutdown deadline.
        try:
            with socket.create_connection(('127.0.0.1', 11434), timeout=2):
                return True
        except OSError:
            return False

    def _close_logs(self):
        for handle in self.logs:
            handle.close()
        self.logs.clear()

    def _launch(self):
        for name in ('models', 'tmp', 'logs'):
            (self.directory / name).mkdir(parents=True, exist_ok=True)
        self._close_logs()
        try:
            for name in ('managed-out.log', 'managed-error.log'):
                path = self.directory / 'logs' / name
                if path.exists() and path.stat().st_size > 5 * 1024 * 1024:
                    path.replace(path.with_suffix('.previous.log'))
                self.logs.append(path.open('ab', buffering=0))
            self.process = subprocess.Popen([str(self.executable), 'serve'], env=self.environment(),
                stdin=subprocess.DEVNULL, stdout=self.logs[0], stderr=self.logs[1],
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except OSError:
            self._close_logs()
            raise

    def tick(self):
        if self.stopping.is_set() or not self.enabled or not self.executable.is_file():
            return
        with self.lock:
            if self.process is not None:
                if self.process.poll() is None:
                    return
                self.process = None; self._close_logs()
        if self._healthy() or time.monotonic() < self.retry_at:
            return
        with self.lock:
            # Shutdown can begin during the probe. Transfer process ownership
            # under the same lock used by stop, and never launch after shutdown.
            if self.stopping.is_set() or self.process is not None or time.monotonic() < self.retry_at:
                return
            self.retry_at = time.monotonic() + 60
            try:
                self._launch()
            except OSError:
                # Availability is reported by /ai and doctor; retries remain bounded.
                pass

    def start(self):
        self.tick()
        def monitor():
            while not self.stopping.wait(5):
                self.tick()
        self.thread = threading.Thread(target=monitor, name='sentinel-local-model', daemon=True)
        self.thread.start()

    def stop(self):
        self.stopping.set()
        if self.thread:
            self.thread.join(timeout=5)
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill(); self.process.wait(timeout=5)
            self._close_logs()
