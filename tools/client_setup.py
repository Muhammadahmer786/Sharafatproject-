"""Install and run the local Windows application; --plan makes no changes."""
import argparse
from contextlib import closing
import ctypes
import getpass
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import webbrowser

from tools.client_setup_support import (Commands, RestartRequired, SetupError, State,
    file_lock, fingerprint, prepare_env, require_free, validate_runtime)

ROOT = Path(__file__).resolve().parents[1]


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true', help='Show the sequence without reading private configuration or changing the PC')
    parser.add_argument('--runtime-directory', type=Path, help='Absolute local folder for new WSL, download cache and AI assets')
    parser.add_argument('--setup-only', action='store_true', help='Install/check everything without launching the web server')
    parser.add_argument('--no-browser', action='store_true', help='Start the site without opening a browser tab')
    parser.add_argument('--port', type=int, default=5050)
    parser.add_argument('--configure-api', action='store_true', help='Prompt to replace the existing VirusTotal key privately')
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error('--port must be between 1024 and 65535')
    return args


def require_original_secret(root, config):
    database = root / 'instance/sentinel.db'
    secret = root / 'instance/.secret'
    if database.exists() and database.stat().st_size and not config.get('SECRET_KEY'):
        if not secret.is_file() or not secret.read_text(encoding='ascii').strip():
            raise SetupError('Existing database has no original server secret. Restore it before setup; no replacement was generated.')


def has_admin(database):
    if not database.is_file():
        return False
    try:
        with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
            return db.execute("SELECT 1 FROM user WHERE role='admin' AND enabled=1 LIMIT 1").fetchone() is not None
    except sqlite3.DatabaseError as exc:
        raise SetupError('Cannot inspect administrator status. Resolve the database/migration error first.') from exc


def local_json(path, port=11434):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, new_url):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(f'http://127.0.0.1:{port}{path}', timeout=5) as response:
            if response.geturl() != f'http://127.0.0.1:{port}{path}':
                return {}
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                return {}
            result = json.loads(data)
            return result if isinstance(result, dict) else {}
    except (OSError, ValueError, urllib.error.URLError):
        return {}


def choose_runtime(config, explicit):
    if explicit:
        root = validate_runtime(explicit)
        return root, root / 'ai'
    configured = config.get('LOCAL_AI_RUNTIME_DIR', '').strip()
    if configured:
        ai = validate_runtime(Path(configured))
        if Path(ai.anchor).exists() and (ai.exists() or configured.replace('\\', '/').lower() != 'd:/sentinelruntime/ai'):
            return ai.parent, ai
        if configured.replace('\\', '/').lower() != 'd:/sentinelruntime/ai':
            raise SetupError('The configured AI drive is missing. Reconnect it or choose --runtime-directory explicitly.')
    # Prefer a non-system fixed disk with adequate room, otherwise the user's local data.
    system = os.environ.get('SystemDrive', 'C:').upper()
    for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
        drive = Path(letter + ':\\')
        if drive.drive.upper() != system and ctypes.windll.kernel32.GetDriveTypeW(str(drive)) == 3:
            if shutil.disk_usage(drive).free >= 40 * 1024**3:
                root = drive / 'SentinelRuntime'
                return root, root / 'ai'
    root = Path(os.environ['LOCALAPPDATA']) / 'SentinelLab/runtime'
    require_free(root, 40)
    return root, root / 'ai'


def ensure_python(root, state, command):
    python = root / '.venv/Scripts/python.exe'
    if not python.exists():
        marker = root / '.venv/.sentinel-setup'
        if (root / '.venv').exists() and not marker.is_file():
            raise SetupError('An incomplete .venv already exists. Preserve/inspect it before recreating the environment.')
        require_free(root, 2)
        marker.parent.mkdir(exist_ok=True)
        marker.touch(exist_ok=True)
        command.run([sys.executable, '-m', 'venv', root / '.venv'])
    version = command.run([python, '-c', 'import sys; assert sys.prefix != sys.base_prefix; print(sys.version_info[:2])'], capture=True, timeout=30)
    if version.stdout.strip() != '(3, 12)':
        raise SetupError('The existing .venv is not Python 3.12; it was not replaced.')
    if command.run([python, '-m', 'pip', '--version'], capture=True, check=False, timeout=30).returncode:
        command.run([python, '-m', 'ensurepip', '--upgrade'])
    def dependencies_ready():
        code = 'import sys; from tools.client_setup_support import locked_versions_match; sys.exit(0 if locked_versions_match(sys.argv[1]) else 1)'
        modules = command.run([python, '-c', code, root / 'requirements.lock.txt'], capture=True, check=False, timeout=30)
        return modules.returncode == 0 and command.run([python, '-m', 'pip', 'check'], capture=True, check=False, timeout=60).returncode == 0
    state.stage('Python packages', fingerprint([root / 'requirements.lock.txt']), dependencies_ready,
                lambda: command.run([python, '-m', 'pip', 'install', '-r', root / 'requirements.lock.txt']))
    return python


class Installer:
    def __init__(self, root, args, state, command):
        from dotenv import dotenv_values
        self.root, self.args, self.state, self.command = Path(root), args, state, command
        self.python = self.root / '.venv/Scripts/python.exe'
        self.config = dict(dotenv_values(self.root / '.env'))
        self.database = self.root / 'instance/sentinel.db'
        self.docker = None
        self.refresh_environment()

    def refresh_environment(self):
        # A stale parent shell must not silently override the preserved .env.
        names = set(self.config) | {'DATABASE_URL', 'SECRET_KEY', 'VIRUSTOTAL_API_KEY',
            'SENTINEL_WSL_DISTRO', 'PE_WORKER_MODE', 'ALLOW_REGISTRATION'}
        for name in names:
            self.command.environment.pop(name, None)
        self.command.environment.update({k: v for k, v in self.config.items() if v is not None})

    def set_config(self, key, value):
        from dotenv import set_key
        if self.config.get(key) != value:
            set_key(str(self.root / '.env'), key, value)
            self.config[key] = value
            self.refresh_environment()

    def tool(self, script, *args, **kwargs):
        return self.command.run([self.python, self.root / script, *args], **kwargs)

    def configure(self):
        require_original_secret(self.root, self.config)
        if self.config.get('DATABASE_URL'):
            raise SetupError('Automatic setup supports the documented default SQLite instance. Existing DATABASE_URL was preserved; use its operator runbook.')
        for key, required in {'PE_WORKER_MODE': 'docker', 'ALLOW_REGISTRATION': '0',
                              'LOCAL_AI_URL': 'http://127.0.0.1:11434', 'LOCAL_AI_MODEL': 'qwen3:4b',
                              'COOKIE_SECURE': '0'}.items():
            if self.config.get(key, required) != required:
                raise SetupError(f'Existing {key} is customized. Automatic setup requires the documented local default; configuration was preserved.')
        self.runtime, self.ai_directory = choose_runtime(self.config, self.args.runtime_directory)
        self.runtime = validate_runtime(self.runtime)
        self.runtime.mkdir(parents=True, exist_ok=True)
        self.set_config('LOCAL_AI_RUNTIME_DIR', self.ai_directory.as_posix())
        self.command.powershell('tools/secure-local-files.ps1')
        self.tool('run.py', 'migrate')
        print(f'Runtime storage: {self.runtime}', flush=True)

    def docker_ok(self, command):
        result = self.command.run([*command, 'info', '--format', '{{.OSType}}'], capture=True, check=False, timeout=60)
        return result.returncode == 0 and result.stdout.strip() == 'linux'

    def engine(self):
        distro = self.config.get('SENTINEL_WSL_DISTRO', '').strip()
        if distro and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', distro):
            raise SetupError('Invalid configured WSL distribution name; configuration was preserved.')
        direct = shutil.which('docker')
        desktop = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Docker/Docker/Docker Desktop.exe'
        if not distro and direct:
            if not self.docker_ok([direct]) and desktop.is_file():
                startup = subprocess.STARTUPINFO()
                startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startup.wShowWindow = 0
                subprocess.Popen([str(desktop)], startupinfo=startup, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for _ in range(30):
                    if self.docker_ok([direct]):
                        break
                    time.sleep(2)
            if not self.docker_ok([direct]):
                raise SetupError('Existing Docker is unavailable or uses Windows containers. Start its Linux engine, then rerun; another engine was not installed.')
            self.docker = [direct]
            return
        wsl = shutil.which('wsl.exe')
        probe = self.command.run([wsl, '--list', '--quiet'], capture=True, check=False, timeout=45, encoding='utf-16-le') if wsl else None
        if probe is None or probe.returncode:
            print('Windows may request administrator approval to enable WSL. No automatic reboot will occur.', flush=True)
            result = self.command.powershell('tools/enable-wsl.ps1', check=False)
            if result.returncode == 3010:
                raise RestartRequired('Restart Windows, then double-click Setup-and-Run.cmd again. Completed steps are retained.')
            if result.returncode:
                raise SetupError('Windows could not enable WSL (or approval was declined). Resolve the Windows message and rerun.')
            wsl = shutil.which('wsl.exe')
            if not wsl:
                raise RestartRequired('Restart Windows to finish WSL setup, then run this launcher again.')
            probe = self.command.run([wsl, '--list', '--quiet'], capture=True, timeout=60, encoding='utf-16-le')
        names = probe.stdout.lstrip('\ufeff').replace('\x00', '').splitlines()
        distro = distro or 'SentinelLab'
        self.docker = [wsl, '-d', distro, '-u', 'root', '--exec', 'docker']
        if distro in names:
            if not self.config.get('SENTINEL_WSL_DISTRO', '').strip():
                # A matching name alone does not establish ownership of a distro.
                import runpy
                installer = runpy.run_path(str(self.root / 'tools/install-wsl-runtime.py'))
                installer['validate_resume'](self.runtime / 'wsl', installer['registered_location'](distro))
            self.command.run([wsl, '-d', distro, '-u', 'root', '--exec', 'systemctl', 'start', 'docker'], check=False, timeout=90)
            if self.docker_ok(self.docker):
                self.set_config('SENTINEL_WSL_DISTRO', distro)
                return
            if distro != 'SentinelLab':
                raise SetupError('The configured WSL engine is unavailable. Its distribution was not modified.')
        self.tool('tools/install-wsl-runtime.py', '--directory', self.runtime, '--distro', distro,
                  '--allow-system-drive', '--preserve-wsl-config', '--resume')
        if not self.docker_ok(self.docker):
            raise SetupError('The dedicated Docker engine did not become ready.')
        self.set_config('SENTINEL_WSL_DISTRO', distro)

    def image_ids(self):
        result = self.command.run([*self.docker, 'image', 'inspect',
            'sentinel-pe-worker:local', 'sentinel-openbin-worker:local', '--format', '{{.Id}}'],
            capture=True, check=False, timeout=60)
        return result.stdout.strip() if result.returncode == 0 else ''

    def workers(self):
        inputs = [self.root / name for name in ('Dockerfile', 'ghidra.Dockerfile', 'requirements.lock.txt',
                  'tools/build_workers.py')]
        inputs += sorted((self.root / 'sentinel').glob('*.py'))
        self.state.stage('Docker workers', fingerprint(inputs), lambda: bool(self.image_ids()),
            lambda: self.tool('tools/build_workers.py', '--include-openbin', '--cache-directory', self.runtime / 'downloads'))
        self.state.stage('Worker acceptance', fingerprint([self.root / 'tools/check_workers.py']) + self.image_ids(),
            lambda: bool(self.image_ids()), lambda: self.tool('tools/check_workers.py', '--include-openbin'))

    def model_record(self):
        models = local_json('/api/tags').get('models', [])
        if not isinstance(models, list):
            return {}
        return next((item for item in models if isinstance(item, dict) and item.get('name') == 'qwen3:4b'
                     and isinstance(item.get('digest'), str) and item['digest']), {})

    def model(self):
        executable = self.ai_directory / 'ollama-0.40.13/ollama.exe'
        if not executable.is_file() or not (executable.parent / '.verified-source.json').is_file():
            self.tool('tools/install-local-ai.py', '--directory', self.ai_directory, '--allow-system-drive')
        self.command.powershell('tools/start-local-ai.ps1', '-RuntimeDirectory', self.ai_directory)
        if not self.model_record():
            self.command.powershell('tools/start-local-ai.ps1', '-RuntimeDirectory', self.ai_directory, '-PullModel')
        if not self.model_record():
            raise SetupError('The local qwen3:4b model is missing after download. Check the model server logs and rerun.')

    def acceptance(self):
        reports = self.root / 'instance/setup-checks'
        reports.mkdir(exist_ok=True)
        def verify():
            output = reports / (str(uuid.uuid4()) + '.json')
            self.tool('tools/check_local_ai.py', '--output', output)
            result = json.loads(output.read_text(encoding='utf-8'))
            if result.get('state') != 'complete' or not result.get('result', {}).get('ai_model_ran'):
                raise SetupError('The local AI fixture did not complete actual inference.')
        digest = fingerprint([self.root / 'tools/check_local_ai.py', self.root / 'sentinel/ai_jobs.py',
                              self.root / 'sentinel/local_ai.py']) + self.image_ids() + self.model_record().get('digest', '')
        self.state.stage('Local AI acceptance', digest, lambda: bool(self.model_record()) and bool(self.image_ids()), verify)

    def accounts(self):
        if not has_admin(self.database):
            print('Create the client administrator now. Credentials are entered privately; no default login is shipped.', flush=True)
            self.tool('run.py', 'create-admin')
            if not has_admin(self.database):
                raise SetupError('Administrator creation did not complete.')
        else:
            print('Existing administrator retained; no password or account key was changed.', flush=True)
        if not self.config.get('VIRUSTOTAL_API_KEY') or self.args.configure_api:
            print('VirusTotal is optional for local features. Enter the client key, or press Enter to skip external checks.', flush=True)
            key = getpass.getpass('VirusTotal API key (hidden): ').strip()
            if key:
                if len(key) > 512 or any(c.isspace() for c in key):
                    raise SetupError('Invalid API key format; it was not saved.')
                self.set_config('VIRUSTOTAL_API_KEY', key)
            else:
                print('External checks remain unavailable unless a valid key was already configured.', flush=True)
        self.command.powershell('tools/secure-local-files.ps1')

    def finish(self):
        self.tool('run.py', 'backup')
        result = self.tool('run.py', 'doctor', capture=True, check=False, timeout=120)
        try:
            report = json.loads(result.stdout)
        except ValueError as exc:
            raise SetupError('Readiness check did not return a valid report. Run run.py doctor to inspect the failure.') from exc
        failed = [item.get('name') for item in report.get('checks', []) if not item.get('ok')]
        if any(name != 'Administrator' for name in failed) or (result.returncode and not failed):
            raise SetupError('Readiness needs attention: ' + ', '.join(str(name) for name in failed))
        print('\nLocal components installed and fixture checks passed.', flush=True)
        if 'Administrator' in failed:
            print('Remaining personal step: sign in, open Workspace settings > Account security, and enroll your authenticator.', flush=True)
        print('Keep the original instance secret and database backups safe. The setup guide explains recovery.', flush=True)

    def install(self):
        steps = [('Configuration/database', self.configure), ('Docker engine', self.engine),
                 ('Document and OpenBin workers', self.workers), ('Ollama and model', self.model),
                 ('Local AI fixture verification', self.acceptance), ('Client accounts and API', self.accounts),
                 ('Backup/readiness', self.finish)]
        for number, (label, action) in enumerate(steps, 1):
            print(f'\n[{number}/{len(steps)}] {label}', flush=True)
            action()

    def serve(self):
        port = self.args.port
        with socket.socket() as probe:
            try:
                probe.bind(('127.0.0.1', port))
            except OSError as exc:
                raise SetupError(f'Port {port} is already in use. Stop the existing server or use --port with a free port.') from exc
        process = subprocess.Popen([str(self.python), str(self.root / 'run.py'), '--port', str(port)],
                                   cwd=self.root, env=self.command.environment)
        try:
            for _ in range(60):
                if process.poll() is not None:
                    raise SetupError('The website stopped during startup. Read the server error above.')
                if local_json('/health', port):
                    url = f'http://127.0.0.1:{port}'
                    print(f'\nOpen {url} — keep this window open. Ctrl+C stops the site.', flush=True)
                    if not self.args.no_browser:
                        webbrowser.open(url)
                    break
                time.sleep(1)
            else:
                raise SetupError('The website did not become healthy within 60 seconds.')
            return process.wait()
        except KeyboardInterrupt:
            print('\nStopping the local website...', flush=True)
            try:
                process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                process.terminate()
            return 0
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()


def main(argv=None, *, root=ROOT):
    args = arguments(argv)
    if args.plan:
        print('Python environment -> private configuration -> WSL/Docker -> document/OpenBin workers')
        print('-> Ollama/local model -> inert-fixture checks -> private account/API prompts -> local website')
        print('Existing accounts, original secrets and WSL configuration are preserved. Windows may request UAC/reboot.')
        return 0
    try:
        if os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64'):
            raise SetupError('This automatic installer supports Windows Intel/AMD x64 only.')
        if sys.version_info[:2] != (3, 12):
            raise SetupError('Run Setup-and-Run.cmd to install/use Python 3.12.')
        if sys.getwindowsversion().build < 22000:
            raise SetupError('This client installer targets Windows 11. Update Windows before a new installation.')
        memory_kib = ctypes.c_ulonglong()
        if ctypes.windll.kernel32.GetPhysicallyInstalledSystemMemory(ctypes.byref(memory_kib)):
            print(f'Installed RAM: {memory_kib.value / 1024**2:.1f} GiB. Recommended: 16 GiB or more for all local features.', flush=True)
            if memory_kib.value < 16 * 1024**2:
                print('This PC is below the documented RAM allowance; local AI may fail for lack of memory.', flush=True)
        root = Path(root).resolve()
        if not (root / 'run.py').is_file():
            raise SetupError('Extract or clone the complete project before running this script.')
        with file_lock(root / 'instance/.server.lock', existing_only=True):
            pass
        # Bootstrap is locked separately so the venv interpreter can continue safely.
        with file_lock(root / 'instance/.setup.lock'):
            prepare_env(root)
            state = State(root / 'instance/setup-state.json')
            command = Commands(root)
            command.environment.pop('PYTHONHOME', None)
            command.environment.pop('PYTHONPATH', None)
            command.environment['PYTHONNOUSERSITE'] = '1'
            python = ensure_python(root, state, command)
        if Path(sys.executable).resolve() != python.resolve():
            return command.run([python, root / 'setup_client.py', *(sys.argv[1:] if argv is None else argv)], check=False).returncode
        with file_lock(root / 'instance/.setup.lock'):
            setup = Installer(root, args, state, command)
            setup.install()
            if not args.setup_only:
                return setup.serve()
        return 0
    except RestartRequired as exc:
        print(f'\nRESTART REQUIRED: {exc}', flush=True)
        return 3010
    except (SetupError, OSError, ValueError) as exc:
        print(f'\nSETUP STOPPED: {exc}', flush=True)
        print('Completed stages are retained. Correct the issue, then run the same launcher again.', flush=True)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('\nSetup canceled. Run the same launcher to continue.', flush=True)
        return 130
