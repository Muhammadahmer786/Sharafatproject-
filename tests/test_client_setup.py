import importlib.util
import json
from pathlib import Path

import pytest

from tools.client_setup_support import SetupError, State, fingerprint, prepare_env, validate_runtime


def test_existing_environment_and_secret_are_never_replaced(tmp_path):
    (tmp_path / '.env.example').write_text('SECRET_KEY=\n')
    (tmp_path / '.env').write_text('SECRET_KEY=original\nCUSTOM=keep\n')
    instance = tmp_path / 'instance'
    instance.mkdir()
    (instance / '.secret').write_text('original-secret')
    assert prepare_env(tmp_path) is False
    assert (tmp_path / '.env').read_text() == 'SECRET_KEY=original\nCUSTOM=keep\n'
    assert (instance / '.secret').read_text() == 'original-secret'


def test_new_environment_copies_example_once(tmp_path):
    (tmp_path / '.env.example').write_text('SECRET_KEY=\n')
    assert prepare_env(tmp_path) is True
    assert prepare_env(tmp_path) is False
    assert (tmp_path / '.env').read_text() == 'SECRET_KEY=\n'


def test_existing_database_without_original_configuration_is_not_bootstrapped(tmp_path):
    (tmp_path / '.env.example').write_text('SECRET_KEY=\n')
    (tmp_path / 'instance').mkdir()
    (tmp_path / 'instance/sentinel.db').write_bytes(b'existing')
    with pytest.raises(SetupError, match='original'):
        prepare_env(tmp_path)
    assert not (tmp_path / '.env').exists()


def test_failed_stage_is_not_marked_complete_and_restarts(tmp_path):
    state = State(tmp_path / 'state.json')
    def broken():
        raise SetupError('stopped')
    with pytest.raises(SetupError):
        state.stage('workers', 'v1', lambda: False, broken)
    assert not state.completed('workers', 'v1')
    artifact = tmp_path / 'installed'
    state.stage('workers', 'v1', artifact.exists, lambda: artifact.write_text('done'))
    assert State(state.path).completed('workers', 'v1')
    assert artifact.read_text() == 'done'


def test_completed_stage_rechecks_actual_artifact_and_changed_version(tmp_path):
    state = State(tmp_path / 'state.json')
    artifact = tmp_path / 'installed'
    state.stage('worker', 'v1', artifact.exists, lambda: artifact.write_text('one'))
    state.stage('worker', 'v1', artifact.exists, lambda: pytest.fail('unnecessary reinstall'))
    artifact.unlink()
    state.stage('worker', 'v1', artifact.exists, lambda: artifact.write_text('repaired'))
    assert artifact.read_text() == 'repaired'
    state.stage('worker', 'v2', artifact.exists, lambda: artifact.write_text('updated'))
    assert artifact.read_text() == 'updated'


def test_stage_must_pass_probe_before_recording_success(tmp_path):
    state = State(tmp_path / 'state.json')
    with pytest.raises(SetupError, match='verification'):
        state.stage('bad', 'v1', lambda: False, lambda: None)
    assert not state.completed('bad', 'v1')


def test_corrupt_checkpoint_is_not_silently_discarded(tmp_path):
    path = tmp_path / 'state.json'
    path.write_text('{not json')
    with pytest.raises(SetupError, match='checkpoint'):
        State(path)
    assert path.read_text() == '{not json'


def test_fingerprint_changes_with_contents_not_mtime(tmp_path):
    item = tmp_path / 'requirements'
    item.write_text('v1')
    first = fingerprint([item])
    item.touch()
    assert fingerprint([item]) == first
    item.write_text('v2')
    assert fingerprint([item]) != first


def test_runtime_must_be_specific_absolute_directory(tmp_path):
    assert validate_runtime(tmp_path / 'runtime') == (tmp_path / 'runtime').resolve()
    with pytest.raises(SetupError):
        validate_runtime(Path(tmp_path.anchor))
    with pytest.raises(SetupError):
        validate_runtime(Path('relative'))


def test_plan_does_not_install_or_create_state(tmp_path, monkeypatch, capsys):
    from tools.client_setup import main
    monkeypatch.setattr('subprocess.run', lambda *a, **k: pytest.fail('plan ran subprocess'))
    assert main(['--plan'], root=tmp_path) == 0
    assert list(tmp_path.iterdir()) == []
    assert 'WSL' in capsys.readouterr().out


def test_existing_database_without_secret_stops_before_migration(tmp_path):
    from tools.client_setup import require_original_secret
    (tmp_path / 'instance').mkdir()
    (tmp_path / 'instance/sentinel.db').write_bytes(b'existing')
    with pytest.raises(SetupError, match='original'):
        require_original_secret(tmp_path, {'SECRET_KEY': ''})
    (tmp_path / 'instance/.secret').write_text('saved-original-secret')
    require_original_secret(tmp_path, {'SECRET_KEY': ''})


def test_administrator_probe_uses_readonly_database_and_enabled_role(tmp_path):
    import sqlite3
    from tools.client_setup import has_admin
    database = tmp_path / 'sentinel.db'
    assert has_admin(database) is False
    assert not database.exists()
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE user (role TEXT, enabled BOOLEAN)')
        db.execute("INSERT INTO user VALUES ('admin',0),('user',1)")
    assert has_admin(database) is False
    with sqlite3.connect(database) as db:
        db.execute("INSERT INTO user VALUES ('admin',1)")
    assert has_admin(database) is True


def test_configuration_updates_keep_private_values_and_unrelated_settings(tmp_path):
    from tools.client_setup import Installer, arguments
    from tools.client_setup_support import Commands
    (tmp_path / '.env').write_text('SECRET_KEY=private-value\nVIRUSTOTAL_API_KEY=client-key\nCUSTOM=keep\n')
    runner = Commands(tmp_path, {'SECRET_KEY': 'stale-inherited-key', 'PATH': 'keep'})
    setup = Installer(tmp_path, arguments([]), State(tmp_path / 'state.json'), runner)
    setup.set_config('LOCAL_AI_RUNTIME_DIR', str(tmp_path / 'models'))
    from dotenv import dotenv_values
    config = dotenv_values(tmp_path / '.env')
    assert config['SECRET_KEY'] == 'private-value'
    assert config['VIRUSTOTAL_API_KEY'] == 'client-key'
    assert config['CUSTOM'] == 'keep'
    assert runner.environment['SECRET_KEY'] == 'private-value'


def test_pipeline_stops_at_failed_worker_and_never_creates_account(tmp_path, monkeypatch):
    from tools.client_setup import Installer, arguments
    from tools.client_setup_support import Commands
    (tmp_path / '.env').write_text('')
    setup = Installer(tmp_path, arguments(['--setup-only']), State(tmp_path / 'state.json'), Commands(tmp_path))
    events = []
    for name in ('configure', 'engine', 'model', 'accounts', 'acceptance', 'finish'):
        monkeypatch.setattr(setup, name, lambda n=name: events.append(n))
    def fail_workers():
        events.append('workers')
        raise SetupError('worker failed')
    monkeypatch.setattr(setup, 'workers', fail_workers)
    with pytest.raises(SetupError, match='worker failed'):
        setup.install()
    assert events == ['configure', 'engine', 'workers']


def load_installer(name):
    path = Path(__file__).resolve().parents[1] / 'tools' / name
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ai_installer_explicitly_allows_system_drive_but_still_rejects_root():
    module = load_installer('install-local-ai.py')
    assert module.validate_destination(Path('C:/SentinelRuntime/ai'), True)
    with pytest.raises(ValueError):
        module.validate_destination(Path('C:/SentinelRuntime/ai'), False)
    with pytest.raises(ValueError):
        module.validate_destination(Path('C:/'), True)


def test_wsl_resume_requires_matching_registered_disk_location(tmp_path):
    module = load_installer('install-wsl-runtime.py')
    wanted = tmp_path / 'wsl'
    module.validate_resume(wanted, wanted)
    with pytest.raises(ValueError, match='different'):
        module.validate_resume(wanted, tmp_path / 'unrelated')
    with pytest.raises(ValueError):
        module.validate_resume(wanted, None)


def test_interrupted_owned_venv_is_completed_without_deleting_files(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from tools.client_setup import ensure_python
    monkeypatch.setattr('tools.client_setup.require_free', lambda *args: None)
    venv = tmp_path / '.venv'
    venv.mkdir()
    (venv / '.sentinel-setup').touch()
    (venv / 'keep.txt').write_text('preserve')
    (tmp_path / 'requirements.lock.txt').write_text('')
    class Runner:
        def run(self, args, **kwargs):
            if '-m' in args and 'venv' in args:
                (venv / 'Scripts').mkdir(exist_ok=True)
                (venv / 'Scripts/python.exe').touch()
            return SimpleNamespace(returncode=0, stdout='(3, 12)\n')
    python = ensure_python(tmp_path, State(tmp_path / 'state.json'), Runner())
    assert python.is_file()
    assert (venv / 'keep.txt').read_text() == 'preserve'


def test_wsl_registry_extended_path_prefix_is_normalized(tmp_path, monkeypatch):
    module = load_installer('install-wsl-runtime.py')
    import sys
    from types import SimpleNamespace
    class Key:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    fake_registry = SimpleNamespace(HKEY_CURRENT_USER=1, OpenKey=lambda *args: Key(),
        QueryInfoKey=lambda key: (1,), EnumKey=lambda key, index: 'id',
        QueryValueEx=lambda key, name: ('SentinelLab' if name == 'DistributionName' else '\\\\?\\' + str(tmp_path), 1))
    monkeypatch.setitem(sys.modules, 'winreg', fake_registry)
    assert module.registered_location('SentinelLab') == tmp_path


def test_account_rerun_keeps_existing_admin_and_api_key(tmp_path, monkeypatch, capsys):
    import sqlite3
    from types import SimpleNamespace
    from tools.client_setup import Installer, arguments
    from tools.client_setup_support import Commands
    private = 'PRIVATE_DO_NOT_PRINT_THIS_KEY'
    (tmp_path / '.env').write_text('VIRUSTOTAL_API_KEY=' + private + '\n')
    (tmp_path / 'instance').mkdir()
    with sqlite3.connect(tmp_path / 'instance/sentinel.db') as db:
        db.execute('CREATE TABLE user (role TEXT, enabled BOOLEAN)')
        db.execute("INSERT INTO user VALUES ('admin',1)")
    runner = Commands(tmp_path)
    monkeypatch.setattr(runner, 'powershell', lambda *a, **k: SimpleNamespace(returncode=0))
    setup = Installer(tmp_path, arguments([]), State(tmp_path / 'state.json'), runner)
    monkeypatch.setattr(setup, 'tool', lambda *a, **k: pytest.fail('created another administrator'))
    monkeypatch.setattr('getpass.getpass', lambda *a: pytest.fail('asked for existing key again'))
    setup.accounts()
    assert (tmp_path / '.env').read_text() == 'VIRUSTOTAL_API_KEY=' + private + '\n'
    assert private not in capsys.readouterr().out


def test_model_probe_does_not_follow_redirects():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from tools.client_setup import local_json
    visits = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            visits.append(self.path)
            if self.path == '/source':
                self.send_response(302)
                self.send_header('Location', '/unexpected')
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{}')
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert local_json('/source', server.server_port) == {}
        assert visits == ['/source']
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_bad_runtime_checksum_never_extracts_or_creates_executable(tmp_path, monkeypatch):
    import sys
    import io
    from types import SimpleNamespace
    module = load_installer('install-local-ai.py')
    archive = tmp_path / 'ollama-0.40.13.zip'
    archive.write_bytes(b'bad download')
    monkeypatch.setattr(module, 'SIZE', len(b'bad download'))
    monkeypatch.setattr(module.urllib.request, 'urlopen', lambda *a, **k: io.BytesIO(b'bad download'))
    monkeypatch.setattr('tools.setup_downloads.shutil.disk_usage', lambda path: SimpleNamespace(free=40*1024**3))
    monkeypatch.setattr(sys, 'argv', ['installer', '--directory', str(tmp_path), '--allow-system-drive'])
    with pytest.raises(RuntimeError, match='checksum'):
        module.main()
    assert not (tmp_path / 'ollama-0.40.13').exists()
    assert not archive.exists()
    assert all(p.read_bytes() == b'bad download' for p in tmp_path.glob('*.rejected-*'))


def test_automatic_wsl_install_preserves_existing_global_configuration(tmp_path, monkeypatch):
    import hashlib
    import sys
    from types import SimpleNamespace
    module = load_installer('install-wsl-runtime.py')
    profile = tmp_path / 'profile'
    profile.mkdir()
    config = profile / '.wslconfig'
    original = b'[wsl2]\nmemory=10GB\nswap=4GB\n'
    config.write_bytes(original)
    runtime = tmp_path / 'runtime'
    cache = runtime / 'downloads'
    cache.mkdir(parents=True)
    archive = cache / 'ubuntu-24.04-amd64.wsl'
    archive.write_bytes(b'verified test archive')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    monkeypatch.setattr(module.Path, 'home', lambda: profile)
    monkeypatch.setattr(module.shutil, 'disk_usage', lambda path: SimpleNamespace(free=40*1024**3))
    monkeypatch.setattr(module.shutil, 'which', lambda name: 'wsl.exe')
    monkeypatch.setattr(module, 'fetch_json', lambda url: {'ModernDistributions': {'Ubuntu': [
        {'Name': 'Ubuntu-24.04', 'Amd64Url': {'Url': 'https://releases.ubuntu.com/fixture', 'Sha256': digest}}]}})
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: SimpleNamespace(stdout=b'', returncode=0))
    monkeypatch.setattr(sys, 'argv', ['installer', '--directory', str(runtime), '--allow-system-drive', '--preserve-wsl-config'])
    module.main()
    assert config.read_bytes() == original
    assert json.loads((cache / 'ubuntu-source.json').read_text())['Sha256'] == digest


def test_every_locked_distribution_and_exact_version_are_required(tmp_path):
    from importlib.metadata import PackageNotFoundError
    from tools.client_setup_support import locked_versions_match
    lock = tmp_path / 'requirements.lock.txt'
    lock.write_text('Flask==1.0\npyotp==2.0\nreportlab==3.0\n')
    installed = {'Flask': '1.0', 'pyotp': '2.0', 'reportlab': '3.0'}
    def version(name):
        if name not in installed:
            raise PackageNotFoundError(name)
        return installed[name]
    assert locked_versions_match(lock, version)
    installed.pop('pyotp')
    assert not locked_versions_match(lock, version)
    installed['pyotp'] = 'different'
    assert not locked_versions_match(lock, version)


def test_interrupted_venv_with_python_but_without_pip_is_repaired(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from tools.client_setup import ensure_python
    monkeypatch.setattr('tools.client_setup.require_free', lambda *args: None)
    venv = tmp_path / '.venv'
    (venv / 'Scripts').mkdir(parents=True)
    (venv / 'Scripts/python.exe').touch()
    (venv / '.sentinel-setup').touch()
    (tmp_path / 'requirements.lock.txt').write_text('')
    pip_ready = False
    class Runner:
        def run(self, args, **kwargs):
            nonlocal pip_ready
            if 'ensurepip' in args:
                pip_ready = True
            if 'pip' in args and not pip_ready:
                if kwargs.get('check', True):
                    raise SetupError('No module named pip')
                return SimpleNamespace(returncode=1, stdout='')
            return SimpleNamespace(returncode=0, stdout='(3, 12)\n')
    python = ensure_python(tmp_path, State(tmp_path / 'state.json'), Runner())
    assert python.is_file() and pip_ready


def test_systemd_update_keeps_other_distro_settings():
    module = load_installer('install-wsl-runtime.py')
    original = '[automount]\noptions=metadata\n[boot]\ncommand=echo keep\nsystemd=false\n[user]\ndefault=owner\n'
    updated = module.systemd_config(original)
    assert updated == original.replace('systemd=false', 'systemd=true')
    assert module.systemd_config(updated) == updated
    assert module.systemd_config('[boot]\ncommand=keep\n') == '[boot]\nsystemd=true\ncommand=keep\n'


def test_corrupt_cached_download_is_quarantined_and_replaced_only_after_verification(tmp_path, monkeypatch):
    import hashlib
    import io
    from tools.setup_downloads import verified_download
    destination = tmp_path / 'runtime.zip'
    destination.write_bytes(b'broken-cache')
    expected = b'verified-download'
    monkeypatch.setattr('urllib.request.urlopen', lambda *a, **k: io.BytesIO(expected))
    verified_download('https://example.invalid/runtime', destination, hashlib.sha256(expected).hexdigest(), size=len(expected))
    assert destination.read_bytes() == expected
    assert [p.read_bytes() for p in tmp_path.glob('*.rejected-*')] == [b'broken-cache']


def test_interrupted_download_is_never_published_and_next_run_recovers(tmp_path, monkeypatch):
    import hashlib
    import io
    from tools.setup_downloads import verified_download
    destination = tmp_path / 'runtime.zip'
    expected = b'whole-verified-download'
    monkeypatch.setattr('urllib.request.urlopen', lambda *a, **k: io.BytesIO(expected[:4]))
    with pytest.raises(RuntimeError, match='Incomplete'):
        verified_download('https://example.invalid/runtime', destination, hashlib.sha256(expected).hexdigest(), size=len(expected))
    assert not destination.exists()
    monkeypatch.setattr('urllib.request.urlopen', lambda *a, **k: io.BytesIO(expected))
    verified_download('https://example.invalid/runtime', destination, hashlib.sha256(expected).hexdigest(), size=len(expected))
    assert destination.read_bytes() == expected
