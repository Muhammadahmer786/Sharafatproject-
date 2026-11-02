import hashlib
import io
import json
import pytest


def test_wsl_transport_keeps_input_bytes_and_container_isolation(pe_bytes, monkeypatch):
    from sentinel.analysis import inspect_pe
    calls = []
    monkeypatch.setenv('SENTINEL_WSL_DISTRO', 'SentinelLab')
    monkeypatch.setattr('shutil.which', lambda name: 'C:/Windows/System32/wsl.exe' if name == 'wsl.exe' else None)
    def worker(command, data, **kwargs):
        calls.append(command)
        assert data == pe_bytes
        return b'{}'
    monkeypatch.setattr('sentinel.analysis.run_bounded', worker)
    monkeypatch.setattr('subprocess.run', lambda command, **kwargs: calls.append(command))
    result = inspect_pe(pe_bytes, 'demo.exe', mode='docker')
    assert result['sha256'] == hashlib.sha256(pe_bytes).hexdigest()
    assert calls[0][:8] == ['C:/Windows/System32/wsl.exe', '-d', 'SentinelLab', '-u', 'root', '--exec', 'docker', 'run']
    assert '--network=none' in calls[0] and '--read-only' in calls[0]
    assert calls[1][:8] == ['C:/Windows/System32/wsl.exe', '-d', 'SentinelLab', '-u', 'root', '--exec', 'docker', 'rm']


def test_configured_wsl_failure_never_uses_another_docker_engine(pe_bytes, monkeypatch):
    from sentinel.analysis import inspect_pe
    monkeypatch.setenv('SENTINEL_WSL_DISTRO', 'SentinelLab')
    monkeypatch.setattr('shutil.which', lambda name: 'docker' if name == 'docker' else None)
    with pytest.raises(ValueError, match='WSL'):
        inspect_pe(pe_bytes, 'demo.exe', mode='docker')


def test_openbin_web_download_has_hash_provenance_and_no_database_sample(user, app, pe_bytes, monkeypatch):
    from sentinel.models import Scan, db
    def worker(data, name):
        assert data == pe_bytes
        return {'functions': [{'name': 'entry', 'code': 'return;'}],
                'sentinel_provenance': {'sha256': hashlib.sha256(data).hexdigest(), 'ai_model_ran': False}}
    monkeypatch.setattr('sentinel.openbin_local.decompile_local', worker)
    response = user.post('/openbin', data={'file': (io.BytesIO(pe_bytes), 'sample.exe')})
    assert response.status_code == 200
    assert response.mimetype == 'application/json'
    assert 'attachment' in response.headers['Content-Disposition']
    assert 'no-store' in response.headers['Cache-Control']
    assert response.json['sentinel_provenance']['ai_model_ran'] is False
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(Scan)) == 0


def test_openbin_web_requires_login_and_handles_missing_runtime(client, user, monkeypatch, pe_bytes):
    # A separate unauthenticated client must not reach the worker.
    response = client.application.test_client().post('/openbin')
    assert response.status_code == 302 and '/login' in response.location
    def unavailable(*args):
        raise ValueError('Docker is required for local OpenBin.')
    monkeypatch.setattr('sentinel.openbin_local.decompile_local', unavailable)
    response = user.post('/openbin', data={'file': (io.BytesIO(pe_bytes), 'sample.exe')})
    assert response.status_code == 400 and b'Docker is required' in response.data


def test_settings_reports_live_openbin_worker_instead_of_downloaded_cli(user, monkeypatch):
    monkeypatch.setattr('sentinel.operations.image_available',lambda image:(True,'Isolated local worker image available'))
    assert b'OpenBin worker available' in user.get('/settings').data
    monkeypatch.setattr('sentinel.operations.image_available',lambda image:(False,'Start the local worker'))
    page=user.get('/settings')
    assert b'OpenBin setup required' in page.data
    assert b'OpenBin worker available' not in page.data
