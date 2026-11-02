import io
import sqlite3
import time
import pytest
from sentinel.models import db, AIAnalysis, User, SchemaVersion


@pytest.fixture(autouse=True)
def available(monkeypatch):
    monkeypatch.setattr('sentinel.ai.model_status', lambda config: {
        'available': True, 'model': 'test-local', 'message': 'Local model ready'})


def submit(user, pe_bytes):
    response = user.post('/ai', data={'trusted_server': 'on', 'file': (io.BytesIO(pe_bytes), 'sample.exe')})
    assert response.status_code == 302
    return response.location


def test_submit_detail_owner_history_exports_and_cancel(user, app, pe_bytes):
    location = submit(user, pe_bytes)
    assert user.get(location).status_code == 200
    assert b'sample.exe' in user.get('/ai/history').data
    assert user.get(location + '/status').json['state'] == 'queued'
    exported = user.get(location + '/export')
    assert exported.json['state'] == 'queued'
    assert 'attachment;' in exported.headers['Content-Disposition']
    assert user.get(location + '/report').data.startswith(b'%PDF')
    user.post(location + '/delete')
    assert user.get(location).status_code == 200  # active records must be cancelled first
    user.post(location + '/cancel')
    assert user.get(location + '/status').json['state'] == 'cancelled'
    user.post(location + '/delete')
    assert user.get(location).status_code == 404


def test_private_to_owner_even_from_another_account(user, app, pe_bytes):
    location = submit(user, pe_bytes)
    other = app.test_client()
    other.post('/register', data={'name': 'Other', 'email': 'other-ai@example.test', 'password': 'Other-password-2026!'})
    for suffix in ('', '/status', '/export', '/report'):
        assert other.get(location + suffix).status_code == 404
    for suffix in ('/cancel', '/delete'):
        assert other.post(location + suffix).status_code == 404
    assert b'sample.exe' not in other.get('/ai/history').data
    feed = other.get('/intelligence/updates?watch_ai=' + location.rsplit('/', 1)[-1]).json
    assert not feed['items']


def test_input_requires_consent_size_native_type_and_available_model(user, pe_bytes, monkeypatch):
    assert user.post('/ai', data={'file': (io.BytesIO(pe_bytes), 'sample.exe')}).status_code == 400
    assert user.post('/ai', data={'trusted_server': 'on', 'file': (io.BytesIO(pe_bytes), 'sample.txt')}).status_code == 400
    monkeypatch.setattr('sentinel.ai.model_status', lambda c: {'available': False, 'message': 'Install local model', 'model': 'x'})
    response = user.post('/ai', data={'trusted_server': 'on', 'file': (io.BytesIO(pe_bytes), 'sample.exe')})
    assert response.status_code == 400 and b'Install local model' in response.data


def test_alerts_link_to_ai_and_poll_does_not_extend_idle(user, app, pe_bytes):
    location = submit(user, pe_bytes)
    feed = user.get('/intelligence/updates').json
    item = feed['items'][0]
    assert feed['active_count'] == 1 and item['kind'] == 'local_ai' and item['url'] == location
    with user.session_transaction() as session:
        before = int(time.time()) - 60
        session['last_seen'] = before
    user.get(location + '/status')
    with user.session_transaction() as session:
        assert session['last_seen'] == before
    user.post(location + '/cancel')
    feed = user.get('/intelligence/updates').json
    assert feed['active_count'] == 0 and feed['items'][0]['label'] == 'AI analysis cancelled'


def test_csrf_required_for_job_changes(user, app, pe_bytes):
    location = submit(user, pe_bytes)
    app.config['WTF_CSRF_ENABLED'] = True
    assert user.post(location + '/cancel').status_code == 400
    assert user.post(location + '/delete').status_code == 400


def test_schema_four_restore_adds_ai_table_without_modifying_backup(user, app, tmp_path):
    from sentinel.database import sqlite_backup
    from sentinel.operations import restore_database
    source = tmp_path / 'test.db'
    backup = sqlite_backup(source, tmp_path / 'backups')
    with sqlite3.connect(backup) as connection:
        connection.execute('DROP TABLE ai_analysis')
        connection.execute('UPDATE schema_version SET version=4')
    with app.app_context():
        identity = db.session.execute(db.select(User.id)).scalar_one()
        db.session.remove(); db.engine.dispose()
    restore_database(backup, source, tmp_path)
    with app.app_context():
        assert db.session.get(SchemaVersion, 1).version == 5
        assert db.session.get(User, identity)
        assert db.session.query(AIAnalysis).count() == 0
    with sqlite3.connect(backup) as connection:
        assert connection.execute('SELECT version FROM schema_version').fetchone()[0] == 4


def test_completed_report_escapes_model_text(user, app, pe_bytes):
    location = submit(user, pe_bytes)
    with app.app_context():
        row = db.session.get(AIAnalysis, location.rsplit('/', 1)[-1])
        row.state = 'complete'; row.stage = 'complete'; row.progress = 100
        row.result = {'verdict': 'suspicious', 'summary': '<script>evil()</script>', 'findings': [
            {'title': '<b>untrusted</b>', 'severity': 'low', 'detail': 'Review required', 'evidence': [
                {'evidence_id': 'F1', 'quote': '<script>evil()</script>', 'kind': 'function'}]}]}
        db.session.commit()
    html = user.get(location).get_data(as_text=True)
    assert '<script>evil()</script>' not in html and '&lt;script&gt;' in html
    assert user.get(location + '/report').data.startswith(b'%PDF')
