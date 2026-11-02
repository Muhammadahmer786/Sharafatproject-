"""Render the actual owner-facing templates; no model or sample execution."""
from html.parser import HTMLParser

from sentinel.models import AIAnalysis, User, db


class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def find(self, tag=None, **attrs):
        return [item for name, item in self.tags if (tag is None or name == tag)
                and all(key in item and (value is None or item[key] == value) for key, value in attrs.items())]


def seed(app, state='complete', **values):
    with app.app_context():
        owner = db.session.execute(db.select(User)).scalar_one()
        row = AIAnalysis(user_id=owner.id, filename='sample.exe', sha256='a' * 64, size=1024,
                         model='local-test:4b', state=state, stage=state, progress=100 if state == 'complete' else 0,
                         **values)
        db.session.add(row)
        db.session.commit()
        return row.id


def test_workspace_posts_file_and_explicit_server_trust_with_csrf(user, monkeypatch):
    monkeypatch.setattr('sentinel.ai.model_status', lambda _: {
        'available': False, 'model': 'local-test:4b', 'message': 'Model not installed.'})
    response = user.get('/ai')
    assert response.status_code == 200
    document = Elements(response.get_data(as_text=True))
    assert document.find('form', action='/ai', method='post', enctype='multipart/form-data')
    assert document.find('input', name='file', required=None)
    assert document.find('input', name='trusted_server', value='on', required=None)
    assert document.find('input', name='csrf_token')


def test_completed_report_escapes_untrusted_evidence_and_links_own_exports(user, app):
    hostile = '<img src=x onerror=alert(1)>'
    identity = seed(app, result={
        'verdict': 'suspicious', 'summary': hostile,
        'findings': [{'title': hostile, 'severity': 'medium', 'detail': hostile,
                      'status': 'review_required', 'evidence': [{'evidence_id': 'F1', 'quote': hostile,
                      'kind': 'function', 'name': hostile, 'address': '0x401000'}]}],
        'coverage': {'functions_selected': 1, 'functions_total': 20, 'evidence_bytes': 700},
        'limitations': [hostile], 'model': 'local-test:4b', 'model_digest': 'a' * 64,
        'ai_model_ran': True, 'processing_location': 'local'})
    response = user.get('/ai/' + identity)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert hostile not in html and '&lt;img src=x onerror=alert(1)&gt;' in html
    document = Elements(html)
    assert not document.find('img')
    assert document.find('a', href='/ai/' + identity + '/export')
    assert document.find('a', href='/ai/' + identity + '/report')
    assert document.find('form', action='/ai/' + identity + '/delete', method='post')
    assert not document.find('form', action='/ai/' + identity + '/cancel')
    assert document.find(**{'data-watch-ai': identity})


def test_running_job_has_live_status_and_cancel_but_no_available_delete(user, app):
    identity = seed(app, state='running')
    response = user.get('/ai/' + identity)
    assert response.status_code == 200
    document = Elements(response.get_data(as_text=True))
    assert document.find(**{'data-status-url': '/ai/' + identity + '/status'})
    cancel = document.find('form', action='/ai/' + identity + '/cancel', method='post')
    assert cancel and 'hidden' not in cancel[0]
    assert document.find(**{'data-ai-terminal-actions': None, 'hidden': None})
    assert not document.find('a', href='/ai/' + identity + '/export')


def test_history_links_completed_and_interrupted_records_without_download_claims(user, app):
    complete = seed(app, result={'verdict': 'no_indicators'})
    interrupted = seed(app, state='interrupted', error='Server restarted.')
    response = user.get('/ai/history')
    assert response.status_code == 200
    document = Elements(response.get_data(as_text=True))
    assert document.find('a', href='/ai/' + complete)
    assert document.find('a', href='/ai/' + interrupted)
    assert not document.find('a', href='/ai/' + interrupted + '/report')
