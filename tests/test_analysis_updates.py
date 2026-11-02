from datetime import timedelta
import time

from sentinel.models import db, User, ExternalCheck, utcnow


def seed(app, **values):
    with app.app_context():
        owner = db.session.execute(db.select(User)).scalars().first()
        row = ExternalCheck(user_id=owner.id, kind='hash', target='a' * 64, **values)
        db.session.add(row); db.session.commit()
        return row.id


def test_feed_requires_login_and_is_owner_only(user, app, monkeypatch):
    mine = seed(app, state='queued')
    with app.app_context():
        other = User(name='Other', email='other-updates@example.test', password_hash='unused')
        db.session.add(other); db.session.flush()
        db.session.add(ExternalCheck(user_id=other.id, kind='url', target='https://private-other.example/', state='complete', result={'status':'available'}))
        db.session.commit()
    def no_network(*args, **kwargs):
        raise AssertionError('Updates must never contact the provider')
    monkeypatch.setattr('sentinel.intelligence.provider_call', no_network)
    assert app.test_client().get('/intelligence/updates').status_code == 302
    response = user.get('/intelligence/updates')
    assert response.status_code == 200
    assert [item['id'] for item in response.json['items']] == [mine]
    assert response.json['active_count'] == 1
    assert 'private-other' not in response.get_data(as_text=True)
    assert response.headers['Cache-Control'].startswith('no-store')


def test_statuses_are_truthful_for_all_check_types(user, app):
    with app.app_context():
        owner = db.session.execute(db.select(User)).scalar_one()
        for kind, state, status in [('file','queued','submitted'), ('url','complete','available'),
                                    ('ip','complete','unknown'), ('hash','failed','poll_limit')]:
            db.session.add(ExternalCheck(user_id=owner.id, kind=kind, target=kind+'-target', state=state,
                result={'status':status, 'engines':[{'private':'must not enter feed'}]}))
        db.session.commit()
    response = user.get('/intelligence/updates')
    assert response.status_code == 200
    items = {row['kind']: row for row in response.json['items']}
    assert items['file']['label'] == 'In progress'
    assert items['url']['label'] == 'Analysis complete'
    assert items['ip']['label'] == 'No report available'
    assert items['hash']['label'] == 'Analysis unfinished'
    assert 'engines' not in response.get_data(as_text=True)
    for row in items.values():
        assert row['url'] == '/intelligence/' + row['id']
        assert row['revision'] and len(row['target']) <= 160


def test_feed_is_bounded_but_includes_watched_older_check(user, app):
    old = seed(app, state='queued', updated_at=utcnow()-timedelta(days=2))
    with app.app_context():
        owner = db.session.execute(db.select(User)).scalar_one()
        for n in range(25):
            db.session.add(ExternalCheck(user_id=owner.id, kind='hash', target=str(n), state='queued'))
            db.session.add(ExternalCheck(user_id=owner.id, kind='ip', target=str(n), state='complete', result={'status':'available'}))
        db.session.commit()
    response = user.get('/intelligence/updates?watch=' + old)
    assert response.status_code == 200
    assert len(response.json['items']) == 41
    assert response.json['active_count'] == 26
    assert old in {item['id'] for item in response.json['items']}


def test_background_updates_do_not_extend_idle_session(user):
    previous = int(time.time()) - 120
    with user.session_transaction() as state:
        state['last_seen'] = previous
    assert user.get('/intelligence/updates').status_code == 200
    with user.session_transaction() as state:
        assert state['last_seen'] == previous
        state['last_seen'] = int(time.time()) - 1801
    assert user.get('/intelligence/updates').status_code == 302


def test_feed_revision_changes_after_refresh_and_completion(user, app):
    identity = seed(app, state='complete', result={'status':'available'})
    first = user.get('/intelligence/updates')
    assert first.status_code == 200
    revision = first.json['items'][0]['revision']
    user.post('/intelligence/' + identity + '/refresh')
    second = user.get('/intelligence/updates').json['items'][0]
    assert second['state'] == 'queued' and second['revision'] != revision


def test_authenticated_pages_have_alert_center_and_pending_page_is_live(user, app):
    identity = seed(app, state='queued')
    for path in ('/protect', '/intelligence', '/intelligence/' + identity):
        response = user.get(path)
        assert b'data-analysis-updates' in response.data
        assert b'analysis-updates.js' in response.data
        assert b'aria-controls="analysis-updates-panel"' in response.data
    detail = user.get('/intelligence/' + identity).data
    assert b'data-live-check' in detail and b'about two minutes' not in detail
    assert b'data-analysis-updates' not in app.test_client().get('/login').data
