from datetime import timedelta
import hashlib
import pytest
import pyotp


def test_registration_can_be_closed_without_locking_out_existing_users(user, app):
    app.config['ALLOW_REGISTRATION'] = False
    user.post('/logout')
    assert user.get('/register').status_code == 403
    assert user.post('/register', data={'name': 'New', 'email': 'new@example.test', 'password': 'Long-password-2026!'}).status_code == 403
    assert user.post('/login', data={'email': 'ayesha@example.test', 'password': 'Correct-horse-42!'}).status_code == 302


def test_rejects_remote_clients_and_dns_rebinding(client):
    assert client.get('/health', headers={'Host': 'attacker.example'}).status_code == 400
    assert client.get('/health', environ_overrides={'REMOTE_ADDR': '192.168.1.22'}).status_code == 403
    assert client.get('/health', headers={'X-Forwarded-For': '8.8.8.8'}).status_code == 200


def test_password_change_revokes_every_old_session(user, app):
    other = app.test_client()
    other.post('/login', data={'email': 'ayesha@example.test', 'password': 'Correct-horse-42!'})
    bad = user.post('/security/password', data={'current_password': 'wrong', 'password': 'New-unique-password-42!', 'confirm': 'New-unique-password-42!'})
    assert bad.status_code == 400
    result = user.post('/security/password', data={'current_password': 'Correct-horse-42!', 'password': 'New-unique-password-42!', 'confirm': 'New-unique-password-42!'})
    assert result.status_code == 302
    assert other.get('/').status_code == 302
    assert user.get('/').status_code == 302
    assert user.post('/login', data={'email': 'ayesha@example.test', 'password': 'New-unique-password-42!'}).status_code == 302


def test_local_reset_token_is_hashed_expiring_and_single_use(user, app):
    from sentinel.security import issue_reset_token
    from sentinel.models import db, User, PasswordReset, utcnow
    with app.app_context():
        account = db.session.execute(db.select(User)).scalar_one()
        token = issue_reset_token(account)
        row = db.session.execute(db.select(PasswordReset)).scalar_one()
        assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert row.expires_at <= utcnow() + timedelta(minutes=31)
    other = app.test_client()
    response = other.post('/reset-password', data={'token': token, 'password': 'Reset-new-password-2026!', 'confirm': 'Reset-new-password-2026!'})
    assert response.status_code == 302
    assert user.get('/').status_code == 302
    assert other.post('/reset-password', data={'token': token, 'password': 'Another-password-2026!', 'confirm': 'Another-password-2026!'}).status_code == 400


def test_mfa_login_requires_second_factor_and_rejects_replay(user, app, monkeypatch):
    from sentinel.security import encrypt_secret
    from sentinel.models import db, User
    secret = pyotp.random_base32()
    with app.app_context():
        account = db.session.execute(db.select(User)).scalar_one()
        account.totp_secret = encrypt_secret(secret)
        assert secret not in account.totp_secret
        db.session.commit()
    user.post('/logout')
    response = user.post('/login', data={'email': 'ayesha@example.test', 'password': 'Correct-horse-42!'})
    assert response.location.endswith('/mfa')
    assert user.get('/').status_code == 302
    code=pyotp.TOTP(secret).now()
    assert user.post('/mfa', data={'code': code}).status_code == 302
    assert user.get('/').status_code == 200
    user.post('/logout')
    user.post('/login', data={'email': 'ayesha@example.test', 'password': 'Correct-horse-42!'})
    assert user.post('/mfa', data={'code': code}).status_code == 400
    assert user.get('/').status_code == 302


def test_admin_actions_require_mfa_enrollment(user, app):
    from sentinel.models import db, User
    with app.app_context():
        account = db.session.execute(db.select(User)).scalar_one()
        account.role = 'admin'
        db.session.commit()
    response = user.get('/admin')
    assert response.status_code == 302
    assert '/security' in response.location


def test_absolute_session_expiry(user):
    import time
    with user.session_transaction() as state:
        state['login_at'] = int(time.time()) - 8 * 3600 - 1
    assert user.get('/').status_code == 302


def test_password_change_invalidates_previously_issued_recovery_code(user,app):
    from sentinel.models import db,User
    from sentinel.security import issue_reset_token
    with app.app_context():
        token=issue_reset_token(db.session.execute(db.select(User)).scalar_one())
    user.post('/security/password',data={'current_password':'Correct-horse-42!', 'password':'New-password-2026!', 'confirm':'New-password-2026!'})
    response=app.test_client().post('/reset-password',data={'token':token,'password':'Attacker-password-2026!','confirm':'Attacker-password-2026!'})
    assert response.status_code==400


def test_operation_limit_is_atomic_across_threads(app,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from sentinel.security import check_rate
    from sentinel.models import db
    barrier=Barrier(4)
    original_scalar=db.session.scalar
    def race_read(*args,**kwargs):
        result=original_scalar(*args,**kwargs)
        barrier.wait(timeout=5)
        return result
    monkeypatch.setattr(db.session,'scalar',race_read)
    def attempt(_):
        with app.app_context():
            barrier.wait()
            return check_rate('concurrent-test',1,10)
    with ThreadPoolExecutor(max_workers=4) as executor:
        results=list(executor.map(attempt,range(4)))
    assert sum(results)==1
