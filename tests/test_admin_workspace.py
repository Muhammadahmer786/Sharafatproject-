import hashlib
import re
import time
import pytest
import pyotp
from sentinel.models import db, User, AccountKey, AuditEvent, Scan, ExternalCheck, PasswordReset
from sentinel.security import encrypt_secret

PASSWORD='Admin-workspace-password-2026!'


@pytest.fixture
def accounts(app):
    with app.app_context():
        admin=User(name='Local administrator',email='admin@example.test',role='admin',
                   totp_secret=encrypt_secret(pyotp.random_base32()))
        owner=User(name='Ordinary owner',email='owner@example.test')
        for user in (admin,owner):
            user.set_password(PASSWORD); db.session.add(user)
        db.session.commit()
        return admin.id,owner.id


def signed_client(app,identity,verified=True):
    client=app.test_client()
    with app.app_context():
        user=db.session.get(User,identity)
        auth_id=user.get_id()
    with client.session_transaction() as session:
        session.update(_user_id=auth_id,_fresh=True,login_at=int(time.time()),last_seen=int(time.time()),
                       epoch=app.config['SESSION_EPOCH'],mfa_verified=verified)
    return client


def routes(identity):
    return [('get','/admin'),('get','/admin/users'),('get',f'/admin/users/{identity}'),
            ('get','/admin/activity'),('get','/admin/operations'),('post','/admin/users/create'),
            *[('post',f'/admin/users/{identity}/{action}') for action in ('toggle','revoke-sessions','recovery-code')]]


@pytest.mark.parametrize('role',['anonymous','user','unverified_admin','unenrolled_admin'])
def test_every_admin_route_has_central_role_and_mfa_guard(app,accounts,role):
    admin,owner=accounts
    if role=='unenrolled_admin':
        with app.app_context():
            db.session.get(User,admin).totp_secret=None; db.session.commit()
    client=app.test_client() if role=='anonymous' else signed_client(app,owner if role=='user' else admin,
                                                                 role!='unverified_admin')
    for method,path in routes(owner):
        response=getattr(client,method)(path)
        assert response.status_code==(403 if role=='user' else 302),(role,path,response.status_code)
        if role.endswith('admin'):
            assert response.location.endswith('/security')


def test_admin_creates_assigned_account_and_one_time_password_setup(app,accounts):
    admin,_=accounts
    client=signed_client(app,admin)
    response=client.post('/admin/users/create',data={'name':'New member','email':'new@example.test','role':'admin'})
    assert response.status_code==200
    token=re.search(rb'data-setup-code>([A-Za-z0-9_-]+)<',response.data).group(1).decode()
    with app.app_context():
        user=db.session.execute(db.select(User).where(User.email=='new@example.test')).scalar_one()
        assert user.role=='user' and db.session.get(AccountKey,user.id)
        public=db.session.get(AccountKey,user.id).public_pem
        reset=db.session.get(PasswordReset,hashlib.sha256(token.encode()).hexdigest())
        assert reset and reset.user_id==user.id
        event=db.session.execute(db.select(AuditEvent).where(AuditEvent.action=='Account created by administrator')).scalar_one()
        assert event.user_id==admin and event.target_user_id==user.id
    assert token.encode() not in client.get('/admin/users').data
    owner=app.test_client()
    assert owner.post('/reset-password',data={'token':token,'password':PASSWORD,'confirm':PASSWORD}).status_code==302
    assert owner.post('/reset-password',data={'token':token,'password':PASSWORD,'confirm':PASSWORD}).status_code==400
    assert owner.post('/login',data={'email':'new@example.test','password':PASSWORD}).status_code==302
    assert owner.get('/keys/public').data.decode()==public


def test_admin_creation_failure_is_atomic(app,accounts,monkeypatch):
    def fail(*args,**kwargs):
        raise ValueError('Worker unavailable')
    monkeypatch.setattr('sentinel.account_keys.document_operation',fail)
    client=signed_client(app,accounts[0])
    assert client.post('/admin/users/create',data={'name':'Failure','email':'failure@example.test'}).status_code==503
    with app.app_context():
        assert db.session.execute(db.select(User).where(User.email=='failure@example.test')).scalar_one_or_none() is None


def test_admin_actions_revoke_access_and_record_actor_target(app,accounts):
    admin,owner=accounts
    client=signed_client(app,admin); owner_client=signed_client(app,owner)
    assert client.post(f'/admin/users/{owner}/revoke-sessions').status_code==302
    assert owner_client.get('/history').status_code==302
    owner_client=signed_client(app,owner)
    assert client.post(f'/admin/users/{owner}/toggle').status_code==302
    assert owner_client.get('/history').status_code==302
    with app.app_context():
        assert not db.session.get(User,owner).enabled
        events=db.session.execute(db.select(AuditEvent).where(AuditEvent.user_id==admin)).scalars().all()
        assert {event.action for event in events}>={'Account disabled','Account sessions revoked'}
        assert all(event.target_user_id==owner for event in events)
    assert client.post(f'/admin/users/{owner}/recovery-code').status_code==400
    assert client.post(f'/admin/users/{owner}/toggle').status_code==302
    response=client.post(f'/admin/users/{owner}/recovery-code')
    assert response.status_code==200 and b'data-setup-code' in response.data


def test_administrator_accounts_are_read_only(app,accounts):
    client=signed_client(app,accounts[0])
    for action in ('toggle','revoke-sessions','recovery-code'):
        assert client.post(f'/admin/users/{accounts[0]}/{action}').status_code==403


def test_admin_metadata_excludes_private_contents_and_keys(app,accounts):
    from sentinel.account_keys import ensure_account_key
    admin,owner=accounts
    with app.app_context():
        key=ensure_account_key(db.session.get(User,owner)); private=key.private_pem
        scan=Scan(user_id=owner,filename='SECRET-FILE-NAME',sha256='a'*64,size=1,
                  static={'private':'SECRET-SCAN-CONTENT'})
        check=ExternalCheck(user_id=owner,kind='url',target='https://SECRET-URL.test/',result={'secret':'SECRET-RESULT'})
        db.session.add_all([scan,check]); db.session.commit(); scan_id=scan.id
    client=signed_client(app,admin)
    for path in ('/admin','/admin/users',f'/admin/users/{owner}','/admin/activity'):
        response=client.get(path)
        assert response.status_code==200
        for secret in (private,'SECRET-FILE-NAME','SECRET-SCAN-CONTENT','SECRET-URL','SECRET-RESULT'):
            assert secret.encode() not in response.data
    assert client.get(f'/scans/{scan_id}').status_code==404
    assert client.get('/keys/public?user_id='+owner).status_code==404


def test_user_search_activity_filter_and_pagination(app,accounts):
    admin,owner=accounts
    with app.app_context():
        db.session.add_all([AuditEvent(user_id=admin,target_user_id=owner,action='Account sessions revoked') for _ in range(27)])
        db.session.add(AuditEvent(user_id=owner,action='Document protected'))
        db.session.commit()
    client=signed_client(app,admin)
    assert b'owner@example.test' in client.get('/admin/users?q=Ordinary').data
    assert b'owner@example.test' not in client.get('/admin/users?q=no-match').data
    response=client.get('/admin/activity?user='+owner+'&q=revoked')
    assert response.status_code==200 and response.data.count(b'Account sessions revoked')==25
    response=client.get('/admin/activity?user='+owner+'&q=revoked&page=2')
    assert response.data.count(b'Account sessions revoked')==2
    assert b'Document protected' not in response.data
    assert client.get('/admin/activity?since=not-a-date').status_code==400
    assert client.get('/admin/activity?since=2100-01-01').data.count(b'Account sessions revoked')==0


def test_actual_mfa_signin_unlocks_admin_workspace(app,accounts):
    from sentinel.security import cipher
    client=app.test_client()
    assert client.post('/login',data={'email':'admin@example.test','password':PASSWORD}).location.endswith('/mfa')
    assert client.get('/admin/users').status_code==302
    with app.app_context():
        secret=cipher().decrypt(db.session.get(User,accounts[0]).totp_secret.encode()).decode()
    assert client.post('/mfa',data={'code':pyotp.TOTP(secret).now()}).status_code==302
    assert client.get('/admin/users').status_code==200
