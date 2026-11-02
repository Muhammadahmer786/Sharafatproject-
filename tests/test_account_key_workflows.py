import io
import zipfile
import pytest
import pyotp
from cryptography.hazmat.primitives import serialization
from sentinel.models import db, User, AccountKey


PASSWORD='Assigned-account-password-2026!'
EXPORT_PASSWORD='Separate-export-password-2026!'


def register(client,email='assigned@example.test'):
    return client.post('/register',data={'name':'Assigned owner','email':email,'password':PASSWORD})


def test_registration_assigns_keys_without_manual_generation(client,app):
    assert register(client).status_code==302
    with app.app_context():
        user=db.session.execute(db.select(User)).scalar_one()
        assigned=db.session.get(AccountKey,user.id)
        assert assigned is not None
        initial=assigned.private_pem
    public=client.get('/keys/public')
    assert public.status_code==200 and b'BEGIN PUBLIC KEY' in public.data
    client.post('/logout')
    assert client.post('/login',data={'email':'assigned@example.test','password':PASSWORD}).status_code==302
    with app.app_context():
        assert db.session.get(AccountKey,user.id).private_pem==initial


def test_registration_failure_does_not_create_a_partial_account(client,app,monkeypatch):
    def fail(*args,**kwargs):
        raise ValueError('Isolated worker unavailable')
    monkeypatch.setattr('sentinel.account_keys.document_operation',fail)
    assert register(client).status_code==503
    with app.app_context():
        assert db.session.query(User).count()==0
        assert db.session.query(AccountKey).count()==0


def test_legacy_mfa_account_is_assigned_only_after_verified_signin(client,app):
    from sentinel.security import encrypt_secret
    with app.app_context():
        secret=pyotp.random_base32()
        user=User(name='Legacy',email='legacy@example.test',totp_secret=encrypt_secret(secret))
        user.set_password(PASSWORD); db.session.add(user); db.session.commit(); identity=user.id
    assert client.post('/login',data={'email':'legacy@example.test','password':PASSWORD}).location.endswith('/mfa')
    with app.app_context():
        assert db.session.get(AccountKey,identity) is None
    code=pyotp.TOTP(secret).now()
    assert client.post('/mfa',data={'code':code}).status_code==302
    with app.app_context():
        assert db.session.get(AccountKey,identity) is not None


def test_private_export_requires_fresh_password_and_exports_assigned_pair(client,app):
    register(client)
    before=client.get('/keys/public').data
    fields={'trusted_server':'on','passphrase':EXPORT_PASSWORD,'current_password':'incorrect'}
    rejected=client.post('/keys',data=fields)
    assert rejected.status_code==403
    fields['current_password']=PASSWORD
    exported=client.post('/keys',data=fields)
    assert exported.status_code==200 and exported.mimetype=='application/zip'
    assert exported.headers['Cache-Control'].startswith('no-store')
    with zipfile.ZipFile(io.BytesIO(exported.data)) as archive:
        assert archive.read('recipient-public.pem')==before
        private=serialization.load_pem_private_key(archive.read('recipient-private.pem'),EXPORT_PASSWORD.encode())
    assert private.public_key().public_numbers()==serialization.load_pem_public_key(before).public_numbers()
    client.post('/security/password',data={'current_password':PASSWORD,'password':'New-login-password-2026!','confirm':'New-login-password-2026!'})
    client.post('/login',data={'email':'assigned@example.test','password':'New-login-password-2026!'})
    assert client.get('/keys/public').data==before


def test_key_export_cannot_select_another_account(client,app):
    register(client)
    alice_public=client.get('/keys/public').data
    other=app.test_client(); register(other,'other@example.test')
    with app.app_context():
        other_id=db.session.execute(db.select(User.id).where(User.email=='other@example.test')).scalar_one()
    assert other.get('/keys/public').data!=alice_public
    response=client.post('/keys?user_id='+other_id,data={'user_id':other_id,'trusted_server':'on',
        'current_password':PASSWORD,'passphrase':EXPORT_PASSWORD})
    assert response.status_code==200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read('recipient-public.pem')==alice_public
    assert app.test_client().get('/keys/public').status_code==302


def test_assigned_key_document_roundtrip_requires_owner_verification(client,app,png):
    register(client)
    protected=client.post('/protect',data={'key_source':'assigned','trusted_server':'on',
        'document':(io.BytesIO(b'assigned document\x00\xff'),'assigned.bin'),
        'image':(io.BytesIO(png),'cover.png')},content_type='multipart/form-data')
    assert protected.status_code==200 and protected.mimetype=='image/png'
    def recover(account,password):
        return account.post('/recover',data={'key_source':'assigned','trusted_server':'on',
            'current_password':password,'image':(io.BytesIO(protected.data),'protected.png')},content_type='multipart/form-data')
    assert recover(client,'incorrect').status_code==403
    other=app.test_client(); register(other,'wrong-recipient@example.test')
    assert recover(other,PASSWORD).status_code==400
    result=recover(client,PASSWORD)
    assert result.status_code==200 and result.data==b'assigned document\x00\xff'


def test_export_requires_totp_when_owner_is_enrolled(client,app):
    from sentinel.security import encrypt_secret
    register(client)
    secret=pyotp.random_base32()
    with app.app_context():
        user=db.session.execute(db.select(User)).scalar_one(); user.totp_secret=encrypt_secret(secret); db.session.commit()
    fields={'trusted_server':'on','current_password':PASSWORD,'passphrase':EXPORT_PASSWORD}
    assert client.post('/keys',data=fields).status_code==403
    fields['code']=pyotp.TOTP(secret).now()
    assert client.post('/keys',data=fields).status_code==200
    assert client.post('/keys',data=fields).status_code==403


def test_operator_created_account_receives_keys(app,monkeypatch):
    import run
    monkeypatch.setattr(run,'create_app',lambda:app)
    monkeypatch.setattr('sys.argv',['run.py','create-user','--email','console@example.test'])
    monkeypatch.setattr('builtins.input',lambda prompt:'Console owner')
    monkeypatch.setattr('getpass.getpass',lambda prompt:PASSWORD)
    run.main()
    with app.app_context():
        user=db.session.execute(db.select(User).where(User.email=='console@example.test')).scalar_one()
        assert db.session.get(AccountKey,user.id) is not None


def test_key_generation_cannot_adopt_a_concurrently_reset_login_version(client,app,monkeypatch):
    import sentinel.account_keys as vault
    with app.app_context():
        user=User(name='Concurrent login',email='concurrent@example.test'); user.set_password(PASSWORD)
        db.session.add(user); db.session.commit(); identity=user.id
    actual=vault.ensure_account_key
    def revoke_while_preparing(account):
        key=actual(account)
        db.session.execute(db.update(User).where(User.id==identity).values(security_version=User.security_version+1),
            execution_options={'synchronize_session':False})
        return key
    monkeypatch.setattr(vault,'ensure_account_key',revoke_while_preparing)
    response=client.post('/login',data={'email':'concurrent@example.test','password':PASSWORD})
    assert response.status_code==302
    assert client.get('/keys/public').status_code==302
