"""Route-level checks: another account may write while crypto is running."""
import io
import sqlite3
import time
import pyotp
import pytest
from sentinel.models import db,User
from sentinel.security import encrypt_secret

PASSWORD='Worker-transaction-password-2026!'


@pytest.mark.parametrize('operation',['login','protect','export_keys','recover'])
def test_crypto_routes_release_writer_before_worker(app,client,png,monkeypatch,operation):
    from sentinel.account_keys import ensure_account_key
    from sentinel.protection import protect_document
    import sentinel.account_keys as vault
    import sentinel.routes as routes
    secret=pyotp.random_base32()
    with app.app_context():
        user=User(name='Transaction owner',email='transaction@example.test')
        user.set_password(PASSWORD)
        other=User(name='Other account',email='other-transaction@example.test');other.set_password(PASSWORD)
        db.session.add_all([user,other]);db.session.commit()
        if operation in ('export_keys','recover'):
            public=ensure_account_key(user).public_pem
            user.totp_secret=encrypt_secret(secret);db.session.commit()
        identity=user.get_id(); other_id=other.id; database=db.engine.url.database
    if operation!='login':
        with client.session_transaction() as session:
            session.update(_user_id=identity,_fresh=True,login_at=int(time.time()),last_seen=int(time.time()),
                           epoch=app.config['SESSION_EPOCH'],mfa_verified=True)
    observations=[]
    def independent_write():
        with sqlite3.connect(database,timeout=0.05) as connection:
            connection.execute('UPDATE user SET name=? WHERE id=?',('Still responsive',other_id))
        observations.append(True)
    if operation=='login':
        actual=vault.document_operation
        def worker(*args,**kwargs):
            independent_write()
            return actual(*args,**kwargs)
        monkeypatch.setattr(vault,'document_operation',worker)
        response=client.post('/login',data={'email':'transaction@example.test','password':PASSWORD})
        assert response.status_code==302
    else:
        actual=routes.process_document
        def worker(*args,**kwargs):
            independent_write()
            return actual(*args,**kwargs)
        monkeypatch.setattr(routes,'process_document',worker)
        fields={'trusted_server':'on','key_source':'assigned','current_password':PASSWORD,'code':pyotp.TOTP(secret).now()}
        if operation=='export_keys':
            fields['passphrase']='Export-transaction-passphrase-2026!'
            response=client.post('/keys',data=fields)
        elif operation=='protect':
            fields.update(document=(io.BytesIO(b'transaction check'),'document.txt'),image=(io.BytesIO(png),'cover.png'))
            response=client.post('/protect',data=fields)
        else:
            protected=protect_document(b'transaction check','document.txt',png,public.encode())
            fields['image']=(io.BytesIO(protected),'protected.png')
            response=client.post('/recover',data=fields)
        assert response.status_code==200
    assert observations==[True]
