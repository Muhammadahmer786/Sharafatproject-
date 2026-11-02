"""Automatic account keys in the trusted local server's encrypted key vault."""
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app
from .models import db, AccountKey, audit, uid
from .processing import document_operation, document_slots
from .protection import MAX_KEY


def vault_passphrase(user_id):
    secret=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,
        info=b'sentinel-account-key-v1:'+user_id.encode('ascii')).derive(current_app.secret_key.encode())
    return base64.urlsafe_b64encode(secret).decode('ascii')


def ensure_account_key(user):
    """Assign once, in the caller's transaction. Never replace an existing key."""
    if not user.id:
        user.id=uid()
    with db.session.no_autoflush:
        existing=db.session.get(AccountKey,user.id)
    if existing is not None:
        if existing.vault_version!=1:
            raise ValueError('This account key requires a newer server version.')
        return existing
    if not document_slots.acquire(blocking=False):
        raise ValueError('Key assignment is busy. Please try again shortly.')
    try:
        public,private=document_operation('keys',[vault_passphrase(user.id)],
            mode=current_app.config['PE_WORKER_MODE'],image=current_app.config['PE_WORKER_IMAGE'])
    finally:
        document_slots.release()
    if (not isinstance(public,bytes) or not isinstance(private,bytes) or
            len(public)>MAX_KEY or len(private)>MAX_KEY or
            not public.startswith(b'-----BEGIN PUBLIC KEY-----') or
            not private.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----')):
        raise ValueError('The isolated worker returned an invalid key pair.')
    values=dict(user_id=user.id,public_pem=public.decode('ascii'),private_pem=private.decode('ascii'),
        fingerprint=hashlib.sha256(public).hexdigest(),vault_version=1)
    db.session.flush()
    # Database conflict handling ensures concurrent logins keep the winning pair.
    if db.engine.dialect.name=='sqlite':
        from sqlalchemy.dialects.sqlite import insert
        statement=insert(AccountKey).values(**values).on_conflict_do_nothing(index_elements=['user_id'])
    elif db.engine.dialect.name=='mysql':
        from sqlalchemy.dialects.mysql import insert
        statement=insert(AccountKey).values(**values).on_duplicate_key_update(user_id=AccountKey.user_id)
    else:
        raise ValueError('Account key assignment requires SQLite or MySQL.')
    result=db.session.execute(statement)
    key=db.session.get(AccountKey,user.id,populate_existing=True)
    if result.rowcount==1:
        audit(user.id,'Account encryption keys assigned')
    return key
