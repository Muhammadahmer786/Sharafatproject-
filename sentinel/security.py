"""Revocable sign-in, TOTP and local-operator password recovery."""
import base64
import hashlib
import secrets
import time
from datetime import timedelta
import pyotp
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from flask import current_app, session
from flask_login import login_user
from sqlalchemy.exc import IntegrityError
from .models import db, User, PasswordReset, RateBucket, audit, utcnow


def cipher():
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b'sentinel-totp-v1').derive(current_app.secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(secret):
    return cipher().encrypt(secret.encode()).decode()


def verify_totp(user, code, pending=False):
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
        return False
    stored = user.totp_pending if pending else user.totp_secret
    if not stored:
        return False
    try:
        totp = pyotp.TOTP(cipher().decrypt(stored.encode()).decode())
    except (InvalidToken, ValueError):
        return False
    now_step = int(time.time()) // 30
    for step in (now_step, now_step - 1, now_step + 1):
        if secrets.compare_digest(totp.at(step * 30), code):
            # Atomic update prevents using the same code in concurrent requests.
            result = db.session.execute(db.update(User).where(
                User.id == user.id, User.totp_last_step < step
            ).values(totp_last_step=step))
            return result.rowcount == 1
    return False


def begin_session(user, mfa=False, auth_id=None):
    session.clear()
    session.permanent = True
    session['login_at'] = int(time.time())
    session['last_seen'] = int(time.time())
    session['mfa_verified'] = bool(mfa)
    session['epoch'] = current_app.config['SESSION_EPOCH']
    login_user(user)
    if auth_id is not None:
        # Retain the version this operation issued, not a later concurrent change.
        session['_user_id']=auth_id


def issue_reset_token(user,actor_id=None):
    token = secrets.token_urlsafe(32)
    db.session.execute(db.delete(PasswordReset).where(PasswordReset.user_id == user.id))
    db.session.add(PasswordReset(token_hash=hashlib.sha256(token.encode()).hexdigest(),
                                user_id=user.id, expires_at=utcnow() + timedelta(minutes=30)))
    audit(actor_id or user.id, 'Local recovery token issued',target_user_id=user.id if actor_id else None)
    db.session.commit()
    return token


def consume_reset(token, password):
    if not token or len(token) > 128:
        return False
    digest = hashlib.sha256(token.encode()).hexdigest()
    row = db.session.get(PasswordReset, digest)
    if not row or row.expires_at <= utcnow():
        return False
    user = db.session.get(User, row.user_id)
    if not user or not user.enabled:
        return False
    result = db.session.execute(db.delete(PasswordReset).where(
        PasswordReset.token_hash == digest, PasswordReset.expires_at > utcnow()))
    if result.rowcount != 1:
        db.session.rollback()
        return False
    user.set_password(password)
    audit(user.id, 'Password recovered by local operator token')
    db.session.commit()
    return True


def check_rate(key, limit, minutes):
    """Atomic fixed-window quota shared by requests/processes, including failed work."""
    window=int(time.time())//(minutes*60)
    digest=hashlib.sha256(f'{key}:{window}'.encode()).hexdigest()
    if not db.session.get(RateBucket,digest):
        db.session.add(RateBucket(key=digest,count=0,expires_at=utcnow()+timedelta(minutes=minutes*2)))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
    result=db.session.execute(db.update(RateBucket).where(
        RateBucket.key==digest,RateBucket.count<limit).values(count=RateBucket.count+1))
    db.session.execute(db.delete(RateBucket).where(RateBucket.expires_at<utcnow()))
    db.session.commit()
    return result.rowcount==1
