import hashlib
import re
from datetime import timedelta
import time
import pyotp
from flask import Blueprint, request, render_template, redirect, url_for, session, flash, current_app, abort
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.exc import IntegrityError
from .models import db, User, LoginAttempt, PasswordReset, utcnow, audit
from .security import begin_session, verify_totp, encrypt_secret, consume_reset, check_rate

bp=Blueprint("auth",__name__)


def complete_signin(user,mfa=False,auth_id=None,cleanup_key=None):
    from .account_keys import ensure_account_key
    # Bind to the version whose credentials were checked, before slow key work.
    verified_id=auth_id or user.get_id()
    ensure_account_key(user)
    if cleanup_key:
        db.session.execute(db.delete(LoginAttempt).where(LoginAttempt.key==cleanup_key))
    audit(user.id,'Signed in with two-step verification' if mfa else 'Signed in')
    db.session.commit()
    begin_session(user,mfa=mfa,auth_id=verified_id)

def valid_identity(name,email,password):
    return (2<=len(name)<=80 and len(email)<=254 and
            re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email) and 12<=len(password)<=128)

def attempt_key(prefix):
    return hashlib.sha256((prefix+":"+(request.remote_addr or "unknown")).encode()).hexdigest()

def limited(key,limit,minutes):
    cutoff=utcnow()-timedelta(minutes=minutes)
    return db.session.scalar(db.select(db.func.count()).select_from(LoginAttempt).where(
        LoginAttempt.key==key,LoginAttempt.created_at>=cutoff))>=limit

@bp.route("/register",methods=["GET","POST"])
def register():
    if not current_app.config['ALLOW_REGISTRATION']:
        abort(403)
    error=None
    error_status=400
    if request.method=="POST":
        name=request.form.get("name","").strip()
        email=request.form.get("email","").strip().lower()
        password=request.form.get("password","")
        key=attempt_key("register")
        if not check_rate('register:'+(request.remote_addr or ''),10,60):
            return render_template("auth.html",mode="register",error="Too many attempts. Try again in one hour."),429
        db.session.add(LoginAttempt(key=key))
        db.session.commit()
        if not valid_identity(name,email,password):
            error="Enter your name, a valid email, and a password of 12 to 128 characters."
        else:
            user=User(name=name,email=email,role="user")
            user.set_password(password)
            db.session.add(user)
            try:
                from .account_keys import ensure_account_key
                ensure_account_key(user)
                audit(user.id,"Account created")
                verified_id=user.get_id()
                db.session.commit()
                begin_session(user,auth_id=verified_id)
                flash('Your account and personal encryption keys are ready. Open Encryption keys to download a protected copy.','success')
                return redirect(url_for("main.dashboard"))
            except IntegrityError:
                db.session.rollback()
                error="That email is already registered. Sign in instead."
            except ValueError as exc:
                db.session.rollback()
                error='Your account could not be prepared. '+str(exc)
                error_status=503
    return render_template("auth.html",mode="register",error=error),error_status if error else 200

@bp.route("/login",methods=["GET","POST"])
def login():
    error=None
    if request.method=="POST":
        email=request.form.get("email","").strip().lower()[:254]
        password=request.form.get("password","")[:129]
        key=attempt_key("login")
        if not check_rate('login-ip:'+(request.remote_addr or ''),5,15) or not check_rate('login-account:'+email,10,15):
            return render_template("auth.html",mode="login",error="Too many sign-in attempts. Try again in 15 minutes."),429
        user=db.session.execute(db.select(User).where(User.email==email)).scalar_one_or_none()
        if user and user.enabled and user.check_password(password):
            if user.totp_secret:
                session.clear()
                session['pending_user']=user.id
                session['pending_version']=user.security_version
                session['pending_until']=int(time.time())+300
                return redirect(url_for('auth.mfa'))
            try:
                complete_signin(user,cleanup_key=key)
            except ValueError as exc:
                db.session.rollback()
                return render_template('auth.html',mode='login',error='Your encryption keys could not be prepared. '+str(exc)),503
            return redirect(url_for("main.dashboard"))
        db.session.add(LoginAttempt(key=key))
        db.session.execute(db.delete(LoginAttempt).where(LoginAttempt.created_at<utcnow()-timedelta(days=1)))
        db.session.commit()
        error="Email or password is incorrect, or the account is disabled."
    return render_template("auth.html",mode="login",error=error),400 if error else 200


@bp.route('/mfa', methods=['GET', 'POST'])
def mfa():
    user=db.session.get(User, session.get('pending_user')) if session.get('pending_user') else None
    if not user or not user.enabled or session.get('pending_version')!=user.security_version or time.time()>session.get('pending_until',0):
        session.clear()
        return redirect(url_for('auth.login'))
    error=None
    if request.method=='POST':
        if not check_rate('mfa:'+user.id, 5, 5):
            abort(429)
        if verify_totp(user, request.form.get('code','')):
            verified_id=f"{user.id}:{session['pending_version']}"
            # Consume the code before isolated key generation; do not hold a write lock.
            db.session.commit()
            try:
                complete_signin(user,mfa=True,auth_id=verified_id)
            except ValueError as exc:
                db.session.rollback()
                return render_template('account_form.html',mode='mfa',title='Two-step verification',
                    error='Your encryption keys could not be prepared. '+str(exc)),503
            return redirect(url_for('main.dashboard'))
        db.session.rollback()
        error='The code is invalid or already used. Wait for a new code and try again.'
    return render_template('account_form.html', mode='mfa', title='Two-step verification', error=error),400 if error else 200


@bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    error=None
    if request.method=='POST':
        if not check_rate('reset:'+(request.remote_addr or ''), 5, 15):
            abort(429)
        password=request.form.get('password','')
        if 12<=len(password)<=128 and password==request.form.get('confirm') and consume_reset(request.form.get('token',''),password):
            session.clear()
            flash('Password changed. Sign in with your new password.', 'success')
            return redirect(url_for('auth.login'))
        error='The recovery code is invalid or expired, or the passwords do not match (12–128 characters).'
    return render_template('account_form.html', mode='reset', title='Recover your account', error=error),400 if error else 200


@bp.get('/security')
@login_required
def security():
    return render_template('security.html', title='Account security', active='settings')


def confirm_account():
    if not check_rate('security:'+current_user.id, 10, 15):
        abort(429)
    if not current_user.check_password(request.form.get('current_password','')[:129]):
        return False
    return not current_user.totp_secret or verify_totp(current_user,request.form.get('code',''))


@bp.post('/security/password')
@login_required
def change_password():
    password=request.form.get('password','')
    if not (12<=len(password)<=128 and password==request.form.get('confirm')) or not confirm_account():
        db.session.rollback()
        return render_template('security.html', title='Account security', active='settings', error='Check your current password, verification code, and matching new passwords (12–128 characters).'),400
    current_user.set_password(password)
    db.session.execute(db.delete(PasswordReset).where(PasswordReset.user_id==current_user.id))
    audit(current_user.id, 'Password changed; sessions revoked')
    db.session.commit()
    logout_user()
    session.clear()
    flash('Password changed. All previous sessions were signed out.', 'success')
    return redirect(url_for('auth.login'))


@bp.post('/security/revoke')
@login_required
def revoke_sessions():
    if not confirm_account():
        db.session.rollback()
        return render_template('security.html', title='Account security', error='Current password or verification code is incorrect.'),400
    current_user.revoke_sessions()
    audit(current_user.id, 'Other sessions revoked')
    db.session.flush()
    auth_id=current_user.get_id()
    db.session.commit()
    begin_session(current_user, mfa=bool(current_user.totp_secret), auth_id=auth_id)
    flash('All other sessions were signed out.', 'success')
    return redirect(url_for('auth.security'))


@bp.post('/security/mfa/setup')
@login_required
def setup_mfa():
    if current_user.totp_secret or not confirm_account():
        db.session.rollback()
        return render_template('security.html', title='Account security', error='Check your password. Two-step verification can only be enrolled once.'),400
    secret=pyotp.random_base32()
    current_user.totp_pending=encrypt_secret(secret)
    db.session.commit()
    return render_template('security.html', title='Set up two-step verification', active='settings', setup_secret=secret)


@bp.post('/security/mfa/confirm')
@login_required
def confirm_mfa():
    if not check_rate('mfa-enroll:'+current_user.id,5,5):
        abort(429)
    if not current_user.totp_secret and verify_totp(current_user,request.form.get('code',''),pending=True):
        current_user.totp_secret=current_user.totp_pending
        current_user.totp_pending=None
        current_user.revoke_sessions()
        audit(current_user.id, 'Two-step verification enabled')
        db.session.flush()
        auth_id=current_user.get_id()
        db.session.commit()
        begin_session(current_user, mfa=True, auth_id=auth_id)
        flash('Two-step verification is enabled. Other sessions were signed out.', 'success')
        return redirect(url_for('auth.security'))
    db.session.rollback()
    return render_template('security.html', title='Account security', error='Code is invalid. Start setup again if you need a new enrollment key.'),400

@bp.post("/logout")
@login_required
def logout():
    audit(current_user.id,'Signed out')
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))
