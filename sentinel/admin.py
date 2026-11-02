"""Local account administration: authorization is shared by every route."""
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user
from sqlalchemy.orm import aliased
from sqlalchemy.exc import IntegrityError
from .models import db, User, AccountKey, Scan, ExternalCheck, AuditEvent, ReputationJob, utcnow, audit
from .security import check_rate, issue_reset_token

bp=Blueprint('admin',__name__,url_prefix='/admin')


@bp.before_request
def authorize():
    if not current_user.is_authenticated:
        from . import login_manager
        return login_manager.unauthorized()
    if current_user.role!='admin':
        abort(403)
    if current_app.config['REQUIRE_ADMIN_MFA'] and (not current_user.totp_secret or not session.get('mfa_verified')):
        flash('Enable two-step verification before using administrator controls.','error')
        return redirect(url_for('auth.security'))
    if request.method=='POST' and not check_rate('admin-actions:'+current_user.id,30,15):
        abort(429)


def count(model,*conditions):
    return db.session.scalar(db.select(db.func.count()).select_from(model).where(*conditions))


def activity_query(user_id=None,q='',since=None):
    actor=aliased(User); target=aliased(User)
    query=db.select(AuditEvent,actor.name.label('actor_name'),actor.email.label('actor_email'),
                    target.name.label('target_name'),target.email.label('target_email')).join(
        actor,actor.id==AuditEvent.user_id).outerjoin(target,target.id==AuditEvent.target_user_id)
    if user_id:
        query=query.where(db.or_(AuditEvent.user_id==user_id,AuditEvent.target_user_id==user_id))
    if q:
        query=query.where(AuditEvent.action.icontains(q,autoescape=True))
    if since:
        query=query.where(AuditEvent.created_at>=since)
    return query.order_by(AuditEvent.created_at.desc(),AuditEvent.id.desc())


def page_number():
    return max(1,min(request.args.get('page',1,type=int),100000))


def page(query):
    # Multi-column rows must remain intact (Flask-SQLAlchemy paginate unwraps them).
    number=page_number(); total=count_rows(query)
    rows=db.session.execute(query.limit(25).offset((number-1)*25)).all()
    return {'items':rows,'page':number,'total':total,'pages':max(1,(total+24)//25)}


def count_rows(query):
    return db.session.scalar(db.select(db.func.count()).select_from(query.order_by(None).subquery()))


def ordinary_user(user_id):
    user=db.get_or_404(User,user_id)
    if user.role!='user':
        abort(403)
    return user


@bp.get('')
def dashboard():
    stats={'accounts':count(User),'enabled':count(User,User.enabled.is_(True)),
           'keys':count(AccountKey),'today':count(AuditEvent,AuditEvent.created_at>=utcnow()-timedelta(days=1))}
    recent=db.session.execute(activity_query().limit(8)).all()
    return render_template('admin.html',title='Administration',active='admin',section='overview',stats=stats,events=recent)


@bp.get('/users')
def users():
    q=request.args.get('q','').strip()[:100]; status=request.args.get('status','')
    query=db.select(User,AccountKey.user_id.label('key_owner')).outerjoin(AccountKey,AccountKey.user_id==User.id)
    if q:
        query=query.where(db.or_(User.name.icontains(q,autoescape=True),User.email.icontains(q,autoescape=True)))
    if status in ('active','disabled'):
        query=query.where(User.enabled.is_(status=='active'))
    pagination=page(query.order_by(User.created_at.desc(),User.id))
    return render_template('admin_users.html',title='Manage accounts',active='admin',section='users',
                           pagination=pagination,q=q,status=status)


@bp.post('/users/create')
def create_user():
    from .auth import valid_identity
    from .account_keys import ensure_account_key
    name=request.form.get('name','').strip(); email=request.form.get('email','').strip().lower()
    password=secrets.token_urlsafe(48)
    if not valid_identity(name,email,password):
        flash('Enter a name of 2–80 characters and a valid email address.','error')
        return users(),400
    try:
        user=User(name=name,email=email,role='user')
        user.set_password(password); db.session.add(user)
        ensure_account_key(user)
        audit(current_user.id,'Account created by administrator',target_user_id=user.id)
        token=issue_reset_token(user,actor_id=current_user.id)
        return render_template('admin_setup.html',title='Account setup code',active='admin',section='users',
                               account=user,token=token,created=True)
    except IntegrityError:
        db.session.rollback(); flash('An account with this email already exists.','error')
        return users(),400
    except ValueError:
        db.session.rollback(); flash('Account creation could not complete. Check the local document worker and try again.','error')
        return users(),503


@bp.get('/users/<user_id>')
def user_detail(user_id):
    user=db.get_or_404(User,user_id)
    key=db.session.execute(db.select(AccountKey.fingerprint,AccountKey.created_at).where(AccountKey.user_id==user_id)).first()
    counts={'scans':count(Scan,Scan.user_id==user_id),'checks':count(ExternalCheck,ExternalCheck.user_id==user_id)}
    events=db.session.execute(activity_query(user_id).limit(12)).all()
    return render_template('admin_user.html',title='Account details',active='admin',section='users',
                           account=user,key=key,counts=counts,events=events)


@bp.post('/users/<user_id>/toggle')
def toggle_user(user_id):
    user=ordinary_user(user_id); user.enabled=not user.enabled; user.revoke_sessions()
    # A disabled account's old setup/recovery codes must not become usable on re-enable.
    from .models import PasswordReset
    db.session.execute(db.delete(PasswordReset).where(PasswordReset.user_id==user_id))
    audit(current_user.id,'Account enabled' if user.enabled else 'Account disabled',target_user_id=user_id)
    db.session.commit(); flash('Account access updated; previous sessions were revoked.','success')
    return redirect(url_for('admin.user_detail',user_id=user_id))


@bp.post('/users/<user_id>/revoke-sessions')
def revoke_sessions(user_id):
    user=ordinary_user(user_id); user.revoke_sessions()
    audit(current_user.id,'Account sessions revoked',target_user_id=user_id)
    db.session.commit(); flash('All current sessions for this account were revoked.','success')
    return redirect(url_for('admin.user_detail',user_id=user_id))


@bp.post('/users/<user_id>/recovery-code')
def recovery_code(user_id):
    user=ordinary_user(user_id)
    if not user.enabled:
        flash('Enable this account before issuing a recovery code.','error')
        return user_detail(user_id),400
    token=issue_reset_token(user,actor_id=current_user.id)
    return render_template('admin_setup.html',title='Account recovery code',active='admin',section='users',
                           account=user,token=token,created=False)


@bp.get('/activity')
def activity():
    user_id=request.args.get('user','')[:36]; q=request.args.get('q','').strip()[:100]
    since_text=request.args.get('since','')[:10]; since=None
    if since_text:
        try:
            since=datetime.strptime(since_text,'%Y-%m-%d')
        except ValueError:
            return render_template('error.html',code=400,title='Invalid activity date',message='Use a date in YYYY-MM-DD format.'),400
    account=db.get_or_404(User,user_id) if user_id else None
    pagination=page(activity_query(user_id,q,since))
    return render_template('admin_activity.html',title='Account activity',active='admin',section='activity',
                           pagination=pagination,q=q,since=since_text,user_id=user_id,account=account)


@bp.get('/operations')
def operations():
    from .operations import readiness
    jobs=dict(db.session.execute(db.select(ReputationJob.status,db.func.count()).group_by(ReputationJob.status)).all())
    return render_template('operations.html',title='Local server',active='admin',section='operations',
                           readiness=readiness(current_app),jobs=jobs)
