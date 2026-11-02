"""Separate external-analysis workspace. Uploaded bytes never enter the database."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import threading
import uuid
from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename
from .models import db, ExternalCheck, AIAnalysis, ProviderQuota, audit, utcnow
from .security import check_rate
from .intel_provider import provider_call, validate_target, MAX_EXTERNAL_FILE

bp=Blueprint('intel',__name__)
upload_slots=threading.BoundedSemaphore(2)
KINDS={'hash':('File hash','hash'),'url':('URL','link'),'ip':('IP address','globe'),'file':('File upload','upload')}
MESSAGES={
    'available':'Provider analysis is available. Results are evidence, not a guarantee of safety.',
    'unknown':'VirusTotal has no report for this indicator. This does not mean it is safe.',
    'unauthorized':'VirusTotal rejected the API credentials or access level. Ask your administrator to check the key.',
    'rate_limited':'VirusTotal rate limited this request. Try again after the provider quota resets.',
    'unavailable':'The provider did not return a usable response. A submission may have reached VirusTotal; it was not automatically repeated.',
    'rejected':'VirusTotal rejected the submission. Check the input and the account permissions.',
    'not_configured':'A VirusTotal API key must be configured by the local administrator.',
    'interrupted':'Submission was interrupted and its outcome is uncertain. It was not automatically repeated.',
    'poll_limit':'The analysis is still unfinished after the polling window. Use Refresh result to check again.',
    'retry_limit':'The provider request stopped after three unsuccessful or interrupted attempts. Use Refresh result to retry.',
}


def owned(check_id):
    return db.session.execute(db.select(ExternalCheck).where(ExternalCheck.id==check_id,
        ExternalCheck.user_id==current_user.id)).scalar_one_or_none() or abort(404)


def finish_result(check_id,token,result):
    row=db.session.get(ExternalCheck,check_id)
    if not row or row.lease_token!=token: return
    status=result.get('status','unavailable')
    values={'result':result,'updated_at':utcnow(),'lease_token':None,'lease_until':None}
    if status=='submitted':
        values.update(analysis_id=result['analysis_id'],state='queued',available_at=utcnow()+timedelta(seconds=20),attempts=0)
    elif status=='pending':
        values.update(attempts=0,state='queued',available_at=utcnow()+timedelta(seconds=30))
        if row.polls>=20:
            values.update(state='failed',result={'status':'poll_limit'})
    elif status in ('unavailable','rate_limited') and (row.kind in ('hash','ip') or row.analysis_id) and row.attempts<3:
        values.update(state='queued',available_at=utcnow()+timedelta(seconds=60*max(row.attempts,1)))
    else:
        values['state']='complete' if status in ('available','unknown') else 'failed'
    db.session.execute(db.update(ExternalCheck).where(ExternalCheck.id==check_id,
        ExternalCheck.lease_token==token).values(**values))
    db.session.commit()


def run_one_check(app):
    from .routes import reserve_lookup
    with app.app_context():
        now=utcnow()
        eligible=db.or_(db.and_(ExternalCheck.state=='queued',ExternalCheck.available_at<=now),
            db.and_(ExternalCheck.state=='running',ExternalCheck.lease_until<=now))
        row=db.session.execute(db.select(ExternalCheck).where(eligible).order_by(ExternalCheck.available_at).limit(1)).scalar_one_or_none()
        if not row: return False
        identity=row.id; previous_state=row.state; token=str(uuid.uuid4())
        claimed=db.session.execute(db.update(ExternalCheck).where(ExternalCheck.id==identity,eligible).values(
            state='running',lease_token=token,lease_until=now+timedelta(seconds=90)))
        db.session.commit()
        if claimed.rowcount!=1: return False
        row=db.session.get(ExternalCheck,identity)
        if not row: return True
        if not app.config['VIRUSTOTAL_API_KEY']:
            finish_result(identity,token,{'status':'not_configured'}); return True
        if not row.analysis_id and (row.kind=='file' or (row.kind=='url' and previous_state=='running')):
            finish_result(identity,token,{'status':'interrupted'}); return True
        if row.attempts>=3:
            finish_result(identity,token,{'status':'retry_limit'}); return True
        if row.analysis_id and row.polls>=20:
            finish_result(identity,token,{'status':'poll_limit'}); return True
        if not reserve_lookup():
            quota=db.session.get(ProviderQuota,'virustotal')
            delay=3600 if quota.count>=500 and quota.day==utcnow().strftime('%Y-%m-%d') else 20
            db.session.execute(db.update(ExternalCheck).where(ExternalCheck.id==identity,ExternalCheck.lease_token==token).values(
                state='queued',lease_token=None,lease_until=None,available_at=utcnow()+timedelta(seconds=delay)))
            db.session.commit(); return True
        operation='analysis' if row.analysis_id else row.kind
        value=row.analysis_id or row.target
        # Count every network attempt before starting; a crash cannot bypass retry bounds.
        changed=db.session.execute(db.update(ExternalCheck).where(ExternalCheck.id==identity,ExternalCheck.lease_token==token).values(
            attempts=ExternalCheck.attempts+1,polls=ExternalCheck.polls+(1 if row.analysis_id else 0)))
        db.session.commit()
        if not changed.rowcount: return True
        db.session.remove()
        result=provider_call(operation,value,app.config['VIRUSTOTAL_API_KEY'])
        finish_result(identity,token,result)
        return True


@bp.route('/intelligence',methods=['GET','POST'])
@login_required
def workspace():
    mode=request.form.get('kind','hash') if request.method=='POST' else request.args.get('kind','hash')
    if mode not in KINDS: mode='hash'
    error=None
    if request.method=='POST':
        try:
            if request.form.get('kind') not in KINDS: raise ValueError('Choose a supported check type.')
            if request.form.get('consent')!='on': raise ValueError('Confirm disclosure to VirusTotal before submitting a check.')
            if not current_app.config['VIRUSTOTAL_API_KEY']: raise ValueError(MESSAGES['not_configured'])
            if not check_rate('external:'+current_user.id,15,1): abort(429)
            if mode=='file':
                item=request.files.get('file')
                if not item or not item.filename: raise ValueError('Choose a file to upload.')
                data=item.stream.read(MAX_EXTERNAL_FILE+1)
                if not 1<=len(data)<=MAX_EXTERNAL_FILE: raise ValueError('Choose a non-empty file no larger than 20 MiB.')
                if not upload_slots.acquire(blocking=False): abort(429)
                try:
                    from .routes import reserve_lookup
                    if not reserve_lookup(): raise ValueError('The shared VirusTotal quota is busy. Wait at least 20 seconds before uploading again; daily limits may take longer.')
                    row=ExternalCheck(user_id=current_user.id,kind='file',target=secure_filename(item.filename)[:180] or 'uploaded-file',
                        sha256=hashlib.sha256(data).hexdigest(),size=len(data),state='running',attempts=1,
                        lease_token=str(uuid.uuid4()),lease_until=utcnow()+timedelta(seconds=90))
                    db.session.add(row); audit(current_user.id,'VirusTotal file disclosure authorized'); db.session.commit()
                    identity,token=row.id,row.lease_token
                    db.session.remove()
                    result=provider_call('file','sample.bin',current_app.config['VIRUSTOTAL_API_KEY'],file_bytes=data)
                    finish_result(identity,token,result)
                finally: upload_slots.release()
            else:
                target=validate_target(mode,request.form.get('target',''))
                row=ExternalCheck(user_id=current_user.id,kind=mode,target=target)
                db.session.add(row); audit(current_user.id,'VirusTotal '+mode+' disclosure authorized'); db.session.commit()
                identity=row.id
            return redirect(url_for('intel.detail',check_id=identity))
        except ValueError as exc:
            db.session.rollback(); error=str(exc)
    recent=db.session.execute(db.select(ExternalCheck).where(ExternalCheck.user_id==current_user.id).order_by(ExternalCheck.created_at.desc()).limit(5)).scalars().all()
    count=db.session.scalar(db.select(db.func.count()).select_from(ExternalCheck).where(ExternalCheck.user_id==current_user.id))
    return render_template('intelligence.html',title='Threat intelligence',active='intelligence',mode=mode,kinds=KINDS,
        recent=recent,total=count,error=error,target=request.form.get('target','')[:2048]),400 if error else 200


@bp.get('/intelligence/history')
@login_required
def history():
    query=request.args.get('q','').strip()[:180]; kind=request.args.get('kind','')
    try: page=max(1,int(request.args.get('page','1')))
    except ValueError: page=1
    stmt=db.select(ExternalCheck).where(ExternalCheck.user_id==current_user.id)
    if query: stmt=stmt.where(ExternalCheck.target.contains(query,autoescape=True))
    if kind in KINDS: stmt=stmt.where(ExternalCheck.kind==kind)
    records=db.paginate(stmt.order_by(ExternalCheck.created_at.desc()),page=page,per_page=15,error_out=False)
    return render_template('intel_history.html',title='Intelligence history',active='intel-history',records=records,q=query,kind=kind,kinds=KINDS)


@bp.get('/intelligence/<check_id>')
@login_required
def detail(check_id):
    row=owned(check_id)
    stats=(row.result or {}).get('stats',{})
    timestamp=row.result.get('analysis_date')
    report_date=datetime.fromtimestamp(timestamp,timezone.utc).strftime('%d %b %Y at %H:%M UTC') if timestamp else 'Not supplied by VirusTotal'
    return render_template('intel_detail.html',title='Check results',active='intelligence',check=row,kinds=KINDS,
        stats=stats,engine_total=sum(stats.values()),report_date=report_date,message=MESSAGES.get(row.result.get('status'),'Waiting for a provider result.'))


@bp.get('/intelligence/<check_id>/status')
@login_required
def status(check_id):
    row=owned(check_id)
    return jsonify(status='pending' if row.state in ('queued','running') else row.state)


@bp.get('/intelligence/updates')
@login_required
def updates():
    """Read local owner status only; this endpoint never spends provider quota."""
    owner=ExternalCheck.user_id==current_user.id
    active=ExternalCheck.state.in_(('queued','running'))
    active_count=db.session.scalar(db.select(db.func.count()).select_from(ExternalCheck).where(owner,active))
    rows=[]
    for condition in (active,~active):
        rows.extend(db.session.execute(db.select(ExternalCheck).where(owner,condition)
            .order_by(ExternalCheck.updated_at.desc(),ExternalCheck.id).limit(20)).scalars().all())
    watch=request.args.get('watch','')[:36]
    if watch and not any(row.id==watch for row in rows):
        watched=db.session.execute(db.select(ExternalCheck).where(owner,ExternalCheck.id==watch)).scalar_one_or_none()
        if watched: rows.append(watched)
    items=[]
    for row in sorted(rows,key=lambda item:item.updated_at,reverse=True):
        result_status=(row.result or {}).get('status','unavailable')
        if row.state in ('queued','running'):
            label,tone='In progress','working'
        elif row.state=='complete' and result_status=='available':
            label,tone='Analysis complete','ready'
        elif row.state=='complete' and result_status=='unknown':
            label,tone='No report available','attention'
        else:
            label='Analysis unfinished' if result_status=='poll_limit' else 'Analysis needs attention'
            tone='attention'
        items.append({'id':row.id,'kind':row.kind,'kind_label':KINDS.get(row.kind,('Check',))[0],
            'target':row.target[:160],'state':row.state,'label':label,'tone':tone,
            'revision':row.state+':'+row.updated_at.isoformat(),
            'url':url_for('intel.detail',check_id=row.id)})
    ai_owner=AIAnalysis.user_id==current_user.id
    ai_active=AIAnalysis.state.in_(('queued','running'))
    active_count+=db.session.scalar(db.select(db.func.count()).select_from(AIAnalysis).where(ai_owner,ai_active))
    ai_rows=[]
    for condition in (ai_active,~ai_active):
        ai_rows.extend(db.session.execute(db.select(AIAnalysis).where(ai_owner,condition)
            .order_by(AIAnalysis.updated_at.desc(),AIAnalysis.id).limit(20)).scalars().all())
    watch_ai=request.args.get('watch_ai','')[:36]
    if watch_ai and not any(row.id==watch_ai for row in ai_rows):
        watched=db.session.execute(db.select(AIAnalysis).where(ai_owner,AIAnalysis.id==watch_ai)).scalar_one_or_none()
        if watched: ai_rows.append(watched)
    for row in ai_rows:
        if row.state in ('queued','running'): label,tone='AI analysis in progress','working'
        elif row.state=='complete': label,tone='AI analysis complete','ready'
        elif row.state=='cancelled': label,tone='AI analysis cancelled','attention'
        elif row.state=='interrupted': label,tone='AI analysis interrupted','attention'
        else: label,tone='AI analysis needs attention','attention'
        items.append({'id':row.id,'kind':'local_ai','kind_label':'Local AI','target':row.filename[:160],
            'state':row.state,'label':label,'tone':tone,'revision':row.state+':'+row.updated_at.isoformat(),
            'url':url_for('ai.detail',job_id=row.id)})
    return jsonify(owner=current_user.get_id(),active_count=active_count,items=items)


@bp.get('/intelligence/<check_id>/export')
@login_required
def export(check_id):
    row=owned(check_id)
    from .routes import download
    content={'provider':'VirusTotal','kind':row.kind,'target':row.target,'sha256':row.sha256,'state':row.state,
        'created_at':row.created_at.isoformat(),'consent_version':row.consent_version,'result':row.result,
        'limitation':'Provider evidence is not a guarantee of safety.'}
    return download(json.dumps(content,indent=2).encode(),'virustotal-check-'+row.id+'.json','application/json')


@bp.post('/intelligence/<check_id>/refresh')
@login_required
def refresh(check_id):
    row=owned(check_id)
    if not check_rate('external-refresh:'+current_user.id,5,1): abort(429)
    if row.state not in ('queued','running'):
        if row.kind in ('url','file') and not row.analysis_id:
            flash('Start a new check with disclosure consent. An uncertain submission is never repeated automatically.','error')
        else:
            row.state='queued'; row.attempts=0; row.polls=0; row.available_at=utcnow()
            row.result={'status':'pending'}; row.lease_token=None; row.lease_until=None
            db.session.commit()
    return redirect(url_for('intel.detail',check_id=check_id))


@bp.post('/intelligence/<check_id>/delete')
@login_required
def delete(check_id):
    row=owned(check_id); db.session.delete(row)
    audit(current_user.id,'External check deleted locally'); db.session.commit()
    flash('Local record deleted. This does not delete data already submitted to VirusTotal.','success')
    return redirect(url_for('intel.history'))
