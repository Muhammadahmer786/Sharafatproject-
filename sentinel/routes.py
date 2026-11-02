import io
import json
import math
import re
import threading
import time
import zipfile
from datetime import timedelta
from flask import Blueprint, request, render_template, redirect, url_for, current_app, send_file, flash, abort, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from .models import db, User, Scan, AuditEvent, ProviderQuota, ReputationJob, AccountKey, audit, utcnow
from .analysis import inspect_pe, validate_findings, MAX_PE
from .protection import protect_document, recover_document, generate_keypair, image_capacity, MAX_DOCUMENT, MAX_PNG, MAX_KEY
from .reports import render_report
from .processing import document_operation, document_slots

bp=Blueprint("main",__name__)
processing_slots=document_slots
openbin_slots=threading.BoundedSemaphore(1)

@bp.before_app_request
def operation_budget():
    if request.method=='POST' and request.endpoint in {
            'main.analyze','main.protect','main.recover','main.capacity','main.keys',
            'main.retry_reputation','main.import_findings','main.openbin'} and current_user.is_authenticated:
        from .security import check_rate
        if not check_rate('processing:'+current_user.id,30,1):
            abort(429)

def process_document(operation,*arguments):
    return document_operation(operation,list(arguments),mode=current_app.config['PE_WORKER_MODE'],image=current_app.config['PE_WORKER_IMAGE'])

def owned_scan(scan_id):
    scan=db.session.execute(db.select(Scan).where(Scan.id==scan_id,Scan.user_id==current_user.id)).scalar_one_or_none()
    if not scan:
        abort(404)
    return scan

def upload(field,limit):
    item=request.files.get(field)
    if not item or not item.filename:
        raise ValueError("Please select all required files.")
    data=item.stream.read(limit+1)
    if len(data)>limit:
        raise ValueError(f"{field.replace('_',' ').capitalize()} exceeds its allowed size.")
    return item.filename,data

def download(data,name,mime):
    response=send_file(io.BytesIO(data),as_attachment=True,download_name=name,mimetype=mime,max_age=0)
    response.headers["Cache-Control"]="no-store, private"
    # A non-secret signal that the attachment is ready, not that it was saved to disk.
    if request.method=='POST' and request.endpoint in ('main.protect','main.recover'):
        token=request.form.get('download_token','')
        if re.fullmatch(r'[0-9a-f]{32}',token):
            response.set_cookie('sentinel_download_'+token,'ready',max_age=120,
                path=request.path,secure=current_app.config['SESSION_COOKIE_SECURE'],
                httponly=False,samesite='Strict')
    return response

def reserve_lookup():
    now=time.time()
    day=utcnow().strftime("%Y-%m-%d")
    quota=db.session.get(ProviderQuota,"virustotal")
    count=quota.count if quota.day==day else 0
    if quota.next_at>now or count>=500:
        return False
    old=quota.next_at
    result=db.session.execute(db.update(ProviderQuota).where(
        ProviderQuota.id=="virustotal",ProviderQuota.next_at==old
    ).values(next_at=math.ceil(now)+16,day=day,count=count+1))
    db.session.commit()
    return result.rowcount==1

def start_reputation(scan):
    if not scan.hash_consent:
        return
    if not current_app.config["VIRUSTOTAL_API_KEY"]:
        scan.reputation={"status":"not_configured"}
        db.session.commit()
        return
    from .jobs import enqueue_lookup, run_one_job
    enqueue_lookup(scan)
    app=current_app._get_current_object()
    if not app.config["ASYNC_REPUTATION"]:
        run_one_job(app)

def repair_stale_status(scan):
    if (scan.reputation or {}).get("status")=="pending":
        job=db.session.get(ReputationJob,scan.id)
        if job and job.status in ('queued','running'):
            return
        from datetime import datetime
        try:
            if datetime.fromisoformat(scan.reputation["queried_at"])<utcnow()-timedelta(minutes=2):
                scan.reputation={"status":"interrupted"}
                db.session.commit()
        except (KeyError,ValueError,TypeError):
            scan.reputation={"status":"unavailable"}
            db.session.commit()

@bp.get("/health")
def health():
    from sqlalchemy import text
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify(status='ok')
    except Exception:
        db.session.rollback()
        return jsonify(status='unavailable'),503

@bp.get('/ready')
def ready():
    from .operations import readiness
    result=readiness(current_app)
    # Public local probe exposes only status, not account or filesystem details.
    return jsonify(status=result['status']),200 if result['status']=='ready' else 503

@bp.get("/")
@login_required
def dashboard():
    from .operations import worker_available
    worker_ready,_=worker_available(current_app)
    from .models import ExternalCheck
    external_total=db.session.scalar(db.select(db.func.count()).select_from(ExternalCheck).where(ExternalCheck.user_id==current_user.id))
    scans=db.session.execute(db.select(Scan).where(Scan.user_id==current_user.id).order_by(Scan.created_at.desc()).limit(5)).scalars().all()
    total=db.session.scalar(db.select(db.func.count()).select_from(Scan).where(Scan.user_id==current_user.id))
    reviewed=db.session.scalar(db.select(db.func.count()).select_from(Scan).where(Scan.user_id==current_user.id,Scan.reviewed_data.is_not(None)))
    count=lambda action: db.session.scalar(db.select(db.func.count()).select_from(AuditEvent).where(
        AuditEvent.user_id==current_user.id,AuditEvent.action==action))
    events=db.session.execute(db.select(AuditEvent).where(AuditEvent.user_id==current_user.id).order_by(
        AuditEvent.created_at.desc()).limit(5)).scalars().all()
    return render_template("dashboard.html",active="dashboard",title="Overview",scans=scans[:5],
                           total=total,reviewed=reviewed,worker_ready=worker_ready,external_total=external_total,
                           protected=count("Document protected"),recovered=count("Document recovered"),events=events)

@bp.route("/analyze",methods=["GET","POST"])
@login_required
def analyze():
    error=None
    if request.method=="POST":
        try:
            name,data=upload("file",MAX_PE)
            if not processing_slots.acquire(blocking=False):
                abort(429)
            try:
                result=inspect_pe(data,name,mode=current_app.config['PE_WORKER_MODE'],image=current_app.config['PE_WORKER_IMAGE'])
            finally:
                processing_slots.release()
            scan=Scan(user_id=current_user.id,filename=secure_filename(name)[:180] or "sample.exe",
                      sha256=result["sha256"],size=result["size"],static=result,
                      cloud_consent=request.form.get("cloud_consent")=="on",
                      hash_consent=request.form.get("hash_consent")=="on")
            db.session.add(scan)
            audit(current_user.id,"File statically inspected")
            db.session.commit()
            start_reputation(scan)
            return redirect(url_for("main.scan_detail",scan_id=scan.id))
        except ValueError as exc:
            error=str(exc)
    return render_template("analyze.html",active="analyze",title="Analyze a file",error=error),400 if error else 200

@bp.get("/scans/<scan_id>")
@login_required
def scan_detail(scan_id):
    scan=owned_scan(scan_id)
    repair_stale_status(scan)
    return render_template("scan.html",active="history",title="Scan details",scan=scan)


@bp.route('/openbin',methods=['GET','POST'])
@login_required
def openbin():
    from .openbin_local import decompile_local
    from .operations import image_available
    error=None
    if request.method=='POST':
        try:
            name,data=upload('file',MAX_PE)
            if not openbin_slots.acquire(blocking=False):
                abort(429)
            try:
                result=decompile_local(data,name)
            finally:
                openbin_slots.release()
            audit(current_user.id,'Local OpenBin decompilation completed')
            db.session.commit()
            import hashlib
            return download(json.dumps(result,ensure_ascii=True).encode('utf-8'),
                            'openbin-'+hashlib.sha256(data).hexdigest()[:12]+'.json','application/json')
        except ValueError as exc:
            error=str(exc)
    available,detail=image_available('sentinel-openbin-worker:local') if request.method=='GET' else (False,'Retry after checking the local worker.')
    return render_template('openbin.html',active='openbin',title='Local OpenBin',error=error,
                           worker_ready=available,worker_detail=detail),400 if error else 200

@bp.get("/scans/<scan_id>/status")
@login_required
def scan_status(scan_id):
    scan=owned_scan(scan_id)
    repair_stale_status(scan)
    return jsonify(status=scan.reputation.get("status"),reviewed=scan.reviewed_data is not None)

@bp.post("/scans/<scan_id>/reputation")
@login_required
def retry_reputation(scan_id):
    scan=owned_scan(scan_id)
    if request.form.get("hash_consent")!="on":
        flash("Confirm the hash lookup consent before requesting reputation data.","error")
    else:
        scan.hash_consent=True
        audit(current_user.id,"Reputation lookup requested")
        db.session.commit()
        start_reputation(scan)
    return redirect(url_for("main.scan_detail",scan_id=scan.id))

@bp.post("/scans/<scan_id>/findings")
@login_required
def import_findings(scan_id):
    scan=owned_scan(scan_id)
    try:
        if request.form.get("reviewed")!="on":
            raise ValueError("Confirm that you checked the findings against code evidence.")
        _,data=upload("findings",512*1024)
        payload=json.loads(data)
        findings=validate_findings(payload,scan.sha256)
        if findings['processing_location']=='cloud' and not scan.cloud_consent:
            raise ValueError('Cloud-processed findings require prior external-code consent. Local-only findings do not.')
        scan.reviewed_data=findings
        scan.imported_by=current_user.id
        scan.reviewed_at=utcnow()
        audit(current_user.id,"Supervised findings imported")
        db.session.commit()
        flash("Reviewed findings imported and linked to this scan.","success")
        return redirect(url_for("main.scan_detail",scan_id=scan.id))
    except (ValueError,UnicodeDecodeError) as exc:
        return render_template("scan.html",active="history",title="Scan details",scan=scan,
                               error=str(exc) if not isinstance(exc,json.JSONDecodeError) else "Choose a valid UTF-8 JSON findings file."),400

@bp.get("/scans/<scan_id>/report")
@login_required
def scan_report(scan_id):
    scan=owned_scan(scan_id)
    return download(render_report(scan),"sentinel-"+scan.sha256[:12]+".pdf","application/pdf")

@bp.post("/scans/<scan_id>/delete")
@login_required
def delete_scan(scan_id):
    scan=owned_scan(scan_id)
    db.session.delete(scan)
    audit(current_user.id,"Scan deleted")
    db.session.commit()
    flash("Scan and its saved findings deleted.","success")
    return redirect(url_for("main.history"))

@bp.get("/history")
@login_required
def history():
    q=request.args.get("q","").strip()[:180]
    status=request.args.get("status","all")
    query=db.select(Scan).where(Scan.user_id==current_user.id)
    if q:
        query=query.where(db.or_(Scan.filename.contains(q,autoescape=True),Scan.sha256.contains(q,autoescape=True)))
    if status=="reviewed":
        query=query.where(Scan.reviewed_data.is_not(None))
    elif status=="pending":
        query=query.where(Scan.reviewed_data.is_(None))
    page=max(1,request.args.get("page",1,type=int) or 1)
    pagination=db.paginate(query.order_by(Scan.created_at.desc()),page=page,per_page=12,error_out=False)
    return render_template("history.html",active="history",title="Scan history",pagination=pagination,q=q,status=status)

@bp.route("/protect",methods=["GET","POST"])
@login_required
def protect():
    error=None
    if request.method=="POST":
        try:
            if request.form.get("trusted_server")!="on":
                raise ValueError("Acknowledge the trusted-server processing notice before continuing.")
            name,document=upload("document",MAX_DOCUMENT)
            _,png=upload("image",MAX_PNG)
            source=request.form.get('key_source') or ('upload' if request.files.get('public_key') else 'assigned')
            if source=='assigned':
                from .account_keys import ensure_account_key
                public=ensure_account_key(current_user).public_pem.encode('ascii')
                # Persist any first assignment before starting another slow worker.
                db.session.commit()
            elif source=='upload':
                _,public=upload("public_key",MAX_KEY)
            else:
                raise ValueError('Choose your assigned key or an uploaded recipient key.')
            if not processing_slots.acquire(blocking=False):
                abort(429)
            try:
                output=process_document('protect',document,name,png,public)
            finally:
                processing_slots.release()
            audit(current_user.id,"Document protected")
            db.session.commit()
            return download(output,"sentinel-protected.png","image/png")
        except ValueError as exc:
            error=str(exc)
    return render_template("protection.html",mode="protect",active="protect",title="Protect a document",error=error),400 if error else 200

@bp.route("/recover",methods=["GET","POST"])
@login_required
def recover():
    error=None
    if request.method=="POST":
        try:
            if request.form.get("trusted_server")!="on":
                raise ValueError("Acknowledge the trusted-server processing notice before continuing.")
            _,png=upload("image",MAX_PNG)
            source=request.form.get('key_source') or ('upload' if request.files.get('private_key') else 'assigned')
            if source=='assigned':
                from .auth import confirm_account
                if not confirm_account():
                    db.session.rollback()
                    return render_template('protection.html',mode='recover',active='recover',title='Recover a document',
                        error='Verify your current account password and authenticator code to use the assigned private key.'),403
                # Consume successful MFA in a short transaction, before any worker.
                db.session.commit()
                from .account_keys import ensure_account_key, vault_passphrase
                private=ensure_account_key(current_user).private_pem.encode('ascii')
                db.session.commit()
                passphrase=vault_passphrase(current_user.id)
            elif source=='upload':
                _,private=upload("private_key",MAX_KEY)
                passphrase=request.form.get('passphrase','')
            else:
                raise ValueError('Choose your assigned key or an uploaded private key.')
            if not processing_slots.acquire(blocking=False):
                abort(429)
            try:
                name,document=process_document('recover',png,private,passphrase)
            finally:
                processing_slots.release()
            audit(current_user.id,"Document recovered")
            db.session.commit()
            return download(document,name,"application/octet-stream")
        except ValueError as exc:
            error=str(exc)
    return render_template("protection.html",mode="recover",active="recover",title="Recover a document",error=error),400 if error else 200

@bp.post("/image-capacity")
@login_required
def capacity():
    try:
        _,png=upload("image",MAX_PNG)
        if not processing_slots.acquire(blocking=False):
            abort(429)
        try:
            result=process_document('capacity',png)
        finally:
            processing_slots.release()
        return jsonify(result)
    except ValueError as exc:
        return jsonify(error=str(exc)),400

@bp.route("/keys",methods=["GET","POST"])
@login_required
def keys():
    error=None
    key=db.session.get(AccountKey,current_user.id)
    if request.method=="POST":
        try:
            action=request.form.get('action','download')
            if action not in ('view','download'):
                raise ValueError('Choose to show your private key or download a key backup.')
            if request.form.get("trusted_server")!="on":
                raise ValueError("Acknowledge temporary server-side key access.")
            from .auth import confirm_account
            if not confirm_account():
                db.session.rollback()
                return render_template('keys.html',active='keys',title='Encryption keys',key=key,
                    error='Verify your current account password and authenticator code to view or export your private key.'),403
            db.session.commit()
            from .account_keys import ensure_account_key, vault_passphrase
            key=ensure_account_key(current_user)
            db.session.commit()
            if not processing_slots.acquire(blocking=False):
                abort(429)
            try:
                public,private=process_document('export_keys',key.private_pem.encode('ascii'),vault_passphrase(current_user.id),
                    request.form.get("passphrase",""),key.public_pem.encode('ascii'))
            finally:
                processing_slots.release()
            if action=='view':
                audit(current_user.id,'Assigned private key viewed')
                db.session.commit()
                return render_template('keys.html',active='keys',title='Encryption keys',key=key,
                    private_pem=private.decode('ascii'))
            buffer=io.BytesIO()
            with zipfile.ZipFile(buffer,"w",zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("recipient-public.pem",public)
                archive.writestr("recipient-private.pem",private)
                archive.writestr("READ-ME.txt","These are copies of your assigned Sentinel Lab keys. Share only recipient-public.pem. Keep recipient-private.pem and its export passphrase separately backed up. The local server retains your assigned private key encrypted in its vault; its original application secret is required to unlock that copy.")
            audit(current_user.id,"Assigned key pair exported")
            db.session.commit()
            return download(buffer.getvalue(),"sentinel-keypair.zip","application/zip")
        except ValueError as exc:
            error=str(exc)
    return render_template("keys.html",active="keys",title="Encryption keys",error=error,key=key),400 if error else 200


@bp.get('/keys/public')
@login_required
def public_key():
    key=db.session.get(AccountKey,current_user.id)
    if key is None:
        abort(404)
    return download(key.public_pem.encode('ascii'),'recipient-public.pem','application/x-pem-file')

@bp.get("/settings")
@login_required
def settings():
    from .operations import worker_available, image_available
    worker_ready,worker_message=worker_available(current_app)
    openbin_ready,openbin_message=image_available('sentinel-openbin-worker:local')
    return render_template("settings.html",active="settings",title="Workspace settings",
                           worker_ready=worker_ready,worker_message=worker_message,
                           openbin_ready=openbin_ready,openbin_message=openbin_message,
                           database="MySQL" if current_app.config["SQLALCHEMY_DATABASE_URI"].startswith("mysql") else "SQLite")

@bp.get("/guide")
@login_required
def guide():
    return render_template("guide.html",active="guide",title="Quick start guide")
