import io
import os
from pathlib import Path
import secrets
import time
import ipaddress
from datetime import timedelta
from flask import Flask, Request, render_template, request, abort, session, redirect, url_for, flash
from flask_login import LoginManager, current_user, logout_user
from flask_wtf.csrf import CSRFProtect, CSRFError
from .models import db, User, ProviderQuota, utcnow

login_manager=LoginManager()
csrf=CSRFProtect()

class MemoryRequest(Request):
    """Prevent multipart uploads, including private key material, being spooled to disk."""
    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        return io.BytesIO()

def create_app(config=None):
    settings=config or {}
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1]/'.env', override=False)
    instance=Path(settings.get("INSTANCE_PATH",Path(__file__).resolve().parents[1]/"instance"))
    instance.mkdir(parents=True,exist_ok=True)
    app=Flask(__name__,instance_path=str(instance))
    app.request_class=MemoryRequest
    secret=settings.get("SECRET_KEY") or os.getenv("SECRET_KEY")
    if not secret:
        path=instance/".secret"
        try:
            with path.open("x",encoding="ascii") as f:
                f.write(secrets.token_hex(32))
            if os.name!="nt":
                path.chmod(0o600)
        except FileExistsError:
            pass
        secret=path.read_text(encoding="ascii").strip()
    app.config.update(
        SECRET_KEY=secret, SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL","sqlite:///"+str(instance/"sentinel.db")),
        # 5 MiB document + 22 MiB PNG, with space for keys and multipart framing.
        SQLALCHEMY_TRACK_MODIFICATIONS=False, MAX_CONTENT_LENGTH=28*1024*1024,
        # Must exceed the parser's 64 KiB reads plus retained boundary bytes.
        MAX_FORM_MEMORY_SIZE=128*1024, MAX_FORM_PARTS=20, SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE")=="1",
        SESSION_COOKIE_NAME='sentinel_session',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8), WTF_CSRF_TIME_LIMIT=8*60*60,
        VIRUSTOTAL_API_KEY=os.getenv("VIRUSTOTAL_API_KEY",""), ASYNC_REPUTATION=True,
        ALLOW_REGISTRATION=os.getenv('ALLOW_REGISTRATION')=='1', REQUIRE_ADMIN_MFA=True,
        TRUSTED_HOSTS=['localhost', '127.0.0.1', '[::1]'],
        PE_WORKER_MODE=os.getenv('PE_WORKER_MODE', 'docker'),
        PE_WORKER_IMAGE=os.getenv('PE_WORKER_IMAGE', 'sentinel-pe-worker:local'),
        OPENBIN_WORKER_IMAGE=os.getenv('OPENBIN_WORKER_IMAGE', 'sentinel-openbin-worker:local'),
        LOCAL_AI_URL=os.getenv('LOCAL_AI_URL', 'http://127.0.0.1:11434'),
        LOCAL_AI_MODEL=os.getenv('LOCAL_AI_MODEL', 'qwen3:4b'),
        LOCAL_AI_RUNTIME_DIR=os.getenv('LOCAL_AI_RUNTIME_DIR', 'D:/SentinelRuntime/ai'),
        LOCAL_AI_TIMEOUT=int(os.getenv('LOCAL_AI_TIMEOUT', '600')),
        LOCAL_ONLY=True,
    )
    app.config.update(settings)
    epoch_path=instance/'.session-epoch'
    try:
        with epoch_path.open('x',encoding='ascii') as f:
            f.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    app.config['SESSION_EPOCH']=epoch_path.read_text(encoding='ascii').strip()
    if not app.testing and len(app.secret_key)<32:
        raise RuntimeError('SECRET_KEY must contain at least 32 random characters.')
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view="auth.login"
    csrf.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        try:
            identity, version = user_id.rsplit(':', 1)
            user=db.session.get(User,identity)
            return user if user and user.enabled and user.security_version==int(version) else None
        except (ValueError, AttributeError):
            return None

    @app.before_request
    def local_access_and_session_lifetime():
        if app.config['LOCAL_ONLY']:
            try:
                if not ipaddress.ip_address(request.remote_addr or '').is_loopback:
                    abort(403)
            except ValueError:
                abort(403)
        if '_user_id' in session:
            now=time.time()
            if (now-session.get('login_at', 0)>8*3600 or now-session.get('last_seen', 0)>30*60
                    or session.get('epoch')!=app.config['SESSION_EPOCH']):
                logout_user()
                session.clear()
            elif request.endpoint not in ('intel.updates','ai.status'):
                session['last_seen']=int(now)

    from .auth import bp as auth_bp
    from .routes import bp as main_bp
    from .intelligence import bp as intel_bp
    from .admin import bp as admin_bp
    from .ai import bp as ai_bp
    from .ai_jobs import AIJobManager
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(intel_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(ai_bp)
    app.extensions['local_ai_jobs']=AIJobManager(app)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"]="nosniff"
        response.headers["X-Frame-Options"]="DENY"
        response.headers["Referrer-Policy"]="no-referrer"
        response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        if response.mimetype!="text/css" and not response.mimetype.startswith("image/") or current_user.is_authenticated:
            response.headers["Cache-Control"]="no-store, private"
        return response

    @app.context_processor
    def shared():
        from .protection import MAX_DOCUMENT, MAX_PNG, MAX_KEY
        return {"now":utcnow(), "vt_configured":bool(app.config["VIRUSTOTAL_API_KEY"]),
                "upload_limits":{"document":MAX_DOCUMENT,"image":MAX_PNG,"key":MAX_KEY,
                                 "request":app.config['MAX_CONTENT_LENGTH']}}

    @app.template_filter("filesize")
    def filesize(value):
        if value>=1024*1024:
            return f"{value/(1024*1024):.1f} MB"
        return f"{value/1024:.1f} KB"

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        return render_template("error.html",code=400,title="Your form has expired",
                               message="Refresh the page and try again. Your session token could not be verified."),400

    @app.errorhandler(413)
    def upload_too_large(error):
        db.session.rollback()
        total=app.config['MAX_CONTENT_LENGTH']//(1024*1024)
        if request.endpoint in ('main.protect','main.recover') and current_user.is_authenticated:
            mode='protect' if request.endpoint=='main.protect' else 'recover'
            message=("The upload or form exceeds an allowed limit. "
                     "Use a document up to 5 MiB, a PNG up to 22 MiB, and PEM keys up to 16 KiB. "
                     f"The complete request must fit within {total} MiB. Please select your files again.")
            return render_template('protection.html',mode=mode,active=mode,
                title='Protect a document' if mode=='protect' else 'Recover a document',error=message),413
        return render_template('error.html',code=413,title='Upload too large',
            message=f'The upload or form exceeds an allowed limit. The complete request must fit within {total} MiB; individual file and form limits also apply.'),413

    for code,title,message in [
        (403,"Access restricted","Your account does not have permission for this action."),
        (404,"Page not found","This page or record is not available to your account."),
        (429,"A little too fast","Please wait before trying again."),
        (500,"Something went wrong","The operation could not be completed. Try again or contact your project administrator."),
    ]:
        def handler(error,code=code,title=title,message=message):
            db.session.rollback()
            return render_template("error.html",code=code,title=title,message=message),code
        app.register_error_handler(code,handler)

    with app.app_context():
        from .database import configure_database, ensure_schema
        configure_database()
        ensure_schema(app)
    return app
