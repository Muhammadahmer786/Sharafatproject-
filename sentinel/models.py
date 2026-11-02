from datetime import datetime, timezone
import uuid
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import inspect

db = SQLAlchemy()

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def uid():
    return str(uuid.uuid4())

class User(UserMixin, db.Model):
    id=db.Column(db.String(36),primary_key=True,default=uid)
    name=db.Column(db.String(80),nullable=False)
    email=db.Column(db.String(254),unique=True,nullable=False,index=True)
    password_hash=db.Column(db.String(255),nullable=False)
    role=db.Column(db.String(20),nullable=False,default="user")
    enabled=db.Column(db.Boolean,nullable=False,default=True)
    created_at=db.Column(db.DateTime,default=utcnow,nullable=False)
    security_version=db.Column(db.Integer,nullable=False,default=1)
    totp_secret=db.Column(db.Text,nullable=True)
    totp_pending=db.Column(db.Text,nullable=True)
    totp_last_step=db.Column(db.BigInteger,nullable=False,default=-1)

    def get_id(self):
        return f"{self.id}:{self.security_version}"

    @property
    def is_active(self):
        return self.enabled

    def set_password(self,password):
        self.password_hash=generate_password_hash(password,method="scrypt")
        self.revoke_sessions()

    def revoke_sessions(self):
        # SQL expression is evaluated by the database, even for a stale ORM object.
        self.security_version=User.security_version+1 if inspect(self).persistent else 1

    def check_password(self,password):
        return check_password_hash(self.password_hash,password)

class Scan(db.Model):
    id=db.Column(db.String(36),primary_key=True,default=uid)
    user_id=db.Column(db.String(36),db.ForeignKey("user.id"),nullable=False,index=True)
    filename=db.Column(db.String(180),nullable=False)
    sha256=db.Column(db.String(64),nullable=False,index=True)
    size=db.Column(db.Integer,nullable=False)
    static=db.Column(db.JSON,nullable=False)
    reputation=db.Column(db.JSON,nullable=False,default=lambda:{"status":"not_requested"})
    reviewed_data=db.Column(db.JSON(none_as_null=True),nullable=True)
    cloud_consent=db.Column(db.Boolean,nullable=False,default=False)
    hash_consent=db.Column(db.Boolean,nullable=False,default=False)
    consent_version=db.Column(db.String(30),nullable=False,default="2026-10-v1")
    imported_by=db.Column(db.String(36),nullable=True)
    reviewed_at=db.Column(db.DateTime,nullable=True)
    created_at=db.Column(db.DateTime,nullable=False,default=utcnow,index=True)

    @property
    def status(self):
        return "Reviewed" if self.reviewed_data is not None else "Awaiting review"

    @property
    def indicator_count(self):
        return len(self.static.get("indicators",[]))

class AuditEvent(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.String(36),db.ForeignKey("user.id"),nullable=False,index=True)
    target_user_id=db.Column(db.String(36),db.ForeignKey("user.id"),nullable=True,index=True)
    action=db.Column(db.String(100),nullable=False)
    created_at=db.Column(db.DateTime,nullable=False,default=utcnow)


class AccountKey(db.Model):
    user_id=db.Column(db.String(36),db.ForeignKey('user.id'),primary_key=True)
    public_pem=db.Column(db.Text,nullable=False)
    private_pem=db.Column(db.Text,nullable=False)
    fingerprint=db.Column(db.String(64),nullable=False)
    vault_version=db.Column(db.Integer,nullable=False,default=1)
    created_at=db.Column(db.DateTime,nullable=False,default=utcnow)

class LoginAttempt(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    key=db.Column(db.String(64),nullable=False,index=True)
    created_at=db.Column(db.DateTime,nullable=False,default=utcnow)

class ProviderQuota(db.Model):
    id=db.Column(db.String(30),primary_key=True)
    next_at=db.Column(db.BigInteger,nullable=False,default=0)
    day=db.Column(db.String(10),nullable=False,default="")
    count=db.Column(db.Integer,nullable=False,default=0)

class SchemaVersion(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    version=db.Column(db.Integer,nullable=False)

class PasswordReset(db.Model):
    token_hash=db.Column(db.String(64),primary_key=True)
    user_id=db.Column(db.String(36),db.ForeignKey('user.id'),nullable=False,index=True)
    expires_at=db.Column(db.DateTime,nullable=False)

class RateBucket(db.Model):
    key=db.Column(db.String(64),primary_key=True)
    count=db.Column(db.Integer,nullable=False,default=0)
    expires_at=db.Column(db.DateTime,nullable=False,index=True)

class ReputationJob(db.Model):
    scan_id=db.Column(db.String(36),db.ForeignKey('scan.id',ondelete='CASCADE'),primary_key=True)
    status=db.Column(db.String(20),nullable=False,default='queued',index=True)
    attempts=db.Column(db.Integer,nullable=False,default=0)
    available_at=db.Column(db.DateTime,nullable=False,default=utcnow,index=True)
    lease_until=db.Column(db.DateTime,nullable=True)
    lease_token=db.Column(db.String(36),nullable=True)
    created_at=db.Column(db.DateTime,nullable=False,default=utcnow)

class ExternalCheck(db.Model):
    id=db.Column(db.String(36),primary_key=True,default=uid)
    user_id=db.Column(db.String(36),db.ForeignKey('user.id'),nullable=False,index=True)
    kind=db.Column(db.String(12),nullable=False)
    target=db.Column(db.Text,nullable=False)
    sha256=db.Column(db.String(64),nullable=True)
    size=db.Column(db.Integer,nullable=True)
    consent_version=db.Column(db.String(40),nullable=False,default='virustotal-disclosure-v1')
    result=db.Column(db.JSON,nullable=False,default=dict)
    state=db.Column(db.String(20),nullable=False,default='queued',index=True)
    analysis_id=db.Column(db.String(512),nullable=True)
    attempts=db.Column(db.Integer,nullable=False,default=0)
    polls=db.Column(db.Integer,nullable=False,default=0)
    available_at=db.Column(db.DateTime,nullable=False,default=utcnow,index=True)
    lease_until=db.Column(db.DateTime,nullable=True)
    lease_token=db.Column(db.String(36),nullable=True)
    created_at=db.Column(db.DateTime,nullable=False,default=utcnow,index=True)
    updated_at=db.Column(db.DateTime,nullable=False,default=utcnow)

    @property
    def flagged(self):
        stats=(self.result or {}).get('stats',{})
        return stats.get('malicious',0)+stats.get('suspicious',0)

class AIAnalysis(db.Model):
    id=db.Column(db.String(36),primary_key=True,default=uid)
    user_id=db.Column(db.String(36),db.ForeignKey('user.id'),nullable=False,index=True)
    filename=db.Column(db.String(180),nullable=False)
    sha256=db.Column(db.String(64),nullable=False,index=True)
    size=db.Column(db.Integer,nullable=False)
    state=db.Column(db.String(20),nullable=False,default='queued',index=True)
    stage=db.Column(db.String(30),nullable=False,default='queued')
    progress=db.Column(db.Integer,nullable=False,default=0)
    model=db.Column(db.String(200),nullable=False)
    result=db.Column(db.JSON,nullable=False,default=dict)
    error=db.Column(db.Text,nullable=True)
    created_at=db.Column(db.DateTime,nullable=False,default=utcnow,index=True)
    updated_at=db.Column(db.DateTime,nullable=False,default=utcnow,index=True)


def audit(user_id,action,target_user_id=None):
    db.session.add(AuditEvent(user_id=user_id,action=action,target_user_id=target_user_id))
