"""Static parser orchestration and a strictly validated supervised findings format."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import os
import uuid
from .worker_process import run_bounded
from .container_runtime import docker_command, worker_timeout

MAX_PE = 10 * 1024 * 1024

def inspect_pe(data, filename, mode='native', image='sentinel-pe-worker:local', job_id=None):
    if not data or len(data) > MAX_PE:
        raise ValueError("Choose a PE file between 1 byte and 10 MiB.")
    if Path(filename).suffix.lower() not in (".exe", ".dll"):
        raise ValueError("Only native Windows .exe and .dll PE files are supported.")
    if mode=='docker':
        docker=docker_command()
        container='sentinel-pe-'+(uuid.UUID(job_id).hex if job_id else uuid.uuid4().hex)
        command=[*docker,'run','--rm','--name',container,'--pull=never','--network=none','--read-only',
                 '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=384m','--memory-swap=384m',
                 '--cpus=1','--pids-limit=32','--user=65534:65534','--log-driver=none',
                 '--tmpfs=/tmp:rw,noexec,nosuid,size=16m','-i',image]
        try:
            output=run_bounded(command,data,timeout=worker_timeout(docker,20))
        finally:
            try:
                subprocess.run([*docker,'rm','-f',container],capture_output=True,timeout=5,
                               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            except (OSError,subprocess.TimeoutExpired):
                pass
    elif mode=='native':
        # Explicit demonstration mode; deliberately excludes application secrets from the child environment.
        environment={k:v for k,v in os.environ.items() if k.upper() in ('SYSTEMROOT','WINDIR','PATH','TEMP','TMP')}
        output=run_bounded([sys.executable,'-I',str(Path(__file__).with_name('pe_worker.py'))],data,env=environment)
    else:
        raise ValueError('Unknown parser mode. Configure the local Docker worker.')
    try:
        payload = json.loads(output)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Static inspection returned an invalid result.") from exc
    if not isinstance(payload,dict):
        raise ValueError('Static inspection returned an invalid result.')
    if payload.get("error"):
        raise ValueError(payload["error"])
    payload["sha256"] = hashlib.sha256(data).hexdigest()
    payload["size"] = len(data)
    payload["method"] = "Static PE inspection"
    payload['isolation'] = 'Docker: network disabled, read-only, resource limited' if mode=='docker' else 'Native demonstration process; not a security sandbox'
    return payload

def _text(value, label, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{label} must be nonempty text, at most {limit} characters.")
    if any(ord(c) < 32 and c not in "\n\t\r" for c in value):
        raise ValueError(f"{label} contains unsupported control characters.")
    return value.strip()

def validate_findings(payload, sha256):
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("Use the version 1 supervised findings format.")
    if not isinstance(payload.get("sha256"), str) or payload["sha256"].lower() != sha256:
        raise ValueError("The findings hash does not match this scan.")
    if payload.get("tool") not in ("OpenBin", "BINNY"):
        raise ValueError("The source tool must be OpenBin or BINNY.")
    location=payload.get('processing_location','cloud')
    if location not in ('local','cloud'):
        raise ValueError('Processing location must be local or cloud.')
    findings = payload.get("findings")
    if not isinstance(findings,list) or len(findings) > 50:
        raise ValueError("Provide a list of at most 50 findings.")
    clean = []
    for item in findings:
        if not isinstance(item,dict) or item.get("severity") not in ("info","low","medium","high"):
            raise ValueError("Each finding needs an allowed severity.")
        clean.append({"title":_text(item.get("title"),"Title",160),
                      "severity":item["severity"], "detail":_text(item.get("detail"),"Detail",3000),
                      "evidence":_text(item.get("evidence"),"Code evidence",3000)})
    return {"schema_version":1, "sha256":sha256,"tool":payload["tool"],
            'processing_location':location,
            "model":_text(payload.get("model"),"Model",200),
            "reviewer":_text(payload.get("reviewer"),"Reviewer",100),"findings":clean}
