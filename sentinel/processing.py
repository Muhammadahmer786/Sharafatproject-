"""Document operations over bounded pipes; keys and documents are never mounted or logged."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
import threading
from .worker_process import run_bounded
from .container_runtime import docker_command, worker_timeout

document_slots=threading.BoundedSemaphore(2)


def encode(value):
    if isinstance(value,bytes):
        return {'bytes':base64.b64encode(value).decode('ascii')}
    if isinstance(value,(tuple,list)):
        return [encode(v) for v in value]
    return value


def decode(value):
    if isinstance(value,dict) and set(value)=={'bytes'}:
        return base64.b64decode(value['bytes'],validate=True)
    if isinstance(value,list):
        return [decode(v) for v in value]
    return value


def document_operation(operation,arguments,mode='docker',image='sentinel-pe-worker:local'):
    if mode=='native':
        # Explicit demo-only setting. Production never falls back to this path.
        from .protection import protect_document,recover_document,generate_keypair,image_capacity,export_keypair
        return {'protect':protect_document,'recover':recover_document,'keys':generate_keypair,'capacity':image_capacity,'export_keys':export_keypair}[operation](*arguments)
    payload=json.dumps({'operation':operation,'arguments':encode(arguments)},separators=(',',':')).encode()
    container=None
    if mode=='docker':
        docker=docker_command()
        container='sentinel-document-'+uuid.uuid4().hex
        command=[*docker,'run','--rm','--name',container,'--pull=never','--network=none','--read-only',
                 '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=768m','--memory-swap=768m',
                 '--cpus=1','--pids-limit=32','--user=65534:65534','--log-driver=none',
                 '--tmpfs=/tmp:rw,noexec,nosuid,size=16m','-i',image,'/worker/document_worker.py']
        environment=None
    elif mode=='native-worker':
        command=[sys.executable,'-I',str(Path(__file__).with_name('document_worker.py'))]
        environment={k:v for k,v in os.environ.items() if k.upper() in ('SYSTEMROOT','WINDIR','PATH','TEMP','TMP')}
    else:
        raise ValueError('Unknown document worker mode.')
    try:
        output=run_bounded(command,payload,timeout=worker_timeout(command,60),env=environment,output_limit=32*1024*1024)
        result=json.loads(output)
        if not isinstance(result,dict):
            raise ValueError('Invalid worker response.')
        if result.get('error'):
            raise ValueError(result['error'])
        return decode(result['result'])
    except (json.JSONDecodeError,KeyError,TypeError) as exc:
        raise ValueError('Document worker returned an invalid response.') from exc
    finally:
        if container:
            try:
                subprocess.run([*docker,'rm','-f',container],capture_output=True,timeout=5,
                               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            except (OSError,subprocess.TimeoutExpired):
                pass
