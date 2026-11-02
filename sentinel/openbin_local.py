"""Offline adapter for the official OpenBin Ghidra worker, never its upload CLI."""
import hashlib
import json
from pathlib import Path
import subprocess
import uuid
from .worker_process import run_bounded
from .container_runtime import docker_command, worker_timeout


def decompile_local(data,filename,image='sentinel-openbin-worker:local',job_id=None):
    if not 256<=len(data)<=10*1024*1024 or not data.startswith(b'MZ') or Path(filename).suffix.lower() not in ('.exe','.dll'):
        raise ValueError('Choose an authorized Windows PE EXE/DLL no larger than 10 MiB.')
    docker=docker_command()
    name='sentinel-openbin-'+(uuid.UUID(job_id).hex if job_id else uuid.uuid4().hex)
    command=[*docker,'run','--rm','--name',name,'--pull=never','--network=none','--read-only',
             '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=2g','--memory-swap=2g',
             '--cpus=2','--pids-limit=128','--user=65534:65534','--log-driver=none',
             '--tmpfs=/tmp:rw,nosuid,size=1g','-i',image]
    try:
        result=json.loads(run_bounded(command,data,timeout=worker_timeout(docker,330),output_limit=16*1024*1024))
        if not isinstance(result,dict) or 'error' in result:
            raise ValueError('The local OpenBin worker could not decompile this file.')
        result['sentinel_provenance']={'sha256':hashlib.sha256(data).hexdigest(),
            'processing_location':'local','tool':'OpenBin Ghidra worker','ai_model_ran':False}
        return result
    except (json.JSONDecodeError,UnicodeDecodeError) as exc:
        raise ValueError('The local OpenBin worker returned an invalid result.') from exc
    finally:
        try:
            subprocess.run([*docker,'rm','-f',name],capture_output=True,timeout=5,
                           creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        except (OSError,subprocess.TimeoutExpired):
            pass
