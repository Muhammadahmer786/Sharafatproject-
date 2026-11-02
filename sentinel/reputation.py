import re
import json
import time
import os
import sys
from pathlib import Path
from datetime import datetime, timezone
import requests
from .worker_process import run_bounded


def lookup_hash_bounded(sha256, api_key):
    """A hard deadline covers DNS, TLS, and slow streamed responses in a child process."""
    if not api_key:
        return {'status':'not_configured'}
    if not re.fullmatch(r'[a-f0-9]{64}',sha256):
        raise ValueError('Invalid SHA-256.')
    env={key:value for key,value in os.environ.items() if key.upper() in
         {'SYSTEMROOT','WINDIR','PATH','TEMP','TMP'}}
    try:
        output=run_bounded([sys.executable,'-I',str(Path(__file__).with_name('reputation_worker.py'))],
            json.dumps({'sha256':sha256,'api_key':api_key}).encode(),timeout=20,
            env=env,output_limit=64*1024)
        result=json.loads(output)
        if not isinstance(result,dict) or result.get('status') not in {
            'available','not_configured','unavailable','unknown','rate_limited','unauthorized'}:
            raise ValueError('Invalid provider response.')
        return result
    except (ValueError,OSError):
        return {'provider':'VirusTotal','status':'unavailable',
                'queried_at':datetime.now(timezone.utc).isoformat()}

def lookup_hash(sha256, api_key):
    result={"provider":"VirusTotal","queried_at":datetime.now(timezone.utc).isoformat()}
    if not api_key:
        return {**result,"status":"not_configured"}
    if not re.fullmatch(r"[a-f0-9]{64}",sha256):
        raise ValueError("Invalid SHA-256.")
    response=None
    try:
        response=requests.get("https://www.virustotal.com/api/v3/files/"+sha256,
                              headers={"x-apikey":api_key,"Accept":"application/json"},
                              timeout=(3,12),allow_redirects=False,stream=True)
        statuses={404:"unknown",429:"rate_limited",401:"unauthorized",403:"unauthorized"}
        if response.status_code != 200:
            return {**result,"status":statuses.get(response.status_code,"unavailable")}
        content=bytearray()
        deadline=time.monotonic()+15
        for chunk in response.iter_content(chunk_size=65536):
            content.extend(chunk)
            if len(content)>2*1024*1024 or time.monotonic()>deadline:
                return {**result,'status':'unavailable'}
        body=json.loads(content)
        attrs=body["data"]["attributes"]
        stats=attrs["last_analysis_stats"]
        allowed={'malicious','suspicious','undetected','harmless','timeout','confirmed-timeout','failure','type-unsupported'}
        if not isinstance(stats,dict) or not stats or not set(stats)<=allowed or any(type(v) is not int or not 0<=v<=10000 for v in stats.values()):
            return {**result,"status":"unavailable"}
        return {**result,"status":"available","stats":stats,"analysis_date":attrs.get("last_analysis_date"),
                "link":"https://www.virustotal.com/gui/file/"+sha256}
    except (requests.RequestException, ValueError, TypeError, KeyError):
        return {**result,"status":"unavailable"}
    finally:
        if response is not None:
            response.close()
