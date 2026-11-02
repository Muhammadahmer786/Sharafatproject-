"""VirusTotal v3 contracts. Targets are sent only to fixed provider endpoints."""
import base64
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, urlunsplit, quote
import requests
from .worker_process import run_bounded

MAX_EXTERNAL_FILE=20*1024*1024
CATEGORIES={'malicious','suspicious','undetected','harmless','timeout','confirmed-timeout','failure','type-unsupported'}
CATEGORY_ALIASES={'confirmed_timeout':'confirmed-timeout','type_unsupported':'type-unsupported'}
STATUSES={'available','submitted','pending','unknown','unauthorized','rate_limited','unavailable','rejected','not_configured'}


def validate_target(kind,value):
    if not isinstance(value,str) or len(value)>2048 or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError('Enter a valid target of at most 2,048 characters.')
    value=value.strip()
    if kind=='hash':
        if not re.fullmatch(r'(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})',value):
            raise ValueError('Enter a valid MD5, SHA-1 or SHA-256 file hash.')
        return value.lower()
    if kind=='ip':
        try: address=ipaddress.ip_address(value)
        except ValueError: raise ValueError('Enter a public IPv4 or IPv6 address.') from None
        if not address.is_global or address.is_multicast or '%' in value:
            raise ValueError('Only public IPv4 or IPv6 addresses can be checked.')
        return str(address)
    if kind=='url':
        if '\\' in value or any(c.isspace() for c in value):
            raise ValueError('URLs cannot contain whitespace or backslashes.')
        try:
            parts=urlsplit(value)
            host=parts.hostname
            port=parts.port
            if parts.scheme.lower() not in ('http','https') or not host or parts.username is not None or parts.password is not None:
                raise ValueError()
            host=host.rstrip('.').encode('idna').decode('ascii').lower()
            try: address=ipaddress.ip_address(host)
            except ValueError:
                if len(host)>253 or '.' not in host or host.endswith(('.local','.internal','.localhost','.test','.invalid')) or not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',host):
                    raise ValueError()
                if any(len(label)>63 or label.startswith('-') or label.endswith('-') for label in host.split('.')):
                    raise ValueError()
                # Reject numeric aliases such as 127.1; the app never resolves/fetches targets.
                if host.split('.')[-1].isdigit(): raise ValueError()
            else:
                validate_target('ip',str(address))
                host='['+host+']' if address.version==6 else host
            if port is not None and not 1<=port<=65535: raise ValueError()
            normalized=urlunsplit((parts.scheme.lower(),host+(':'+str(port) if port else ''),parts.path or '/',parts.query,''))
            if len(normalized)>2048: raise ValueError()
            return normalized
        except (ValueError,UnicodeError):
            raise ValueError('Enter a public HTTP(S) URL without embedded credentials.') from None
    raise ValueError('Unsupported check type.')


def analysis_id(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,510}={0,2}',value):
        raise ValueError('Invalid analysis identifier.')
    return value


def normalize_result(body,operation):
    data=body['data']
    if operation in ('url','file'):
        return {'status':'submitted','analysis_id':analysis_id(data['id'])}
    attrs=data['attributes']
    if operation=='analysis' and attrs.get('status') in ('queued','in-progress'):
        return {'status':'pending'}
    if operation=='analysis' and attrs.get('status')!='completed':
        return {'status':'unavailable'}
    stats=attrs.get('stats') if operation=='analysis' else attrs.get('last_analysis_stats')
    if isinstance(stats,dict):
        normalized={CATEGORY_ALIASES.get(k,k):v for k,v in stats.items()}
        if len(normalized)!=len(stats): return {'status':'unavailable'}
        stats=normalized
    if not isinstance(stats,dict) or not stats or not set(stats)<=CATEGORIES or any(type(v) is not int or not 0<=v<=10000 for v in stats.values()):
        return {'status':'unavailable'}
    engines=attrs.get('results' if operation=='analysis' else 'last_analysis_results',{})
    rows=[]
    if isinstance(engines,dict):
        for name,info in list(engines.items())[:200]:
            if not isinstance(info,dict): continue
            category=info.get('category')
            if isinstance(category,str): category=CATEGORY_ALIASES.get(category,category)
            if not isinstance(category,str) or category not in CATEGORIES: category='failure'
            fallback='No detection reported' if category in ('harmless','undetected') else 'No result reported'
            rows.append({'name':str(name)[:100],'category':category,
                         'result':str(info.get('result') or fallback)[:300]})
    result={'status':'available','stats':stats,'engines':sorted(rows,key=lambda x:(x['category'] not in ('malicious','suspicious'),x['name'].lower()))}
    for key in ('country','as_owner','meaningful_name','type_description','sha256'):
        if isinstance(attrs.get(key),str): result[key]=attrs[key][:200]
    date=attrs.get('date' if operation=='analysis' else 'last_analysis_date')
    if type(date) is int and 0<=date<=4102444800: result['analysis_date']=date
    return result


def request_provider(operation,value,key,file_bytes=None):
    if not key: return {'status':'not_configured'}
    base='https://www.virustotal.com/api/v3/'
    kwargs={'headers':{'x-apikey':key,'Accept':'application/json'},'timeout':(5,15),'allow_redirects':False,'stream':True}
    method='GET'
    if operation=='hash': endpoint='files/'+validate_target('hash',value)
    elif operation=='ip': endpoint='ip_addresses/'+quote(validate_target('ip',value),safe=':')
    elif operation=='url':
        method='POST'; endpoint='urls'; kwargs['data']={'url':validate_target('url',value)}
    elif operation=='analysis': endpoint='analyses/'+quote(analysis_id(value),safe='')
    elif operation=='file':
        if not isinstance(file_bytes,bytes) or not 1<=len(file_bytes)<=MAX_EXTERNAL_FILE:
            raise ValueError('Choose a non-empty file no larger than 20 MiB.')
        method='POST'; endpoint='files'
        kwargs['files']={'file':('sample.bin',io.BytesIO(file_bytes),'application/octet-stream')}
    else: raise ValueError('Unsupported provider operation.')
    response=None
    try:
        response=requests.request(method,base+endpoint,**kwargs)
        # An accepted analysis can be briefly unavailable while the provider indexes it.
        # Only poll its existing ID, within the durable twenty-poll budget.
        if operation=='analysis' and response.status_code==404:
            return {'status':'pending'}
        if response.status_code not in (200,201):
            return {'status':{404:'unknown',401:'unauthorized',403:'unauthorized',429:'rate_limited',400:'rejected',413:'rejected'}.get(response.status_code,'unavailable')}
        content=bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            content.extend(chunk)
            if len(content)>2*1024*1024: return {'status':'unavailable'}
        return normalize_result(json.loads(content),operation)
    except (requests.RequestException,ValueError,TypeError,KeyError,AttributeError):
        return {'status':'unavailable'}
    finally:
        if response is not None: response.close()


def provider_call(operation,value,key,file_bytes=None):
    if not key: return {'status':'not_configured'}
    payload={'operation':operation,'value':value,'key':key}
    if file_bytes is not None:
        if len(file_bytes)>MAX_EXTERNAL_FILE: raise ValueError('File exceeds 20 MiB.')
        payload['file']=base64.b64encode(file_bytes).decode('ascii')
    env={k:v for k,v in os.environ.items() if k.upper() in ('SYSTEMROOT','WINDIR','PATH','TEMP','TMP')}
    try:
        output=run_bounded([sys.executable,'-I',str(Path(__file__).with_name('intel_worker.py'))],
            json.dumps(payload).encode(),timeout=60 if operation=='file' else 20,env=env,output_limit=256*1024)
        result=json.loads(output)
        return result if isinstance(result,dict) and result.get('status') in STATUSES else {'status':'unavailable'}
    except (ValueError,OSError): return {'status':'unavailable'}
