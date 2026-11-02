"""Bounded API subprocess; no application secrets inherited or payload files created."""
import base64
import json
from pathlib import Path
import sys
import types
package=types.ModuleType('sentinel'); package.__path__=[str(Path(__file__).resolve().parent)]
sys.modules['sentinel']=package
from sentinel.intel_provider import request_provider

if __name__=='__main__':
    try:
        payload=sys.stdin.buffer.read(29*1024*1024+1)
        if len(payload)>29*1024*1024: raise ValueError('Too large')
        args=json.loads(payload)
        content=base64.b64decode(args['file'],validate=True) if 'file' in args else None
        result=request_provider(args['operation'],args['value'],args['key'],file_bytes=content)
    except Exception:
        result={'status':'unavailable'}
    sys.stdout.write(json.dumps(result))
