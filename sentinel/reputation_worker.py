"""Provider credentials travel over stdin, never argv, files, or inherited environment."""
import json
from pathlib import Path
import sys
import types

# Load only the HTTP adapter, not Flask or application configuration.
package=types.ModuleType('sentinel')
package.__path__=[str(Path(__file__).resolve().parent)]
sys.modules['sentinel']=package
from sentinel.reputation import lookup_hash

if __name__=='__main__':
    try:
        payload=sys.stdin.buffer.read(16385)
        if len(payload)>16384:
            raise ValueError('Input too large')
        request=json.loads(payload)
        result=lookup_hash(request['sha256'],request['api_key'])
    except Exception:
        result={'status':'unavailable'}
    sys.stdout.write(json.dumps(result))
