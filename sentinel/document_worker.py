"""Standalone worker entrypoint. Its only inputs and outputs are bounded pipes."""
import base64
import json
from pathlib import Path
import sys

# -I excludes the script directory. Add only this immutable worker code directory.
sys.path.insert(0,str(Path(__file__).resolve().parent))
from protection import protect_document,recover_document,generate_keypair,image_capacity,export_keypair


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


def main():
    try:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU,(45,45))
        except ImportError:
            pass
        raw=sys.stdin.buffer.read(48*1024*1024+1)
        if len(raw)>48*1024*1024:
            raise ValueError('Worker input exceeds its limit.')
        payload=json.loads(raw)
        functions={'protect':protect_document,'recover':recover_document,'keys':generate_keypair,'capacity':image_capacity,'export_keys':export_keypair}
        function=functions[payload['operation']]
        result={'result':encode(function(*decode(payload['arguments'])))}
    except ValueError as exc:
        result={'error':str(exc)[:400]}
    except Exception:
        result={'error':'Document processing failed. Check the supplied files.'}
    sys.stdout.write(json.dumps(result,separators=(',',':')))


if __name__=='__main__':
    main()
