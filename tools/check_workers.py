"""Run real isolated workers with synthetic inputs; never executes uploaded binaries."""
import argparse
import hashlib
from pathlib import Path
import sys

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
from dotenv import load_dotenv
load_dotenv(root/'.env',override=False)
from sentinel.analysis import inspect_pe
from sentinel.processing import document_operation
from sentinel.openbin_local import decompile_local


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--include-openbin',action='store_true')
    args=parser.parse_args()
    sample=(root/'examples/synthetic-demo.exe').read_bytes()
    result=inspect_pe(sample,'synthetic-demo.exe',mode='docker')
    if result['sha256']!=hashlib.sha256(sample).hexdigest():
        raise ValueError('Static worker hash mismatch')
    print('PASS: Docker static inspection')
    # Keys and passphrase are disposable, generated only for this in-memory check.
    import secrets
    passphrase=secrets.token_urlsafe(32)
    public,private=document_operation('keys',[passphrase])
    export_passphrase=secrets.token_urlsafe(32)
    exported_public,exported_private=document_operation('export_keys',[private,passphrase,export_passphrase,public])
    if exported_public!=public:
        raise ValueError('Key export changed the assigned public key')
    cover=(root/'examples/cover.png').read_bytes()
    original=b'Sentinel isolated worker acceptance\x00\xff'
    protected=document_operation('protect',[original,'acceptance.bin',cover,public])
    name,recovered=document_operation('recover',[protected,private,passphrase])
    if name!='acceptance.bin' or recovered!=original:
        raise ValueError('Document worker round-trip mismatch')
    _,exported_recovery=document_operation('recover',[protected,exported_private,export_passphrase])
    if exported_recovery!=original:
        raise ValueError('Exported key recovery mismatch')
    print('PASS: Docker key generation, encrypted export and exact document recovery with both keys')
    if args.include_openbin:
        result=decompile_local(sample,'synthetic-demo.exe')
        if result['sentinel_provenance']['sha256']!=hashlib.sha256(sample).hexdigest():
            raise ValueError('OpenBin provenance mismatch')
        functions=result.get('functions',[])
        if not any(isinstance(f,dict) and f.get('decompiled') for f in functions):
            raise ValueError('OpenBin did not produce decompiled function code for the synthetic fixture')
        print(f'PASS: Offline OpenBin decompilation ({len(functions)} functions); no AI inference')


if __name__=='__main__':
    try:
        main()
    except (ValueError,OSError) as exc:
        raise SystemExit('Worker acceptance failed: '+str(exc))
