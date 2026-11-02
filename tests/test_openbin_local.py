import json
import pytest


def test_local_openbin_never_uses_cloud_cli_and_binds_result_to_input(pe_bytes,monkeypatch):
    import hashlib
    from sentinel.openbin_local import decompile_local
    commands=[]
    monkeypatch.setattr('shutil.which',lambda name:'docker')
    def fake(command,data,**kwargs):
        commands.append(command)
        assert data==pe_bytes
        return json.dumps({'metadata':{},'functions':[]}).encode()
    monkeypatch.setattr('sentinel.openbin_local.run_bounded',fake)
    monkeypatch.setattr('subprocess.run',lambda *a,**k:None)
    result=decompile_local(pe_bytes,'example.exe')
    assert result['sentinel_provenance']['sha256']==hashlib.sha256(pe_bytes).hexdigest()
    assert result['sentinel_provenance']['processing_location']=='local'
    assert result['sentinel_provenance']['ai_model_ran'] is False
    assert '--network=none' in commands[0] and '--read-only' in commands[0]
    assert not any('openbin.exe' in arg or 'https://' in arg or 'mount' in arg for arg in commands[0])


def test_local_evidence_does_not_require_cloud_consent(user,pe_bytes):
    import hashlib,io
    location=user.post('/analyze',data={'file':(io.BytesIO(pe_bytes),'sample.exe')}).location
    payload={'schema_version':1,'sha256':hashlib.sha256(pe_bytes).hexdigest(),'tool':'OpenBin',
        'processing_location':'local','model':'Manual review; no AI model','reviewer':'Local reviewer',
        'findings':[{'title':'Entry point','severity':'info','detail':'Review only','evidence':'Address 0x401000'}]}
    result=user.post(location+'/findings',data={'reviewed':'on','findings':(io.BytesIO(json.dumps(payload).encode()),'findings.json')})
    assert result.status_code==302
    assert b'Local reviewer' in user.get(location).data
