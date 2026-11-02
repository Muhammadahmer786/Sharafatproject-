import io
import pytest


def test_deployment_refuses_native_fallback_when_docker_is_missing(user,app,pe_bytes,monkeypatch):
    app.config['PE_WORKER_MODE']='docker'
    monkeypatch.setattr('shutil.which',lambda command: None)
    response=user.post('/analyze',data={'file':(io.BytesIO(pe_bytes),'test.exe')})
    assert response.status_code==400
    assert b'Docker' in response.data
    from sentinel.models import db,Scan
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(Scan))==0


def test_docker_worker_has_no_network_mounts_or_privileges(pe_bytes,monkeypatch):
    import json
    from sentinel.analysis import inspect_pe
    from sentinel.worker_process import run_bounded
    seen=[]
    monkeypatch.setattr('shutil.which',lambda command: 'docker')
    def fake(command,data,**kwargs):
        seen.append(command)
        return json.dumps({'architecture':'x86','sections':[]}).encode()
    monkeypatch.setattr('sentinel.analysis.run_bounded',fake)
    monkeypatch.setattr('subprocess.run',lambda *a,**k:None)
    inspect_pe(pe_bytes,'file.exe',mode='docker')
    command=seen[0]
    for flag in ['--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=32','--pull=never']:
        assert flag in command
    assert not any('mount' in item or item=='-v' for item in command)


def test_worker_output_is_bounded_and_timeout_enforced():
    import sys
    from sentinel.worker_process import run_bounded
    with pytest.raises(ValueError,match='limit'):
        run_bounded([sys.executable,'-c','print("x" * 2000000)'],b'',timeout=5)
    with pytest.raises(ValueError,match='timed out'):
        run_bounded([sys.executable,'-c','import time; time.sleep(10)'],b'',timeout=0.1)


def test_document_worker_round_trip_has_no_files(png,keys,tmp_path):
    from sentinel.processing import document_operation
    protected=document_operation('protect',[b'private document','paper.txt',png,keys[0]],mode='native-worker')
    name,data=document_operation('recover',[protected,keys[1],''],mode='native-worker')
    assert name=='paper.txt' and data==b'private document'
    assert list(tmp_path.iterdir())==[]


def test_png_processing_also_refuses_unsafe_fallback(user,app,png,keys,monkeypatch):
    app.config['PE_WORKER_MODE']='docker'
    monkeypatch.setattr('shutil.which',lambda command: None)
    response=user.post('/protect',data={'trusted_server':'on','document':(io.BytesIO(b'private'),'x.txt'),
        'image':(io.BytesIO(png),'x.png'),'public_key':(io.BytesIO(keys[0]),'key.pem')})
    assert response.status_code==400
    assert b'Docker' in response.data
