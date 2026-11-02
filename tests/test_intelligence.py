import io
from datetime import timedelta
import pytest


@pytest.mark.parametrize('kind,value,expected',[
    ('hash','A'*32,'a'*32),('hash','b'*40,'b'*40),('hash','c'*64,'c'*64),
    ('ip','8.8.8.8','8.8.8.8'),('ip','2606:4700:4700::1111','2606:4700:4700::1111'),
    ('url','HTTPS://Example.com/test?q=1#fragment','https://example.com/test?q=1')])
def test_normalizes_supported_targets(kind,value,expected):
    from sentinel.intel_provider import validate_target
    assert validate_target(kind,value)==expected


@pytest.mark.parametrize('kind,value',[
    ('hash','z'*64),('hash','a'*63),('ip','127.0.0.1'),('ip','192.168.1.1'),('ip','::1'),
    ('url','file:///etc/passwd'),('url','https://user:pass@example.com/'),
    ('url','http://localhost/'),('url','http://127.0.0.1/'),('url','https://example.com\\@localhost/'),
    ('url','https://example.com/\nsecret'),('url','https://intranet.local/'),('url','https://example.com:99999/')])
def test_rejects_invalid_or_private_targets(kind,value):
    from sentinel.intel_provider import validate_target
    with pytest.raises(ValueError): validate_target(kind,value)


def test_all_checks_require_consent_and_configuration(user,app):
    app.config['VIRUSTOTAL_API_KEY']='test-key'
    response=user.post('/intelligence',data={'kind':'hash','target':'a'*64})
    assert response.status_code==400
    app.config['VIRUSTOTAL_API_KEY']=''
    response=user.post('/intelligence',data={'kind':'hash','target':'a'*64,'consent':'on'})
    assert response.status_code==400
    assert b'API key' in response.data


def create_check(user,app,kind='hash',target='a'*64):
    app.config['VIRUSTOTAL_API_KEY']='test-key'
    response=user.post('/intelligence',data={'kind':kind,'target':target,'consent':'on'})
    assert response.status_code==302
    return response.location


def test_hash_queue_owner_isolation_and_delete(user,app,monkeypatch):
    from sentinel.intelligence import run_one_check
    from sentinel.models import db, ExternalCheck
    location=create_check(user,app)
    monkeypatch.setattr('sentinel.intelligence.provider_call',lambda *a,**k:{'status':'available','stats':{'malicious':1,'undetected':4},'engines':[]})
    assert run_one_check(app)
    assert b'1' in user.get(location).data
    assert user.get(location+'/status').json['status']=='complete'
    other=app.test_client()
    other.post('/register',data={'name':'Other','email':'other@test.example','password':'Another-password-2026!'})
    for suffix in ('','/status','/export'):
        assert other.get(location+suffix).status_code==404
    assert other.post(location+'/delete').status_code==404
    assert user.get(location+'/export').json['kind']=='hash'
    assert user.post(location+'/delete').status_code==302
    with app.app_context(): assert db.session.query(ExternalCheck).count()==0


def test_any_file_type_is_uploaded_only_after_consent_without_persistence(user,app,monkeypatch):
    from sentinel.models import db, ExternalCheck
    app.config['VIRUSTOTAL_API_KEY']='test-key'
    calls=[]
    def provider(op,value,key,**kwargs):
        calls.append((op,value,kwargs))
        return {'status':'submitted','analysis_id':'test-analysis'}
    monkeypatch.setattr('sentinel.intelligence.provider_call',provider)
    payload=b'Harmless test text; not a PE file.'
    missing=user.post('/intelligence',data={'kind':'file','file':(io.BytesIO(payload),'test.anything')})
    assert missing.status_code==400 and not calls
    response=user.post('/intelligence',data={'kind':'file','consent':'on','file':(io.BytesIO(payload),'test.anything')})
    assert response.status_code==302
    assert calls[0][0]=='file' and calls[0][2]['file_bytes']==payload
    with app.app_context():
        record=db.session.query(ExternalCheck).one()
        assert record.analysis_id=='test-analysis' and record.state=='queued'
        assert payload.decode() not in str(record.result)
        assert not any('bytes' in column.name or 'blob' in column.name for column in ExternalCheck.__table__.columns)


def test_url_submission_polls_to_completion_and_does_not_resubmit(user,app,monkeypatch):
    from sentinel.intelligence import run_one_check
    from sentinel.models import db, ExternalCheck, ProviderQuota, utcnow
    location=create_check(user,app,'url','https://example.com/')
    calls=[]
    responses=iter([{'status':'submitted','analysis_id':'url-analysis'}, {'status':'pending'},
                    {'status':'available','stats':{'harmless':3},'engines':[]}])
    def provider(op,*args,**kwargs): calls.append(op); return next(responses)
    monkeypatch.setattr('sentinel.intelligence.provider_call',provider)
    for _ in range(3):
        with app.app_context():
            row=db.session.query(ExternalCheck).one(); row.available_at=utcnow()-timedelta(seconds=1)
            db.session.get(ProviderQuota,'virustotal').next_at=0; db.session.commit()
        assert run_one_check(app)
    assert calls==['url','analysis','analysis']
    assert user.get(location+'/status').json['status']=='complete'


def test_expired_submission_lease_never_silently_reuploads(user,app,monkeypatch):
    from sentinel.intelligence import run_one_check
    from sentinel.models import db, ExternalCheck, utcnow
    create_check(user,app,'url','https://example.com/')
    with app.app_context():
        row=db.session.query(ExternalCheck).one(); row.state='running'; row.lease_until=utcnow()-timedelta(seconds=1)
        db.session.commit()
    monkeypatch.setattr('sentinel.intelligence.provider_call',lambda *a,**k:pytest.fail('Must not repeat uncertain submission'))
    assert run_one_check(app)
    with app.app_context(): assert db.session.query(ExternalCheck).one().result['status']=='interrupted'


def test_delete_during_lookup_does_not_restore_deleted_record(user,app,monkeypatch):
    from sentinel.intelligence import run_one_check
    from sentinel.models import db, ExternalCheck
    location=create_check(user,app)
    def provider(*args,**kwargs):
        with app.app_context():
            db.session.execute(db.delete(ExternalCheck)); db.session.commit()
        return {'status':'available','stats':{'harmless':1},'engines':[]}
    monkeypatch.setattr('sentinel.intelligence.provider_call',provider)
    assert run_one_check(app)
    assert user.get(location).status_code==404


def test_provider_uses_fixed_endpoints_and_normalizes_untrusted_results(monkeypatch):
    from sentinel.intel_provider import request_provider
    calls=[]
    class Response:
        status_code=200
        def iter_content(self,chunk_size):
            yield b'{"data":{"attributes":{"last_analysis_stats":{"malicious":1},"last_analysis_results":{"engine":{"category":"malicious","result":"<script>x</script>"}}}}}'
        def close(self): pass
    def request(method,url,**kwargs): calls.append((method,url,kwargs)); return Response()
    monkeypatch.setattr('sentinel.intel_provider.requests.request',request)
    result=request_provider('ip','8.8.8.8','fake-key')
    assert calls[0][1]=='https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8'
    assert calls[0][2]['allow_redirects'] is False
    assert result['stats']=={'malicious':1}
    assert result['engines'][0]['result']=='<script>x</script>'


def test_provider_child_has_deadline_and_key_not_in_arguments(monkeypatch):
    from sentinel.intel_provider import provider_call
    seen=[]
    def bounded(command,payload,**kwargs):
        seen.append((command,payload,kwargs)); return b'{"status":"unknown"}'
    monkeypatch.setattr('sentinel.intel_provider.run_bounded',bounded)
    assert provider_call('hash','a'*64,'private-key')['status']=='unknown'
    command,payload,kwargs=seen[0]
    assert 'private-key' not in str(command) and b'private-key' in payload
    assert kwargs['timeout']==20
    assert 'VIRUSTOTAL_API_KEY' not in kwargs['env']


@pytest.mark.parametrize('analysis,attempts,polls,expected',[
    (None,3,0,'retry_limit'),('analysis-id',3,4,'retry_limit'),('analysis-id',0,20,'poll_limit')])
def test_expired_lease_respects_durable_budgets(user,app,monkeypatch,analysis,attempts,polls,expected):
    from sentinel.intelligence import run_one_check
    from sentinel.models import db, ExternalCheck, ProviderQuota, utcnow
    create_check(user,app)
    with app.app_context():
        row=db.session.query(ExternalCheck).one()
        row.analysis_id=analysis; row.attempts=attempts; row.polls=polls
        row.state='running'; row.lease_until=utcnow()-timedelta(seconds=1)
        db.session.commit()
    monkeypatch.setattr('sentinel.intelligence.provider_call',lambda *a,**k:pytest.fail('Exhausted work must not transmit'))
    assert run_one_check(app)
    with app.app_context():
        row=db.session.query(ExternalCheck).one()
        assert row.state=='failed' and row.result['status']==expected
        assert db.session.get(ProviderQuota,'virustotal').count==0


def test_pending_polls_reset_error_budget_and_count_before_transmission(user,app,monkeypatch):
    from sentinel.intelligence import run_one_check
    from sentinel.models import db, ExternalCheck, ProviderQuota, utcnow
    create_check(user,app,'url','https://example.com/')
    with app.app_context():
        row=db.session.query(ExternalCheck).one(); row.analysis_id='analysis-id'; db.session.commit()
    seen=[]
    def provider(*args,**kwargs):
        with app.app_context():
            row=db.session.query(ExternalCheck).one(); seen.append((row.attempts,row.polls))
        return {'status':'pending'}
    monkeypatch.setattr('sentinel.intelligence.provider_call',provider)
    for _ in range(4):
        with app.app_context():
            db.session.query(ExternalCheck).one().available_at=utcnow()-timedelta(seconds=1)
            db.session.get(ProviderQuota,'virustotal').next_at=0; db.session.commit()
        run_one_check(app)
    assert seen==[(1,1),(1,2),(1,3),(1,4)]


@pytest.mark.parametrize('code,status',[(401,'unauthorized'),(403,'unauthorized'),(404,'unknown'),(429,'rate_limited'),(413,'rejected'),(302,'unavailable'),(503,'unavailable')])
def test_provider_http_failures_remain_explicit(monkeypatch,code,status):
    from sentinel.intel_provider import request_provider
    class Response:
        status_code=code
        def close(self): pass
    monkeypatch.setattr('sentinel.intel_provider.requests.request',lambda *a,**k:Response())
    assert request_provider('hash','a'*64,'test-key')['status']==status


@pytest.mark.parametrize('payload',[b'{',b'{"data":{"attributes":{"last_analysis_stats":{"malicious":-1}}}}',b'x'*(2*1024*1024+1)])
def test_invalid_provider_payload_is_not_a_clean_report(monkeypatch,payload):
    from sentinel.intel_provider import request_provider
    class Response:
        status_code=200
        def iter_content(self,chunk_size): yield payload
        def close(self): pass
    monkeypatch.setattr('sentinel.intel_provider.requests.request',lambda *a,**k:Response())
    assert request_provider('hash','a'*64,'test-key')['status']=='unavailable'


def test_failed_engines_are_not_presented_as_no_detection():
    from sentinel.intel_provider import normalize_result
    result=normalize_result({'data':{'attributes':{'last_analysis_stats':{'failure':2},
        'last_analysis_results':{'broken':{'category':'failure'},'unrecognized':{'category':'future-category'}}}}},'hash')
    assert all(row['category']=='failure' and row['result']=='No result reported' for row in result['engines'])


def test_external_post_enforces_csrf(user,app):
    app.config.update(WTF_CSRF_ENABLED=True,VIRUSTOTAL_API_KEY='test-key')
    assert user.post('/intelligence',data={'kind':'hash','target':'a'*64,'consent':'on'}).status_code==400
    from sentinel.models import db,ExternalCheck
    with app.app_context(): assert db.session.query(ExternalCheck).count()==0


def test_analysis_accepts_provider_underscore_stat_names():
    from sentinel.intel_provider import normalize_result
    result=normalize_result({'data':{'attributes':{'status':'completed','stats':{
        'harmless':62,'undetected':31,'confirmed_timeout':0,'type_unsupported':2},'results':{}}}},'analysis')
    assert result['status']=='available'
    assert result['stats']['type-unsupported']==2
    assert result['stats']['confirmed-timeout']==0


def test_new_analysis_not_found_keeps_polling_without_resubmission(monkeypatch):
    from sentinel.intel_provider import request_provider
    class Response:
        status_code=404
        def close(self): pass
    monkeypatch.setattr('sentinel.intel_provider.requests.request',lambda *a,**k:Response())
    assert request_provider('analysis','accepted-analysis-id','test-key')['status']=='pending'
