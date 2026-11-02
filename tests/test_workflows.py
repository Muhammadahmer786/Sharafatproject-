import io
import re

def upload_scan(client, data, **extra):
    return client.post("/analyze", data={"file":(io.BytesIO(data),"fixture.exe"), **extra}, content_type="multipart/form-data")

def test_scan_history_pdf_and_owner_isolation(user, app, pe_bytes):
    response=upload_scan(user,pe_bytes)
    assert response.status_code==302
    location=response.headers["Location"]
    detail=user.get(location)
    assert detail.status_code==200
    assert b"fixture.exe" in detail.data
    assert b"Awaiting" in detail.data
    report=user.get(location+"/report")
    assert report.status_code==200 and report.data.startswith(b"%PDF")
    assert b"fixture.exe" in user.get("/history?q=fixture").data
    other=app.test_client()
    other.post("/register",data={"name":"Other","email":"other@example.test","password":"Another-password-42"})
    assert other.get(location).status_code==404
    assert other.get(location+"/report").status_code==404
    assert other.post(location+"/delete").status_code==404
    assert user.post(location+"/delete").status_code==302
    assert user.get(location).status_code==404

def test_protect_and_recover_http_roundtrip(user,png,keys,app):
    res=user.post("/protect",data={
        "document":(io.BytesIO(b"important paper"),"paper.txt"),
        "image":(io.BytesIO(png),"cover.png"),
        "public_key":(io.BytesIO(keys[0]),"recipient.pem"),
        "trusted_server":"on",
    },content_type="multipart/form-data")
    assert res.status_code==200 and res.mimetype=="image/png"
    output=user.post("/recover",data={
        "image":(io.BytesIO(res.data),"protected.png"),
        "private_key":(io.BytesIO(keys[1]),"private.pem"),
        "trusted_server":"on",
    },content_type="multipart/form-data")
    assert output.status_code==200 and output.data==b"important paper"
    assert "paper.txt" in output.headers["Content-Disposition"]
    assert output.headers["Cache-Control"].startswith("no-store")
    from sentinel.models import db, AuditEvent
    with app.app_context():
        events=db.session.execute(db.select(AuditEvent)).scalars().all()
        assert not any("paper.txt" in e.action or "important" in e.action for e in events)

def test_document_processing_requires_trust_acknowledgment(user,png,keys):
    res=user.post("/protect",data={"document":(io.BytesIO(b"x"),"x.txt"),
        "image":(io.BytesIO(png),"x.png"),"public_key":(io.BytesIO(keys[0]),"k.pem")})
    assert res.status_code==400

def test_openbin_import_requires_consent_and_hash_binding(user,pe_bytes):
    import hashlib,json
    response=upload_scan(user,pe_bytes)
    location=response.headers["Location"]
    payload={"schema_version":1,"sha256":hashlib.sha256(pe_bytes).hexdigest(),"tool":"OpenBin",
        "model":"reviewed external model","reviewer":"Ayesha",
        "findings":[{"title":"Manual review","severity":"info","detail":"Reviewed entry point","evidence":"0x401000: return"}]}
    res=user.post(location+"/findings",data={"findings":(io.BytesIO(json.dumps(payload).encode()),"findings.json"),"reviewed":"on"})
    assert res.status_code==400
    response=upload_scan(user,pe_bytes,cloud_consent="on")
    location=response.headers["Location"]
    res=user.post(location+"/findings",data={"findings":(io.BytesIO(json.dumps(payload).encode()),"findings.json"),"reviewed":"on"})
    assert res.status_code==302
    assert b"Manual review" in user.get(location).data

def test_admin_is_not_a_scan_content_backdoor(user,app,pe_bytes):
    # Authorization is independent of enrollment; MFA gating has its own regression.
    app.config['REQUIRE_ADMIN_MFA']=False
    from sentinel.models import db,User
    response=upload_scan(user,pe_bytes)
    location=response.headers["Location"]
    admin=app.test_client()
    admin.post("/register",data={"name":"Admin","email":"admin@example.test","password":"Another-password-42"})
    with app.app_context():
        u=db.session.execute(db.select(User).where(User.email=="admin@example.test")).scalar_one()
        u.role="admin"
        db.session.commit()
    assert admin.get("/admin").status_code==200
    assert admin.get(location).status_code==404

def test_empty_history_and_all_pages_render(user):
    for url in ["/","/analyze","/history","/protect","/recover","/keys","/settings","/guide"]:
        assert user.get(url).status_code==200
    assert user.get("/health").json["status"]=="ok"
