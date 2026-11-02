import pytest

def test_native_pe_metadata_and_nonexecution(pe_bytes):
    from sentinel.analysis import inspect_pe
    import hashlib
    result = inspect_pe(pe_bytes, "sample.exe")
    assert result["sha256"] == hashlib.sha256(pe_bytes).hexdigest()
    assert result["architecture"] == "x86"
    assert result["sections"][0]["name"] == ".text"
    assert result["method"] == "Static PE inspection"
    assert result["size"] == 1024

@pytest.mark.parametrize("data,name", [(b"MZ" + b"x"*400,"a.exe"), (b"hello","a.exe"), (b"","a.dll")])
def test_invalid_pe_rejected(data,name):
    from sentinel.analysis import inspect_pe
    with pytest.raises(ValueError):
        inspect_pe(data,name)

def test_oversized_and_managed_pe_are_rejected(pe_bytes):
    from sentinel.analysis import inspect_pe
    import struct
    with pytest.raises(ValueError):
        inspect_pe(b"x"*(10*1024*1024+1),"a.exe")
    altered = bytearray(pe_bytes)
    struct.pack_into("<II",altered,152+96+14*8,0x1000,72)
    with pytest.raises(ValueError, match="managed|NET"):
        inspect_pe(bytes(altered),"managed.exe")

def test_import_is_bound_to_hash_and_requires_evidence():
    from sentinel.analysis import validate_findings
    payload={"schema_version":1,"sha256":"a"*64,"tool":"OpenBin","model":"Recorded model","reviewer":"Student reviewer",
             "findings":[{"title":"Suspicious import","severity":"medium","detail":"Requires investigation","evidence":"function 0x401000: VirtualAlloc"}]}
    assert len(validate_findings(payload,"a"*64)["findings"]) == 1
    with pytest.raises(ValueError, match="hash"):
        validate_findings(payload,"b"*64)
    payload["findings"][0]["evidence"]=""
    with pytest.raises(ValueError):
        validate_findings(payload,"a"*64)

def test_reputation_no_key_and_provider_failures(monkeypatch):
    from sentinel.reputation import lookup_hash
    import requests
    assert lookup_hash("a"*64,"")["status"] == "not_configured"
    def fail(*args,**kwargs):
        raise requests.Timeout()
    monkeypatch.setattr(requests,"get",fail)
    assert lookup_hash("a"*64,"test")["status"] == "unavailable"

@pytest.mark.parametrize("status,expected",[(404,"unknown"),(429,"rate_limited"),(401,"unauthorized"),(503,"unavailable")])
def test_reputation_http_status_is_not_a_safe_verdict(monkeypatch,status,expected):
    from sentinel.reputation import lookup_hash
    import requests
    class Response:
        status_code=status
        def close(self):
            pass
    monkeypatch.setattr(requests,"get",lambda *a,**k:Response())
    assert lookup_hash("a"*64,"test")["status"] == expected


def test_reputation_response_is_streamed_and_capped(monkeypatch):
    import requests
    from sentinel.reputation import lookup_hash
    class Response:
        status_code=200
        closed=False
        def iter_content(self,chunk_size):
            for _ in range(40):
                yield b'x'*65536
        def close(self):
            self.closed=True
    response=Response()
    def fake(*args,**kwargs):
        assert kwargs['stream'] is True
        assert kwargs['allow_redirects'] is False
        return response
    monkeypatch.setattr(requests,'get',fake)
    assert lookup_hash('a'*64,'test')['status']=='unavailable'
    assert response.closed
