import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import pytest


def test_worker_download_resumes_a_cut_response_without_accepting_truncated_archive(tmp_path):
    from tools.build_workers import download_verified
    content=b'known release bytes'*1000
    ranges=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):
            pass
        def do_GET(self):
            start,end=map(int,self.headers['Range'].removeprefix('bytes=').split('-'))
            ranges.append(start)
            end=min(end,len(content)-1)
            self.send_response(206)
            self.send_header('Content-Range',f'bytes {start}-{end}/{len(content)}')
            self.send_header('Content-Length',str(end-start+1))
            self.end_headers()
            actual_end=start+1000 if len(ranges)==1 else end+1
            self.wfile.write(content[start:actual_end])
            self.close_connection=True
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    target=tmp_path/'worker.tar.gz'
    try:
        download_verified(f'http://127.0.0.1:{server.server_port}/worker',target,len(content),hashlib.sha256(content).hexdigest())
    finally:
        server.shutdown(); server.server_close(); thread.join()
    assert target.read_bytes()==content
    assert ranges==[0,1000]
    assert not target.with_suffix('.partial').exists()


def test_worker_download_rejects_complete_corrupt_cached_image(tmp_path):
    from tools.build_workers import download_verified
    target=tmp_path/'worker.tar.gz'; target.write_bytes(b'wrong')
    with pytest.raises(ValueError,match='checksum'):
        download_verified('https://invalid.test/never-contacted',target,5,hashlib.sha256(b'right').hexdigest())
