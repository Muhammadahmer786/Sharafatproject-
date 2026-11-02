"""Upload limits must allow advertised files without false multipart 413s."""
import io
import re
from unittest.mock import Mock

import pytest
from PIL import Image


def multipart_with_chunk_boundary(token, png, public):
    boundary = b'SentinelRegressionBoundary'
    prefix = b''
    for name, value in [('csrf_token', token), ('trusted_server', 'on'), ('key_source', 'upload')]:
        prefix += b'--' + boundary + b'\r\nContent-Disposition: form-data; name="' + name.encode() + b'"\r\n\r\n' + value.encode() + b'\r\n'
    prefix += b'--' + boundary + b'\r\nContent-Disposition: form-data; name="document"; filename="boundary.txt"\r\nContent-Type: application/octet-stream\r\n\r\n'
    # A CR at the end of a 64 KiB parser read must be retained for boundary matching.
    document = b'x' * (65535 - len(prefix)) + b'\r\n' + b'y' * 100000
    body = prefix + document + b'\r\n'
    for name, filename, data in [('image', 'cover.png', png), ('public_key', 'recipient.pem', public)]:
        body += b'--' + boundary + b'\r\nContent-Disposition: form-data; name="' + name.encode() + b'"; filename="' + filename.encode() + b'"\r\nContent-Type: application/octet-stream\r\n\r\n' + data + b'\r\n'
    return body + b'--' + boundary + b'--\r\n', boundary.decode(), document


def test_small_valid_multipart_with_boundary_lookbehind_downloads(user, app, keys):
    app.config['WTF_CSRF_ENABLED'] = True
    page = user.get('/protect').get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    image = io.BytesIO(); Image.new('RGB', (800, 600), (30, 50, 70)).save(image, 'PNG')
    body, boundary, document = multipart_with_chunk_boundary(token, image.getvalue(), keys[0])
    assert len(body) < 200000
    response = user.post('/protect', data=body, content_type='multipart/form-data; boundary=' + boundary)
    assert response.status_code == 200, response.status_code
    assert response.mimetype == 'image/png' and 'attachment' in response.headers['Content-Disposition']
    from sentinel.protection import recover_document
    assert recover_document(response.data, keys[1])[1] == document


def test_advertised_combined_file_sizes_reach_document_worker(user, app, keys, monkeypatch):
    from sentinel.protection import MAX_DOCUMENT, MAX_PNG
    worker = Mock(return_value=b'protected-png-placeholder')
    monkeypatch.setattr('sentinel.routes.process_document', worker)
    response = user.post('/protect', data={'trusted_server': 'on', 'key_source': 'upload',
        'document': (io.BytesIO(b'x' * MAX_DOCUMENT), 'limit.bin'),
        'image': (io.BytesIO(b'y' * MAX_PNG), 'limit.png'),
        'public_key': (io.BytesIO(keys[0]), 'recipient.pem')})
    assert response.status_code == 200
    assert len(worker.call_args.args[1]) == MAX_DOCUMENT
    assert len(worker.call_args.args[3]) == MAX_PNG
    # This test checks transport limits; real PNG capacity is enforced by the worker.


@pytest.mark.parametrize('field,limit', [('document', 5 * 1024 * 1024), ('image', 22 * 1024 * 1024), ('public_key', 16384)])
def test_individual_file_limits_still_reject_before_worker(user, png, keys, monkeypatch, field, limit):
    worker = Mock(); monkeypatch.setattr('sentinel.routes.process_document', worker)
    data = {'trusted_server': 'on', 'key_source': 'upload',
        'document': (io.BytesIO(b'small'), 'sample.txt'), 'image': (io.BytesIO(png), 'cover.png'),
        'public_key': (io.BytesIO(keys[0]), 'recipient.pem')}
    data[field] = (io.BytesIO(b'x' * (limit + 1)), 'oversized.bin')
    response = user.post('/protect', data=data)
    assert response.status_code == 400
    assert b'exceeds its allowed size' in response.data
    worker.assert_not_called()


def test_total_upload_rejection_returns_to_protection_form(user, app, monkeypatch):
    worker = Mock(); monkeypatch.setattr('sentinel.routes.process_document', worker)
    response = user.post('/protect', data=b'', content_type='multipart/form-data; boundary=test',
        environ_overrides={'CONTENT_LENGTH': str(app.config['MAX_CONTENT_LENGTH'] + 1)})
    assert response.status_code == 413
    assert b'Protect &amp; download' in response.data
    assert b'5 MiB' in response.data and b'22 MiB' in response.data
    assert b'25 MiB' not in response.data
    worker.assert_not_called()


def test_oversized_text_field_is_still_rejected(user, app):
    response = user.post('/protect', data={'trusted_server': 'x' * (app.config['MAX_FORM_MEMORY_SIZE'] + 1)}, content_type='multipart/form-data')
    assert response.status_code == 413


def test_too_many_multipart_parts_are_still_rejected(user, app):
    response = user.post('/protect', data={f'field{i}': 'x' for i in range(app.config['MAX_FORM_PARTS'] + 1)}, content_type='multipart/form-data')
    assert response.status_code == 413


def test_document_forms_advertise_file_limits_for_browser_validation(user):
    for route in ('/protect', '/recover'):
        page = user.get(route).data
        assert b'data-max-request-bytes=' in page
        assert b'data-max-bytes="23068672"' in page
        assert b'data-max-bytes="16384"' in page
    assert b'data-max-bytes="5242880"' in user.get('/protect').data


def test_waitress_and_flask_share_the_request_limit(app, monkeypatch):
    import run
    app.config['MAX_CONTENT_LENGTH'] = 28 * 1024 * 1024
    serve = Mock()
    monkeypatch.setattr('waitress.serve', serve)
    monkeypatch.setattr('sentinel.jobs.start_worker', lambda app: (Mock(), Mock()))
    monkeypatch.setattr('sentinel.ai_runtime.LocalAIRuntime', lambda config: Mock())
    monkeypatch.setattr('sentinel.operations.configure_logging', lambda app: None)
    monkeypatch.setattr('sentinel.operations.backup_if_due', lambda app: None)
    run.serve_local(app, 5050)
    assert serve.call_args.kwargs['max_request_body_size'] == app.config['MAX_CONTENT_LENGTH']
    assert serve.call_args.kwargs['inbuf_overflow'] > app.config['MAX_CONTENT_LENGTH']
