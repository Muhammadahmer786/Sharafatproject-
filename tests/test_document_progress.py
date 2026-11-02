"""Completion markers acknowledge a real attachment, never a saved-on-disk file."""
import io

import pytest

TOKEN = 'a1' * 16


def protect(client, png, public, token=TOKEN, **extra):
    return client.post('/protect', data={
        'trusted_server': 'on', 'key_source': 'upload', 'download_token': token,
        'document': (io.BytesIO(b'progress round trip'), 'progress.txt'),
        'image': (io.BytesIO(png), 'cover.png'),
        'public_key': (io.BytesIO(public), 'public.pem'), **extra})


def marker_headers(response):
    return [value for value in response.headers.getlist('Set-Cookie') if value.startswith('sentinel_download_')]


def test_document_success_marker_and_exact_roundtrip(user, png, keys):
    protected = protect(user, png, keys[0])
    assert protected.status_code == 200 and 'attachment' in protected.headers['Content-Disposition']
    marker = marker_headers(protected)
    assert len(marker) == 1
    assert 'sentinel_download_' + TOKEN + '=ready;' in marker[0]
    assert 'Max-Age=120' in marker[0] and 'Path=/protect' in marker[0]
    assert 'SameSite=Strict' in marker[0] and 'HttpOnly' not in marker[0]
    recovery_token = 'b2' * 16
    recovered = user.post('/recover', data={
        'trusted_server': 'on', 'key_source': 'upload', 'download_token': recovery_token,
        'image': (io.BytesIO(protected.data), 'protected.png'),
        'private_key': (io.BytesIO(keys[1]), 'private.pem')})
    assert recovered.status_code == 200 and recovered.data == b'progress round trip'
    assert 'attachment' in recovered.headers['Content-Disposition']
    assert marker_headers(recovered)[0].startswith('sentinel_download_' + recovery_token + '=ready;')
    assert 'Path=/recover' in marker_headers(recovered)[0]


@pytest.mark.parametrize('token', ['', 'x' * 32, 'a' * 31, 'a' * 33, 'a; Path=/'])
def test_invalid_or_missing_marker_does_not_break_native_download(user, png, keys, token):
    response = protect(user, png, keys[0], token)
    assert response.status_code == 200 and response.mimetype == 'image/png'
    assert marker_headers(response) == []


def test_invalid_document_response_never_claims_success(user, png, keys):
    response = protect(user, png, keys[0], trusted_server='')
    assert response.status_code == 400 and marker_headers(response) == []


def test_other_downloads_and_error_responses_do_not_emit_document_markers(user, app):
    from sentinel.routes import download
    with app.test_request_context('/keys', method='POST', data={'download_token': TOKEN}):
        response = download(b'public', 'public.pem', 'application/octet-stream')
        assert marker_headers(response) == []


def test_secure_configuration_applies_to_progress_cookie(user, app, png, keys):
    app.config['SESSION_COOKIE_SECURE'] = True
    response = protect(user, png, keys[0])
    assert response.status_code == 200
    assert 'Secure' in marker_headers(response)[0]


def test_document_forms_include_accessible_progress_and_marker(user):
    for mode in ('protect', 'recover'):
        page = user.get('/' + mode).data
        assert b'data-document-progress="' + mode.encode() + b'"' in page
        assert b'name="download_token"' in page
        assert b'role="progressbar"' in page and b'data-progress-bar' in page
        assert b'data-progress-status' in page and b'data-progress-detail' in page
        assert b'document-progress.js' in page
