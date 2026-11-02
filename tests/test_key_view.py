"""Owner key display must preserve the export authorization boundary."""
import io
import re
import zipfile
from html import unescape

import pyotp
import pytest
from cryptography.hazmat.primitives import serialization

from sentinel.models import AccountKey, AuditEvent, User, db
from sentinel.security import encrypt_secret

PASSWORD = 'Key-view-account-password-2026!'
PASSPHRASE = 'Key-view-backup-passphrase-2026!'


def register(client, email='key-view@example.test'):
    assert client.post('/register', data={'name': 'Key viewer', 'email': email,
                                       'password': PASSWORD}).status_code == 302


def fields(**extra):
    return dict(action='view', trusted_server='on', current_password=PASSWORD,
                passphrase=PASSPHRASE, **extra)


def displayed_pem(response, name):
    match = re.search(r'<textarea[^>]+id="' + name + r'"[^>]*>(.*?)</textarea>',
                      response.get_data(as_text=True), re.S)
    assert match is not None, f'Missing {name} display'
    return unescape(match.group(1)).encode('ascii')


def test_owner_sees_public_key_but_no_private_key_on_get(client, app):
    register(client)
    page = client.get('/keys?action=view')
    assert displayed_pem(page, 'public-key-pem') == client.get('/keys/public').data
    assert b'BEGIN ENCRYPTED PRIVATE KEY' not in page.data
    assert page.headers['Cache-Control'].startswith('no-store')
    assert app.test_client().get('/keys').status_code == 302


def test_verified_view_displays_same_pair_without_leaking_vault_copy(client, app):
    register(client)
    public = client.get('/keys/public').data
    with app.app_context():
        key = db.session.execute(db.select(AccountKey)).scalar_one()
        stored_private = key.private_pem
    response = client.post('/keys', data=fields())
    assert response.status_code == 200 and response.mimetype == 'text/html'
    assert 'Content-Disposition' not in response.headers
    assert response.headers['Cache-Control'].startswith('no-store')
    shown = displayed_pem(response, 'private-key-pem')
    private = serialization.load_pem_private_key(shown, PASSPHRASE.encode())
    assert private.public_key().public_numbers() == serialization.load_pem_public_key(public).public_numbers()
    assert stored_private.encode() not in response.data
    assert PASSPHRASE.encode() not in response.data
    assert b'BEGIN PRIVATE KEY' not in response.data
    assert b'BEGIN ENCRYPTED PRIVATE KEY' not in client.get('/keys').data
    with app.app_context():
        assert db.session.execute(db.select(AccountKey)).scalar_one().private_pem == stored_private
        assert db.session.execute(db.select(AuditEvent).where(AuditEvent.action == 'Assigned private key viewed')).scalar_one()


@pytest.mark.parametrize('change,status', [({'current_password': 'wrong'}, 403),
                                          ({'trusted_server': ''}, 400),
                                          ({'passphrase': 'short'}, 400),
                                          ({'action': 'unknown'}, 400)])
def test_view_rejects_unverified_or_invalid_requests(client, change, status):
    register(client)
    data = fields(); data.update(change)
    response = client.post('/keys', data=data)
    assert response.status_code == status
    assert b'BEGIN ENCRYPTED PRIVATE KEY' not in response.data


def test_view_cannot_select_another_owner(client, app):
    register(client)
    owner_public = client.get('/keys/public').data
    other = app.test_client(); register(other, 'other-key-view@example.test')
    other_public = other.get('/keys/public').data
    with app.app_context():
        other_id = db.session.execute(db.select(User.id).where(User.email == 'other-key-view@example.test')).scalar_one()
    response = client.post('/keys?user_id=' + other_id, data=fields(user_id=other_id))
    assert displayed_pem(response, 'public-key-pem') == owner_public
    assert other_public not in response.data
    private = serialization.load_pem_private_key(displayed_pem(response, 'private-key-pem'), PASSPHRASE.encode())
    assert private.public_key().public_numbers() == serialization.load_pem_public_key(owner_public).public_numbers()


def test_view_requires_fresh_mfa_and_rejects_replay(client, app):
    register(client)
    secret = pyotp.random_base32()
    with app.app_context():
        user = db.session.execute(db.select(User)).scalar_one()
        user.totp_secret = encrypt_secret(secret); db.session.commit()
    assert client.post('/keys', data=fields()).status_code == 403
    data = fields(code=pyotp.TOTP(secret).now())
    response = client.post('/keys', data=data)
    assert response.status_code == 200 and response.mimetype == 'text/html'
    replay = client.post('/keys', data=data)
    assert replay.status_code == 403 and b'BEGIN ENCRYPTED PRIVATE KEY' not in replay.data


def test_explicit_backup_download_remains_a_native_attachment(client):
    register(client)
    data = fields(); data['action'] = 'download'
    response = client.post('/keys', data=data)
    assert response.status_code == 200 and response.mimetype == 'application/zip'
    assert 'attachment; filename=sentinel-keypair.zip' == response.headers['Content-Disposition']
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read('recipient-public.pem') == client.get('/keys/public').data
        serialization.load_pem_private_key(archive.read('recipient-private.pem'), PASSPHRASE.encode())


def test_document_downloads_are_attachments_and_recover_exact_bytes(client, png):
    register(client)
    document = b'Local download roundtrip\x00\xff'
    protected = client.post('/protect', data={'trusted_server': 'on', 'key_source': 'assigned',
        'document': (io.BytesIO(document), 'download-check.bin'), 'image': (io.BytesIO(png), 'cover.png')})
    assert protected.status_code == 200 and protected.mimetype == 'image/png'
    assert protected.headers['Content-Disposition'] == 'attachment; filename=sentinel-protected.png'
    recovered = client.post('/recover', data={'trusted_server': 'on', 'key_source': 'assigned',
        'current_password': PASSWORD, 'image': (io.BytesIO(protected.data), 'protected.png')})
    assert recovered.status_code == 200 and recovered.data == document
    assert recovered.headers['Content-Disposition'] == 'attachment; filename=download-check.bin'
