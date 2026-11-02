import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

@pytest.fixture(autouse=True)
def isolated_worker_configuration(monkeypatch):
    # Tests must not depend on the operator's private runtime configuration.
    monkeypatch.setenv('SENTINEL_WSL_DISTRO', '')

@pytest.fixture
def app(tmp_path):
    from sentinel import create_app
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///" + str(tmp_path / "test.db"),
        "WTF_CSRF_ENABLED": False, "VIRUSTOTAL_API_KEY": "",
        "INSTANCE_PATH": str(tmp_path), "ASYNC_REPUTATION": False,
        "ALLOW_REGISTRATION": True, "PE_WORKER_MODE": "native", "REQUIRE_ADMIN_MFA": True,
    })
    yield app
    from sentinel.models import db
    with app.app_context():
        db.session.remove()
        db.engine.dispose()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def user(client):
    client.post("/register", data={"name": "Ayesha", "email": "ayesha@example.test", "password": "Correct-horse-42!"})
    return client

@pytest.fixture
def png():
    from PIL import Image
    import io
    buf = io.BytesIO()
    Image.new("RGB", (160, 160), (49, 110, 99)).save(buf, "PNG")
    return buf.getvalue()

@pytest.fixture(scope="session")
def keys():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )

@pytest.fixture
def pe_bytes():
    # Hand-built inert PE32 fixture. It is parsed as data and never executed.
    import struct
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 132, 0x14c, 1, 0, 0, 0, 224, 0x102)
    off = 152
    struct.pack_into("<H", data, off, 0x10b)
    struct.pack_into("<I", data, off+16, 0x1000)
    struct.pack_into("<I", data, off+20, 0x1000)
    struct.pack_into("<I", data, off+28, 0x400000)
    struct.pack_into("<II", data, off+32, 0x1000, 0x200)
    struct.pack_into("<II", data, off+56, 0x2000, 0x200)
    struct.pack_into("<H", data, off+68, 3)
    struct.pack_into("<I", data, off+92, 16)
    sec = off+224
    data[sec:sec+8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, sec+8, 1, 0x1000, 512, 512)
    struct.pack_into("<I", data, sec+36, 0x60000020)
    data[512] = 0xc3
    return bytes(data)
