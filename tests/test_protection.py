import io
import pytest

def test_exact_binary_roundtrip_and_randomized_ciphertext(png, keys):
    from sentinel.protection import protect_document, recover_document
    original = b"\x00private document\xff" * 30
    a = protect_document(original, "notes.pdf", png, keys[0])
    b = protect_document(original, "notes.pdf", png, keys[0])
    assert a != b
    name, recovered = recover_document(a, keys[1])
    assert name == "notes.pdf"
    assert recovered == original
    from PIL import Image
    assert Image.open(io.BytesIO(a)).size == (160,160)

def test_wrong_key_releases_no_document(png, keys):
    from sentinel.protection import protect_document, recover_document, generate_keypair
    _, other = generate_keypair("another-long-passphrase")
    protected = protect_document(b"secret", "a.txt", png, keys[0])
    with pytest.raises(ValueError):
        recover_document(protected, other, "another-long-passphrase")

def test_ciphertext_corruption_fails_authentication(png, keys):
    from sentinel.protection import protect_document, recover_document
    from PIL import Image
    protected = protect_document(b"secret", "a.txt", png, keys[0])
    image = Image.open(io.BytesIO(protected)).convert("RGB")
    pixels = bytearray(image.tobytes())
    # Bit 2400 is inside the ciphertext for this small RSA-2048 package.
    pixels[2400] ^= 1
    changed = Image.frombytes("RGB",image.size,bytes(pixels))
    buf = io.BytesIO()
    changed.save(buf,"PNG")
    with pytest.raises(ValueError):
        recover_document(buf.getvalue(), keys[1])

def test_ordinary_png_and_capacity_and_bad_key(png, keys):
    from sentinel.protection import protect_document, recover_document
    with pytest.raises(ValueError):
        recover_document(png, keys[1])
    with pytest.raises(ValueError, match="capacity"):
        protect_document(b"x"*12000, "a.txt", png, keys[0])
    with pytest.raises(ValueError):
        protect_document(b"x", "a.txt", png, b"bad key")

def test_filename_is_sanitized_and_empty_document_recovers(png, keys):
    from sentinel.protection import protect_document, recover_document
    output = protect_document(b"", "../../secret.txt", png, keys[0])
    name, data = recover_document(output,keys[1])
    assert "/" not in name and "\\" not in name
    assert data == b""

def test_passphrase_protected_keys_and_non_png_rejection():
    from sentinel.protection import generate_keypair, image_capacity
    public, private = generate_keypair("correct long passphrase")
    assert b"ENCRYPTED PRIVATE KEY" in private
    assert b"PUBLIC KEY" in public
    with pytest.raises(ValueError):
        image_capacity(b"not an image")
    with pytest.raises(ValueError):
        generate_keypair("short")

def test_malicious_payload_length_does_not_allocate(png, keys):
    from sentinel.protection import recover_document
    from PIL import Image
    image = Image.open(io.BytesIO(png)).convert("RGB")
    pixels = bytearray(image.tobytes())
    header = b"SLABPNG1" + (0xffffffff).to_bytes(4, "big")
    for i,b in enumerate(header):
        for bit in range(8):
            j = i*8+bit
            pixels[j] = (pixels[j]&254) | ((b>>(7-bit))&1)
    buf = io.BytesIO()
    Image.frombytes("RGB",image.size,bytes(pixels)).save(buf,"PNG")
    with pytest.raises(ValueError):
        recover_document(buf.getvalue(),keys[1])

def test_protection_rejects_output_that_exceeds_recovery_limit(keys):
    import random
    from PIL import Image
    from sentinel.protection import protect_document, MAX_PNG
    rng = random.Random(19)
    image = Image.frombytes("P", (4000, 3000), rng.randbytes(12_000_000))
    image.putpalette(rng.randbytes(768))
    source = io.BytesIO()
    image.save(source, "PNG")
    assert len(source.getvalue()) < MAX_PNG
    with pytest.raises(ValueError, match="resulting PNG"):
        protect_document(b"small document", "note.txt", source.getvalue(), keys[0])

def test_every_supported_rsa_key_size_can_recover(png):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from sentinel.protection import protect_document, recover_document
    key = rsa.generate_private_key(public_exponent=65537, key_size=2056)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    protected = protect_document(b"unusual supported key size", "note.txt", png, public)
    assert recover_document(protected, private) == ("note.txt", b"unusual supported key size")
