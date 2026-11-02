"""Versioned authenticated encrypted packages embedded into RGB PNG pixels."""
import io
import json
import secrets
import struct
import warnings
from PIL import Image, UnidentifiedImageError
from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename

MAGIC = b"SLABPNG1"
MAX_PIXELS = 12_000_000
MAX_DOCUMENT = 5 * 1024 * 1024
MAX_PNG = 22 * 1024 * 1024
MAX_KEY = 16_384
HEADER = struct.Struct(">8sI")
INNER = struct.Struct(">H")

def _image(data):
    if len(data) > MAX_PNG:
        raise ValueError("PNG exceeds the 22 MiB image limit.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            image = Image.open(io.BytesIO(data))
            if image.format != "PNG" or getattr(image, "n_frames", 1) != 1:
                raise ValueError("Choose a single-frame, lossless PNG image.")
            if image.width * image.height > MAX_PIXELS or image.width < 8 or image.height < 8:
                raise ValueError("PNG dimensions must be at least 8 × 8 and at most 12 million pixels.")
            image.load()
            return image.convert("RGB")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise ValueError("The image is invalid or exceeds safe image limits.") from exc

def image_capacity(png_bytes):
    image = _image(png_bytes)
    return {"width": image.width, "height": image.height,
            "gross_bytes": (image.width * image.height * 3) // 8,
            "estimated_document_bytes": max(0, (image.width * image.height * 3)//8 - 1024)}

def _public(data):
    if len(data) > MAX_KEY:
        raise ValueError("Key file is too large.")
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError("Choose a valid RSA public key in PEM format.") from exc
    if not isinstance(key, rsa.RSAPublicKey) or not 2048 <= key.key_size <= 4096:
        raise ValueError("Use an RSA public key between 2048 and 4096 bits.")
    return key

def _oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

def generate_keypair(passphrase):
    if not isinstance(passphrase, str) or not 12 <= len(passphrase) <= 256:
        raise ValueError("Use a passphrase of 12 to 256 characters.")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(passphrase.encode("utf-8")))
    return public, private


def export_keypair(private_pem,old_passphrase,new_passphrase,expected_public):
    if not isinstance(new_passphrase,str) or not 12<=len(new_passphrase)<=256:
        raise ValueError('Use an export passphrase of 12 to 256 characters.')
    if not isinstance(old_passphrase,str) or not 12<=len(old_passphrase)<=256 or len(private_pem)>MAX_KEY:
        raise ValueError('The assigned key could not be unlocked.')
    try:
        private=serialization.load_pem_private_key(private_pem,password=old_passphrase.encode())
        public=_public(expected_public)
        if not isinstance(private,rsa.RSAPrivateKey) or private.public_key().public_numbers()!=public.public_numbers():
            raise ValueError('Assigned key mismatch')
        return (public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo),
                private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(new_passphrase.encode())))
    except (ValueError,TypeError,UnsupportedAlgorithm) as exc:
        raise ValueError('The assigned key could not be unlocked. Check the original server secret and backup.') from exc

def protect_document(document, filename, png_bytes, public_pem):
    if len(document) > MAX_DOCUMENT:
        raise ValueError("Document exceeds the 5 MiB limit.")
    image = _image(png_bytes)
    key = _public(public_pem)
    filename = secure_filename(filename)[:180] or "document.bin"
    metadata = json.dumps({"name": filename, "size": len(document)}, separators=(",", ":")).encode()
    plaintext = struct.pack(">H", len(metadata)) + metadata + document
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    wrapped = key.encrypt(aes_key, _oaep())
    # Outer length and algorithm version, wrapped key and nonce are authenticated.
    length = 2 + len(wrapped) + 12 + len(plaintext) + 16
    outer = HEADER.pack(MAGIC, length)
    prefix = INNER.pack(len(wrapped)) + wrapped + nonce
    if (len(outer) + length) * 8 > image.width * image.height * 3:
        raise ValueError("The document exceeds this PNG's capacity. Choose a larger image or smaller document.")
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, outer + prefix)
    package = outer + prefix + ciphertext
    pixels = bytearray(image.tobytes())
    for index, value in enumerate(package):
        offset = index * 8
        for bit in range(8):
            pixels[offset + bit] = (pixels[offset + bit] & 254) | ((value >> (7-bit)) & 1)
    output = io.BytesIO()
    Image.frombytes("RGB", image.size, bytes(pixels)).save(output, format="PNG")
    if output.tell() > MAX_PNG:
        raise ValueError("The resulting PNG exceeds the 22 MiB recovery limit. Choose a smaller cover image.")
    return output.getvalue()

def _extract(pixels, count):
    if count < 0 or count * 8 > len(pixels):
        raise ValueError("Invalid hidden-package length.")
    result = bytearray(count)
    for i in range(count):
        value = 0
        for bit in pixels[i*8:i*8+8]:
            value = (value << 1) | (bit & 1)
        result[i] = value
    return bytes(result)

def recover_document(png_bytes, private_pem, password=None):
    image = _image(png_bytes)
    pixels = image.tobytes()
    outer = _extract(pixels, HEADER.size)
    magic, length = HEADER.unpack(outer)
    if magic != MAGIC:
        raise ValueError("This PNG does not contain a supported Sentinel Lab package.")
    if length < 2+256+12+16 or length > MAX_DOCUMENT+4096 or (length+HEADER.size)*8 > len(pixels):
        raise ValueError("The hidden package is damaged or has an invalid length.")
    package = _extract(pixels, length + HEADER.size)[HEADER.size:]
    wrapped_size = INNER.unpack(package[:2])[0]
    if not 256 <= wrapped_size <= 512 or len(package) < 2+wrapped_size+12+16:
        raise ValueError("Invalid encrypted-key package.")
    if len(private_pem) > MAX_KEY or (password and len(password) > 256):
        raise ValueError("Key or passphrase is too large.")
    try:
        key = serialization.load_pem_private_key(private_pem, password=password.encode() if password else None)
        if not isinstance(key, rsa.RSAPrivateKey) or not 2048 <= key.key_size <= 4096:
            raise ValueError("Unsupported RSA key.")
        wrapped = package[2:2+wrapped_size]
        nonce = package[2+wrapped_size:14+wrapped_size]
        prefix = package[:14+wrapped_size]
        aes_key = key.decrypt(wrapped, _oaep())
        plaintext = AESGCM(aes_key).decrypt(nonce, package[14+wrapped_size:], outer+prefix)
        metadata_size = struct.unpack(">H", plaintext[:2])[0]
        if not 1 <= metadata_size <= 1024:
            raise ValueError("Invalid metadata.")
        metadata = json.loads(plaintext[2:2+metadata_size])
        document = plaintext[2+metadata_size:]
        if not isinstance(metadata, dict) or metadata.get("size") != len(document) or len(document) > MAX_DOCUMENT:
            raise ValueError("Invalid document length.")
        if not isinstance(metadata.get("name"), str):
            raise ValueError("Invalid filename.")
        name = secure_filename(metadata["name"])[:180] or "document.bin"
        return name, document
    except (ValueError, TypeError, InvalidTag, UnsupportedAlgorithm, struct.error, UnicodeDecodeError, KeyError) as exc:
        raise ValueError("Recovery failed: check your private key/passphrase and use the original, unmodified PNG.") from exc
