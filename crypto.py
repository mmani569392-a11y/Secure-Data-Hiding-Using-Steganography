"""
Cryptographic layer for the project.

The reference project uses Prime 1 / Prime 2, Base64 and an AES-labelled
encryption stage. This implementation keeps those project concepts but
uses authenticated AES-GCM and PBKDF2 so the resulting application is
actually suitable as a demonstrable secure-data-hiding project.

The final encrypted payload is Base64 text, which is then stored inside
the image by the LSB steganography layer.
"""

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_SIZE = 12


def _derive_key(password: str, prime_1: int, prime_2: int, salt: bytes) -> bytes:
    extra = f"{prime_1}:{prime_2}".encode("utf-8")
    password_material = password.encode("utf-8") + b"|" + extra
    return hashlib.pbkdf2_hmac(
        "sha256",
        password_material,
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


def encrypt_message(message: str, password: str, prime_1: int, prime_2: int) -> str:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, prime_1, prime_2, salt)

    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, message.encode("utf-8"), None)

    payload = {
        "v": 1,
        "alg": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }

    # Base64 gives the steganography layer a safe text payload.
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def decrypt_message(payload_text: str, password: str, prime_1: int, prime_2: int) -> str:
    raw = base64.b64decode(payload_text.encode("ascii"), validate=True)
    payload = json.loads(raw.decode("utf-8"))

    if payload.get("alg") != "AES-256-GCM":
        raise ValueError("Unsupported encrypted payload")

    salt = base64.b64decode(payload["salt"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    key = _derive_key(password, prime_1, prime_2, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
