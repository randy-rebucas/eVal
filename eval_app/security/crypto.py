"""Credential encryption with key rotation (Fernet = AES-128-CBC + HMAC-SHA256).

``EVAL_ENCRYPTION_KEYS`` is a comma-separated list. The first key encrypts; all keys decrypt, so a new
key can be prepended and old ciphertexts re-encrypted with ``rotate()``.

Run ``python -m eval_app.security.crypto`` to generate a key.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from flask import current_app


class CredentialDecryptionError(Exception):
    pass


def _fernet() -> MultiFernet:
    raw = current_app.config.get("ENCRYPTION_KEYS") or ""
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if not keys:
        raise RuntimeError("EVAL_ENCRYPTION_KEYS is not configured")
    return MultiFernet([Fernet(k.encode()) for k in keys])


def encrypt(plaintext: str) -> bytes:
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt(ciphertext: bytes) -> str:
    try:
        return _fernet().decrypt(bytes(ciphertext)).decode("utf-8")
    except InvalidToken as exc:  # wrong/rotated-out key or tampering
        raise CredentialDecryptionError("credential could not be decrypted") from exc


def rotate(ciphertext: bytes) -> bytes:
    return _fernet().rotate(bytes(ciphertext))


def last4(secret: str) -> str:
    return secret[-4:] if len(secret) >= 8 else ""


if __name__ == "__main__":  # pragma: no cover
    print(Fernet.generate_key().decode())
