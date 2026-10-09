from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from eval_app.security import crypto


def test_roundtrip_and_ciphertext_hides_plaintext(app):
    ct = crypto.encrypt("ghp_supersecretvalue1234")
    assert b"supersecret" not in ct
    assert crypto.decrypt(ct) == "ghp_supersecretvalue1234"


def test_key_rotation(app):
    old_ct = crypto.encrypt("value-1234")
    new_key = Fernet.generate_key().decode()
    app.config["ENCRYPTION_KEYS"] = new_key + "," + app.config["ENCRYPTION_KEYS"]
    rotated = crypto.rotate(old_ct)
    app.config["ENCRYPTION_KEYS"] = new_key  # old key retired
    assert crypto.decrypt(rotated) == "value-1234"
    with pytest.raises(crypto.CredentialDecryptionError):
        crypto.decrypt(old_ct)


def test_last4():
    assert crypto.last4("ghp_abcdefgh1234") == "1234"
    assert crypto.last4("short") == ""
