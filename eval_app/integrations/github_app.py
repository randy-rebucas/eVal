"""GitHub App authentication: app JWTs, short-lived installation tokens, webhook signatures.

The App's private key signs a 10-minute JWT (RS256) that is exchanged for an installation token (valid one hour,
scoped to the repositories the installation grants). Installation tokens are cached in memory until shortly before
they expire and are never stored in the database or logged.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import current_app

from .github import GitHubClient, GitHubError

_TOKEN_CACHE: dict[int, tuple[str, float]] = {}
_LOCK = threading.Lock()
TOKEN_REFRESH_MARGIN = 300  # seconds before expiry a cached token is replaced


class AppNotConfigured(GitHubError):
    def __init__(self):
        super().__init__("The GitHub App is not configured on this server.")


def enabled() -> bool:
    cfg = current_app.config
    return bool(cfg.get("GITHUB_APP_ID") and _private_key_pem() and cfg.get("GITHUB_APP_WEBHOOK_SECRET"))


def install_url(state: str) -> str:
    from .services import github_web_url

    slug = current_app.config.get("GITHUB_APP_SLUG") or ""
    return f"{github_web_url()}/apps/{slug}/installations/new?state={state}"


def _private_key_pem() -> str:
    cfg = current_app.config
    pem = cfg.get("GITHUB_APP_PRIVATE_KEY") or ""
    if not pem and cfg.get("GITHUB_APP_PRIVATE_KEY_FILE"):
        try:
            pem = Path(cfg["GITHUB_APP_PRIVATE_KEY_FILE"]).read_text(encoding="utf-8")
        except OSError:
            return ""
    return pem.replace("\\n", "\n").strip()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(now: float | None = None) -> str:
    """A JWT identifying the App (RS256), valid for 9 minutes with 60 s of clock-skew allowance."""
    if not enabled():
        raise AppNotConfigured()
    now = int(now or time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 540, "iss": str(current_app.config["GITHUB_APP_ID"])}
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}".encode()
    key = serialization.load_pem_private_key(_private_key_pem().encode(), password=None)
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode()}.{_b64(signature)}"


def app_client() -> GitHubClient:
    return GitHubClient(app_jwt(), api_url=current_app.config["GITHUB_API_URL"])


def installation_token(installation_id: int) -> str:
    with _LOCK:
        cached = _TOKEN_CACHE.get(installation_id)
        if cached and cached[1] - TOKEN_REFRESH_MARGIN > time.time():
            return cached[0]
    data = app_client().create_installation_token(installation_id)
    expires = _parse_expiry(data.get("expires_at")) or time.time() + 3000
    with _LOCK:
        _TOKEN_CACHE[installation_id] = (data["token"], expires)
    return data["token"]


def forget_installation(installation_id: int) -> None:
    with _LOCK:
        _TOKEN_CACHE.pop(installation_id, None)


def _parse_expiry(value) -> float | None:
    from datetime import datetime

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def verify_signature(body: bytes, header: str) -> bool:
    """``X-Hub-Signature-256`` check (constant time). Unsigned or wrongly signed deliveries are rejected."""
    secret = current_app.config.get("GITHUB_APP_WEBHOOK_SECRET") or ""
    if not secret or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header[len("sha256="):])
