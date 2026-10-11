"""Signatures between eVal and its sandbox service. Standard library only: the web app imports this module too.

Two kinds, each with its own key derived from ``EVAL_SANDBOX_SECRET``:

* **Service requests** (web app / worker → sandbox): ``Authorization: EvalSandbox <unix ts>:<hex HMAC>`` over the
  method, path, timestamp and SHA-256 of the body. Accepted for ``MAX_SKEW`` seconds.
* **Terminal tokens** (browser → sandbox websocket): ``<session>.<expires>.<user>.<HMAC>``, issued by the web app
  to a member who may open that session, valid for at most ``TTY_TOKEN_SECONDS``.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time

MAX_SKEW = 60
TTY_TOKEN_SECONDS = 120
SESSION_RE = re.compile(r"^[0-9a-f]{32}$")
MIN_SECRET_LENGTH = 32


class TokenError(Exception):
    pass


def _key(secret: str, purpose: str) -> bytes:
    if len(secret) < MIN_SECRET_LENGTH:
        raise TokenError(f"EVAL_SANDBOX_SECRET must be at least {MIN_SECRET_LENGTH} characters.")
    return hmac.new(secret.encode(), purpose.encode(), hashlib.sha256).digest()


def _service_mac(secret: str, method: str, path: str, ts: str, body: bytes) -> str:
    msg = f"{method.upper()}\n{path}\n{ts}\n{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(_key(secret, "service"), msg, hashlib.sha256).hexdigest()


def sign_request(secret: str, method: str, path: str, body: bytes = b"", now: float | None = None) -> str:
    """The ``Authorization`` header value for a service request."""
    ts = str(int(now if now is not None else time.time()))
    return f"EvalSandbox {ts}:{_service_mac(secret, method, path, ts, body)}"


def verify_request(secret: str, header: str, method: str, path: str, body: bytes = b"",
                   now: float | None = None) -> None:
    scheme, _, value = (header or "").partition(" ")
    ts, _, mac = value.partition(":")
    if scheme != "EvalSandbox" or not ts.isdigit() or not mac:
        raise TokenError("missing or malformed signature")
    if abs((now if now is not None else time.time()) - int(ts)) > MAX_SKEW:
        raise TokenError("signature expired")
    if not hmac.compare_digest(mac, _service_mac(secret, method, path, ts, body)):
        raise TokenError("bad signature")


def _tty_mac(secret: str, session: str, expires: str, user: str) -> str:
    msg = f"{session}\n{expires}\n{user}".encode()
    return hmac.new(_key(secret, "tty"), msg, hashlib.sha256).hexdigest()


def issue_tty_token(secret: str, session: str, user: str, now: float | None = None) -> str:
    if not SESSION_RE.match(session) or not re.fullmatch(r"[0-9a-f]{32}", user):
        raise TokenError("session and user must be 32-character hex ids")
    expires = str(int((now if now is not None else time.time()) + TTY_TOKEN_SECONDS))
    return f"{session}.{expires}.{user}.{_tty_mac(secret, session, expires, user)}"


def verify_tty_token(secret: str, token: str, session: str, now: float | None = None) -> str:
    """Check a terminal token for ``session``; returns the user id it was issued to."""
    parts = (token or "").split(".")
    if len(parts) != 4:
        raise TokenError("malformed token")
    sid, expires, user, mac = parts
    if sid != session or not expires.isdigit():
        raise TokenError("token is for another session")
    if int(expires) < (now if now is not None else time.time()):
        raise TokenError("token expired")
    if not hmac.compare_digest(mac, _tty_mac(secret, sid, expires, user)):
        raise TokenError("bad token")
    return user
