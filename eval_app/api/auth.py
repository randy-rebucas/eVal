"""Bearer-token authentication for the JSON API.

Tokens look like ``evl_<43 urlsafe chars>``. Only a SHA-256 hash and a short display prefix are stored. A token
belongs to (user, organization); the user's *current* membership role is checked on every request, so removing a
member or lowering their role takes effect immediately.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC
from functools import wraps

from flask import abort, current_app, g, jsonify, request

from ..extensions import db
from ..models import ApiToken, Membership, Organization, User, utcnow
from ..security import events, ratelimit
from ..security.tenancy import reopen_lapsed_triage, role_at_least

TOKEN_PREFIX = "evl_"  # noqa: S105  # nosec B105
REQUESTS_PER_MINUTE = 600


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(org: Organization, user: User, name: str) -> tuple[ApiToken, str]:
    name = name.strip()[:120] or "API token"
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = ApiToken(organization_id=org.id, user_id=user.id, name=name, prefix=raw[:12], token_hash=hash_token(raw))
    db.session.add(token)
    db.session.flush()
    events.record("api_token.created", organization_id=org.id, target=token, name=name)
    db.session.commit()
    return token, raw


def revoke_token(org: Organization, token: ApiToken) -> None:
    token.revoked_at = utcnow()
    events.record("api_token.revoked", organization_id=org.id, target=token)
    db.session.commit()


def _error(status: int, message: str):
    resp = jsonify(error=message)
    resp.status_code = status
    if status == 401:
        resp.headers["WWW-Authenticate"] = 'Bearer realm="eval"'
    return resp


def api_auth(min_role: str = "viewer"):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            scheme, _, raw = header.partition(" ")
            if scheme.lower() != "bearer" or not raw.startswith(TOKEN_PREFIX) or len(raw) > 200:
                return _error(401, "Missing or malformed bearer token.")
            digest = hash_token(raw.strip())
            token = db.session.execute(db.select(ApiToken).where(ApiToken.token_hash == digest)).scalar_one_or_none()
            if token is None or token.revoked_at is not None or not hmac.compare_digest(token.token_hash, digest):
                return _error(401, "Invalid or revoked token.")
            membership = db.session.execute(db.select(Membership).where(
                Membership.user_id == token.user_id, Membership.organization_id == token.organization_id)
            ).scalar_one_or_none()
            if membership is None or not token.user.is_active:
                return _error(401, "Token owner is no longer an active member of the organization.")
            if not ratelimit.hit("api", str(token.id), current_app.config.get("API_RATE_LIMIT", REQUESTS_PER_MINUTE),
                                 60):
                abort(429)
            if not role_at_least(membership.role, min_role):
                return _error(403, f"This action requires the {min_role} role.")
            g.org = db.session.get(Organization, token.organization_id)
            g.membership = membership
            reopen_lapsed_triage(g.org.id)
            g.api_token = token
            g._login_user = token.user  # current_user for this request only; no session is created
            last = token.last_used_at
            if last is not None and last.tzinfo is None:  # SQLite returns naive datetimes
                last = last.replace(tzinfo=UTC)
            if last is None or (utcnow() - last).total_seconds() > 60:
                token.last_used_at = utcnow()
                db.session.commit()
            return view(*args, **kwargs)

        return wrapper

    return decorator
