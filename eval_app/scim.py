"""SCIM 2.0 user provisioning (RFC 7643/7644 subset) for an organization's identity provider.

``Authorization: Bearer scim_...`` (an organization's SCIM token). Users are the organization's members:
* POST creates the account if needed (owned by this organization: ``managed_by_org_id``) and adds the membership.
  An existing eVal account is only added as a member; its sign-in methods are not touched.
* ``active: false``, DELETE: remove the membership; an account this organization created and that belongs to no other
  organization is also deactivated. Owners are never removed through SCIM (avoids locking an organization out).
Groups are not supported; new members get the SSO connection's default role (member if no SSO is set up).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from functools import wraps

from flask import Blueprint, g, jsonify, request, url_for

from .auth.services import AuthError, normalize_email
from .extensions import db
from .models import Membership, Organization, ScimToken, SsoConnection, User, utcnow
from .security import events

bp = Blueprint("scim", __name__, url_prefix="/scim/v2")
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
MAX_PAGE = 200


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(org: Organization, user_id) -> tuple[ScimToken, str]:
    raw = "scim_" + secrets.token_urlsafe(32)
    token = ScimToken(organization_id=org.id, prefix=raw[:12], token_hash=_hash(raw), created_by_id=user_id)
    db.session.add(token)
    db.session.flush()
    events.record("scim.token_created", organization_id=org.id, target=token, actor_id=user_id)
    db.session.commit()
    return token, raw


def _error(status: int, detail: str, scim_type: str | None = None):
    body = {"schemas": [ERROR_SCHEMA], "status": str(status), "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    resp = jsonify(body)
    resp.status_code = status
    resp.mimetype = "application/scim+json"
    return resp


def _scim(data, status: int = 200):
    resp = jsonify(data)
    resp.status_code = status
    resp.mimetype = "application/scim+json"
    return resp


def scim_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer scim_"):
            return _error(401, "SCIM bearer token required.")
        digest = _hash(header[len("Bearer "):].strip())
        token = db.session.execute(db.select(ScimToken).where(ScimToken.token_hash == digest)).scalar_one_or_none()
        if token is None or token.revoked_at is not None or not hmac.compare_digest(token.token_hash, digest):
            return _error(401, "Invalid or revoked SCIM token.")
        token.last_used_at = utcnow()
        g.org = db.session.get(Organization, token.organization_id)
        return view(*args, **kwargs)

    return wrapper


def _default_role() -> str:
    conn = db.session.execute(db.select(SsoConnection).where(SsoConnection.organization_id == g.org.id)
                              ).scalar_one_or_none()
    return conn.default_role if conn else "member"


def _member(user: User) -> Membership | None:
    return db.session.execute(db.select(Membership).where(Membership.user_id == user.id,
                                                          Membership.organization_id == g.org.id)).scalar_one_or_none()


def _resource(user: User, member: Membership | None) -> dict:
    return {"schemas": [USER_SCHEMA], "id": str(user.id), "userName": user.email,
            "name": {"formatted": user.name}, "displayName": user.name or user.email,
            "emails": [{"value": user.email, "primary": True}],
            "active": bool(member is not None and user.is_active),
            "roles": [{"value": member.role}] if member else [],
            "meta": {"resourceType": "User", "created": user.created_at.isoformat(),
                     "location": url_for("scim.user", user_id=user.id, _external=True)}}


def _user_or_404(user_id: str) -> tuple[User | None, Membership | None]:
    try:
        user = db.session.get(User, uuid.UUID(user_id))
    except ValueError:
        return None, None
    if user is None:
        return None, None
    member = _member(user)
    # Only members, and accounts this organization created, are visible to its SCIM client.
    if member is None and user.managed_by_org_id != g.org.id:
        return None, None
    return user, member


def _activate(user: User, member: Membership | None) -> Membership:
    if member is None:
        member = Membership(user_id=user.id, organization_id=g.org.id, role=_default_role())
        db.session.add(member)
        events.record("member.added", organization_id=g.org.id, target=user, role=member.role, via="scim")
    if user.managed_by_org_id == g.org.id:
        user.is_active_flag = True
    return member


def _deactivate(user: User, member: Membership | None):
    """Returns an error response if refused, else None."""
    if member is not None:
        if member.role == "owner":
            return _error(409, "Owners cannot be removed through SCIM; change the role in eVal first.")
        db.session.delete(member)
        events.record("member.removed", organization_id=g.org.id, target=user, via="scim")
    db.session.flush()
    others = db.session.scalar(db.select(db.func.count(Membership.id)).where(Membership.user_id == user.id))
    if user.managed_by_org_id == g.org.id and not others:
        user.is_active_flag = False
        events.record("user.deactivated", organization_id=g.org.id, target=user, via="scim")
    return None


def _set_active(user: User, member: Membership | None, active: bool):
    if active:
        _activate(user, member)
        return None
    return _deactivate(user, member)


@bp.get("/ServiceProviderConfig")
def service_provider_config():
    return _scim({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                  "patch": {"supported": True}, "bulk": {"supported": False}, "filter": {"supported": True,
                                                                                         "maxResults": MAX_PAGE},
                  "changePassword": {"supported": False}, "sort": {"supported": False}, "etag": {"supported": False},
                  "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token",
                                             "description": "Organization SCIM token (scim_...)"}]})


@bp.get("/Users")
@scim_auth
def users():
    q = db.select(User).join(Membership, Membership.user_id == User.id).where(
        Membership.organization_id == g.org.id)
    flt = request.args.get("filter", "")
    if flt:
        parts = flt.split(" ", 2)
        if len(parts) != 3 or parts[0] not in ("userName", "emails.value") or parts[1].lower() != "eq":
            return _error(400, "Only 'userName eq \"...\"' filters are supported.", "invalidFilter")
        q = q.where(User.email == parts[2].strip().strip('"').lower())
    start = max(1, request.args.get("startIndex", 1, type=int))
    count = min(MAX_PAGE, max(0, request.args.get("count", 100, type=int)))
    total = db.session.scalar(db.select(db.func.count()).select_from(q.subquery()))
    rows = db.session.execute(q.order_by(User.created_at).offset(start - 1).limit(count)).scalars().all()
    db.session.commit()
    return _scim({"schemas": [LIST_SCHEMA], "totalResults": total, "startIndex": start, "itemsPerPage": len(rows),
                  "Resources": [_resource(u, _member(u)) for u in rows]})


@bp.post("/Users")
@scim_auth
def create_user():
    data = request.get_json(silent=True) or {}
    raw = data.get("userName") or next((e.get("value") for e in data.get("emails") or [] if e.get("value")), "")
    try:
        email = normalize_email(str(raw))
    except AuthError:
        return _error(400, "userName must be an email address.", "invalidValue")
    user = db.session.execute(db.select(User).where(User.email == email)).scalar_one_or_none()
    if user is not None and _member(user) is not None:
        return _error(409, "User is already a member.", "uniqueness")
    name = data.get("displayName") or " ".join(
        x for x in ((data.get("name") or {}).get("givenName"), (data.get("name") or {}).get("familyName")) if x)
    if user is None:
        user = User(email=email, name=str(name or "")[:120], managed_by_org_id=g.org.id)
        user.set_unusable_password()
        db.session.add(user)
        db.session.flush()
        events.record("user.provisioned", organization_id=g.org.id, target=user, via="scim")
    member = _activate(user, None) if data.get("active", True) else None
    db.session.commit()
    return _scim(_resource(user, member), 201)


@bp.get("/Users/<user_id>")
@scim_auth
def user(user_id):
    u, member = _user_or_404(user_id)
    db.session.commit()
    return _scim(_resource(u, member)) if u else _error(404, "User not found.")


@bp.put("/Users/<user_id>")
@scim_auth
def replace_user(user_id):
    u, member = _user_or_404(user_id)
    if u is None:
        return _error(404, "User not found.")
    data = request.get_json(silent=True) or {}
    if u.managed_by_org_id == g.org.id and data.get("displayName"):
        u.name = str(data["displayName"])[:120]
    refused = _set_active(u, member, bool(data.get("active", True)))
    if refused is not None:
        db.session.rollback()
        return refused
    db.session.commit()
    return _scim(_resource(u, _member(u)))


@bp.patch("/Users/<user_id>")
@scim_auth
def patch_user(user_id):
    u, member = _user_or_404(user_id)
    if u is None:
        return _error(404, "User not found.")
    data = request.get_json(silent=True) or {}
    for op in data.get("Operations") or []:
        kind = str(op.get("op", "")).lower()
        path, value = op.get("path"), op.get("value")
        if kind not in ("replace", "add"):
            continue
        updates = value if isinstance(value, dict) and not path else {path: value}
        for key, val in updates.items():
            if key == "active":
                active = val if isinstance(val, bool) else str(val).lower() == "true"
                refused = _set_active(u, _member(u), active)
                if refused is not None:
                    db.session.rollback()
                    return refused
            elif key in ("displayName", "name.formatted") and u.managed_by_org_id == g.org.id:
                u.name = str(val)[:120]
    db.session.commit()
    return _scim(_resource(u, _member(u)))


@bp.delete("/Users/<user_id>")
@scim_auth
def delete_user(user_id):
    u, member = _user_or_404(user_id)
    if u is None:
        return _error(404, "User not found.")
    refused = _deactivate(u, member)
    if refused is not None:
        db.session.rollback()
        return refused
    db.session.commit()
    return "", 204
