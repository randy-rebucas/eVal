"""Tenant resolution and role checks.

Every org-scoped route is mounted under ``/o/<org_slug>/...``. ``org_required(min_role)`` resolves the
organization, verifies the current user's membership, and stores both on ``flask.g``. Resources looked up
inside the org must go through ``get_scoped_or_404`` so a foreign ID yields 404 (no existence oracle).
"""

from __future__ import annotations

import uuid
from functools import wraps

from flask import abort, g
from flask_login import current_user

from ..extensions import db
from ..models import ROLE_RANK, Membership, Organization


def role_at_least(role: str, minimum: str) -> bool:
    return ROLE_RANK.get(role, -1) >= ROLE_RANK[minimum]


def load_membership(user_id, org_slug: str) -> tuple[Organization, Membership] | None:
    row = db.session.execute(
        db.select(Organization, Membership)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Organization.slug == org_slug, Membership.user_id == user_id)
    ).first()
    return (row[0], row[1]) if row else None


def org_required(min_role: str = "viewer"):
    """Decorator for routes taking ``org_slug``. Unauthenticated → login; non-member → 404; low role → 403."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, org_slug: str, **kwargs):
            if not current_user.is_authenticated:
                from flask import current_app

                return current_app.login_manager.unauthorized()
            found = load_membership(current_user.id, org_slug)
            if not found:
                abort(404)
            org, membership = found
            if not role_at_least(membership.role, min_role):
                abort(403)
            g.org = org
            g.membership = membership
            return view(*args, org_slug=org_slug, **kwargs)

        return wrapper

    return decorator


def require_role(min_role: str) -> None:
    """Imperative check inside an already org-scoped view (e.g. for POST branches)."""
    if not role_at_least(g.membership.role, min_role):
        abort(403)


def parse_uuid_or_404(value) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        abort(404)


def get_scoped_or_404[T](model: type[T], obj_id, organization_id=None) -> T:
    org_id = organization_id or g.org.id
    obj = db.session.execute(
        db.select(model).where(model.id == parse_uuid_or_404(obj_id), model.organization_id == org_id)
    ).scalar_one_or_none()
    if obj is None:
        abort(404)
    return obj


def scoped_select(model, organization_id=None):
    return db.select(model).where(model.organization_id == (organization_id or g.org.id))
