from __future__ import annotations

import re
import secrets

from email_validator import EmailNotValidError, validate_email

from ..extensions import db
from ..models import Membership, Organization, User, utcnow
from ..security import events

MIN_PASSWORD_LENGTH = 12
SLUG_RE = re.compile(r"[^a-z0-9]+")


class AuthError(Exception):
    pass


def normalize_email(email: str) -> str:
    try:
        return validate_email(email.strip(), check_deliverability=False).normalized.lower()
    except EmailNotValidError as exc:
        raise AuthError("Enter a valid email address.") from exc


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > 256:
        raise AuthError("Password is too long.")
    classes = sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )
    if classes < 2:
        raise AuthError("Password must combine at least two of: lowercase, uppercase, digits, symbols.")


def slugify(name: str) -> str:
    slug = SLUG_RE.sub("-", name.lower()).strip("-")[:48]
    return slug or "org"


def unique_org_slug(name: str) -> str:
    base = slugify(name)
    slug = base
    while db.session.execute(db.select(Organization.id).where(Organization.slug == slug)).first():
        slug = f"{base}-{secrets.token_hex(3)}"
    return slug


def create_organization(name: str, owner: User) -> Organization:
    name = name.strip()
    if not 2 <= len(name) <= 120:
        raise AuthError("Organization name must be 2–120 characters.")
    org = Organization(name=name, slug=unique_org_slug(name))
    db.session.add(org)
    db.session.flush()
    db.session.add(Membership(user_id=owner.id, organization_id=org.id, role="owner"))
    events.record("org.created", organization_id=org.id, target=org, actor_id=owner.id)
    return org


def register_user(email: str, password: str, name: str = "", org_name: str | None = None):
    email = normalize_email(email)
    validate_password(password)
    if db.session.execute(db.select(User.id).where(User.email == email)).first():
        # Same message shape as success paths would leak; the route shows a generic message.
        raise AuthError("An account with that email already exists.")
    user = User(email=email, name=name.strip()[:120])
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    events.record("user.registered", target=user, actor_id=user.id)
    org = create_organization(org_name, user) if org_name else None
    db.session.commit()
    return user, org


# A constant dummy hash so failed lookups take the same time as real password checks.
_DUMMY = User(email="dummy@invalid")
_DUMMY.set_password(secrets.token_urlsafe(16))


def authenticate(email: str, password: str) -> User | None:
    try:
        email = normalize_email(email)
    except AuthError:
        _DUMMY.check_password(password)
        return None
    user = db.session.execute(db.select(User).where(User.email == email)).scalar_one_or_none()
    if user is None:
        _DUMMY.check_password(password)
        return None
    if not user.check_password(password) or not user.is_active:
        return None
    user.last_login_at = utcnow()
    return user
