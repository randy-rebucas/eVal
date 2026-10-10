from __future__ import annotations

import re
import secrets

from email_validator import EmailNotValidError, validate_email
from flask import current_app

from ..extensions import db
from ..models import Membership, Organization, User, UserIdentity, utcnow
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
    # Each organization gets its own concurrent-audit allowance on the shared workers; cap how many one user
    # can create so a single account cannot multiply its share.
    limit = current_app.config.get("MAX_ORGS_PER_USER", 5)
    owned = db.session.scalar(db.select(db.func.count(Membership.id)).where(
        Membership.user_id == owner.id, Membership.role == "owner"))
    if owned >= limit:
        raise AuthError(f"You can own at most {limit} organizations.")
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
        # This reveals that the address is registered. Hiding it needs email verification (the response must be
        # identical for new and existing addresses), which is not implemented yet — see ROADMAP. Registration is
        # rate limited per IP, which bounds enumeration.
        raise AuthError("An account with that email already exists.")
    user = User(email=email, name=name.strip()[:120])
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    events.record("user.registered", target=user, actor_id=user.id)
    org = create_organization(org_name, user) if org_name else None
    db.session.commit()
    return user, org


def _identity(provider: str, subject: str) -> UserIdentity | None:
    return db.session.execute(
        db.select(UserIdentity).where(UserIdentity.provider == provider, UserIdentity.subject == subject)
    ).scalar_one_or_none()


def social_sign_in(provider: str, label: str, profile) -> tuple[User, Organization | None]:
    """The user behind a provider account, creating one (with a workspace) on first sign-in.

    An email already registered here is never linked automatically: eVal does not verify addresses, so whoever
    registered it first may not own it. That user signs in with their password and connects the provider from
    their account page instead."""
    if not profile.subject:
        raise AuthError(f"{label} did not return an account id.")
    identity = _identity(provider, profile.subject)
    if identity is not None:
        user = identity.user
        if not user.is_active:
            raise AuthError("This account is disabled.")
        identity.last_login_at = user.last_login_at = utcnow()
        return user, None
    if not profile.email or not profile.email_verified:
        raise AuthError(f"Your {label} account has no verified email address.")
    email = normalize_email(profile.email)
    if db.session.execute(db.select(User.id).where(User.email == email)).first():
        raise AuthError(f"An eVal account already uses {email}. Log in with your password, then connect "
                        f"{label} from your account page.")
    if not current_app.config["ALLOW_REGISTRATION"]:
        raise AuthError("Registration is closed. Ask an administrator for an invitation.")
    name = (profile.name or "").strip()[:120]
    user = User(email=email, name=name)
    user.set_unusable_password()
    user.last_login_at = utcnow()
    db.session.add(user)
    db.session.flush()
    db.session.add(UserIdentity(user_id=user.id, provider=provider, subject=profile.subject, email=email,
                                last_login_at=user.last_login_at))
    events.record("user.registered", target=user, actor_id=user.id, method=provider)
    workspace = f"{name or email.split('@')[0]}'s workspace"[:120]
    org = create_organization(workspace if len(workspace) >= 2 else "My workspace", user)
    return user, org


def link_identity(user: User, provider: str, label: str, profile) -> UserIdentity:
    if not profile.subject:
        raise AuthError(f"{label} did not return an account id.")
    existing = _identity(provider, profile.subject)
    if existing is not None:
        if existing.user_id != user.id:
            raise AuthError(f"That {label} account is already connected to another eVal user.")
        return existing
    if any(i.provider == provider for i in user.identities):
        raise AuthError(f"Disconnect your current {label} account first.")
    identity = UserIdentity(user_id=user.id, provider=provider, subject=profile.subject,
                            email=(profile.email or "")[:320])
    db.session.add(identity)
    db.session.flush()
    events.record("auth.identity_linked", actor_id=user.id, provider=provider)
    return identity


def unlink_identity(user: User, identity: UserIdentity) -> None:
    if not user.has_password and len(user.identities) <= 1:
        raise AuthError("This is your only way to sign in, so it cannot be disconnected.")
    events.record("auth.identity_unlinked", actor_id=user.id, provider=identity.provider)
    db.session.delete(identity)


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
