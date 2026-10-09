from __future__ import annotations

from ..extensions import db
from ..models import ROLES, Audit, Finding, Membership, Organization, Repository, User
from ..security import events
from ..security.tenancy import role_at_least


class OrgError(Exception):
    pass


def user_orgs(user: User) -> list[tuple[Organization, str]]:
    rows = db.session.execute(
        db.select(Organization, Membership.role)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Membership.user_id == user.id)
        .order_by(Organization.name)
    ).all()
    return [(org, role) for org, role in rows]


def portfolio(org: Organization) -> list[dict]:
    """Latest successful audit per repository with open critical/high counts and recent score history."""
    repos = db.session.execute(
        db.select(Repository).where(Repository.organization_id == org.id).order_by(Repository.name)
    ).scalars().all()
    rows = []
    for repo in repos:
        history = db.session.execute(
            db.select(Audit).where(Audit.repository_id == repo.id, Audit.organization_id == org.id,
                                   Audit.status == "succeeded")
            .order_by(Audit.created_at.desc()).limit(10)
        ).scalars().all()
        latest = history[0] if history else None
        open_counts = {}
        if latest:
            open_counts = dict(db.session.execute(
                db.select(Finding.severity, db.func.count(Finding.id))
                .where(Finding.audit_id == latest.id, Finding.organization_id == org.id,
                       Finding.triage_status == "open", Finding.kind != "ai_observation")
                .group_by(Finding.severity)
            ).all())
        rows.append({"repo": repo, "latest": latest, "history": list(reversed(history)), "open": open_counts})
    risk_rank = {"Critical": 0, "High": 1, "Moderate": 2, "Low": 3}
    rows.sort(key=lambda r: (risk_rank.get(r["latest"].risk_level, 9) if r["latest"] else 10, r["repo"].name))
    return rows


def members(org: Organization) -> list[Membership]:
    return list(
        db.session.execute(
            db.select(Membership).join(User).where(Membership.organization_id == org.id).order_by(User.email)
        ).scalars()
    )


def _owner_count(org: Organization) -> int:
    return db.session.scalar(
        db.select(db.func.count(Membership.id)).where(
            Membership.organization_id == org.id, Membership.role == "owner"
        )
    )


def add_member(org: Organization, actor: Membership, email: str, role: str) -> Membership:
    """Add an *existing* user. (Email invitations require an SMTP integration — see ROADMAP.)"""
    if role not in ROLES:
        raise OrgError("Unknown role.")
    if role == "owner" and actor.role != "owner":
        raise OrgError("Only owners can grant the owner role.")
    user = db.session.execute(db.select(User).where(User.email == email.strip().lower())).scalar_one_or_none()
    if user is None:
        raise OrgError("No user with that email. Ask them to register first.")
    existing = db.session.execute(
        db.select(Membership).where(Membership.organization_id == org.id, Membership.user_id == user.id)
    ).scalar_one_or_none()
    if existing:
        raise OrgError("That user is already a member.")
    membership = Membership(organization_id=org.id, user_id=user.id, role=role)
    db.session.add(membership)
    events.record("member.added", organization_id=org.id, target=membership, role=role)
    db.session.commit()
    return membership


def change_role(org: Organization, actor: Membership, membership: Membership, role: str) -> None:
    if role not in ROLES:
        raise OrgError("Unknown role.")
    if (role == "owner" or membership.role == "owner") and actor.role != "owner":
        raise OrgError("Only owners can grant or revoke the owner role.")
    if not role_at_least(actor.role, membership.role):
        raise OrgError("You cannot change the role of a member above your own role.")
    if membership.role == "owner" and role != "owner" and _owner_count(org) <= 1:
        raise OrgError("An organization must keep at least one owner.")
    old = membership.role
    membership.role = role
    events.record("member.role_changed", organization_id=org.id, target=membership, old=old, new=role)
    db.session.commit()


def remove_member(org: Organization, actor: Membership, membership: Membership) -> None:
    if membership.role == "owner" and actor.role != "owner":
        raise OrgError("Only owners can remove an owner.")
    if not role_at_least(actor.role, membership.role):
        raise OrgError("You cannot remove a member above your own role.")
    if membership.role == "owner" and _owner_count(org) <= 1:
        raise OrgError("An organization must keep at least one owner.")
    events.record("member.removed", organization_id=org.id, target=membership)
    db.session.delete(membership)
    db.session.commit()
