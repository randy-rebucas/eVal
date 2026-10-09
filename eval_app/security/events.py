from __future__ import annotations

from flask import has_request_context, request
from flask_login import current_user

from ..extensions import db
from ..models import AuditEvent


def record(action: str, organization_id=None, target=None, actor_id=None, **details) -> None:
    """Append to the security audit log. Callers must never pass secrets in ``details``."""
    if actor_id is None and has_request_context() and current_user.is_authenticated:
        actor_id = current_user.id
    ip = ""
    if has_request_context():
        ip = (request.remote_addr or "")[:64]
    db.session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_id=actor_id,
            action=action,
            target_type=type(target).__name__ if target is not None else "",
            target_id=str(getattr(target, "id", "") or ""),
            ip=ip,
            details={k: v for k, v in details.items() if v is not None},
        )
    )
