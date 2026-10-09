from __future__ import annotations

from flask import current_app

from ..extensions import db
from ..models import Audit, Organization, Repository, Upload, utcnow
from ..security import events

ACTIVE_STATUSES = ("queued", "running")
MAX_ACTIVE_AUDITS_PER_ORG = 5


class AuditError(Exception):
    pass


def previous_successful(repo: Repository, before: Audit | None = None) -> Audit | None:
    q = db.select(Audit).where(
        Audit.repository_id == repo.id,
        Audit.organization_id == repo.organization_id,
        Audit.status == "succeeded",
    )
    if before is not None:
        q = q.where(Audit.id != before.id, Audit.created_at <= before.created_at)
    return db.session.execute(q.order_by(Audit.created_at.desc()).limit(1)).scalar_one_or_none()


def create_audit(
    org: Organization, repo: Repository, user_id, *, ref: str = "", upload: Upload | None = None
) -> Audit:
    from eval_engine.workspace import WorkspaceError, validate_ref

    active = db.session.scalar(
        db.select(db.func.count(Audit.id)).where(
            Audit.organization_id == org.id, Audit.status.in_(ACTIVE_STATUSES)
        )
    )
    if active >= MAX_ACTIVE_AUDITS_PER_ORG:
        raise AuditError(f"At most {MAX_ACTIVE_AUDITS_PER_ORG} audits can run at once per organization.")

    if repo.source == "github":
        ref = (ref or repo.default_branch).strip()
        try:
            validate_ref(ref)
        except WorkspaceError as exc:
            raise AuditError(str(exc)) from exc
    else:
        if upload is None:
            raise AuditError("Upload a ZIP archive first.")
        if upload.repository_id != repo.id or upload.organization_id != org.id:
            raise AuditError("Upload does not belong to this repository.")
        ref = ""

    audit = Audit(
        organization_id=org.id,
        repository_id=repo.id,
        upload_id=upload.id if upload else None,
        requested_by_id=user_id,
        requested_ref=ref,
        branch=ref if repo.source == "github" else "",
        previous_audit_id=(prev.id if (prev := previous_successful(repo)) else None),
        status="queued",
        stage="queued",
    )
    db.session.add(audit)
    db.session.flush()
    events.record("audit.requested", organization_id=org.id, target=audit, ref=ref or None)
    db.session.commit()
    enqueue(audit)
    return audit


def enqueue(audit: Audit) -> None:
    from .tasks import run_audit

    try:
        result = run_audit.apply_async(args=[str(audit.id)], queue="audits")
    except Exception as exc:  # broker unavailable
        current_app.logger.error("failed to enqueue audit %s: %s", audit.id, type(exc).__name__)
        audit.status = "failed"
        audit.error = "The audit queue is unavailable. Try again shortly."
        audit.finished_at = utcnow()
        db.session.commit()
        return
    # In eager mode the task already ran and committed; refresh before writing.
    db.session.refresh(audit)
    if not audit.celery_task_id:
        audit.celery_task_id = result.id or ""
        db.session.commit()


def cancel_audit(org: Organization, audit: Audit) -> None:
    if audit.status not in ACTIVE_STATUSES:
        raise AuditError("Only queued or running audits can be cancelled.")
    if audit.celery_task_id:
        celery = current_app.extensions["celery"]
        celery.control.revoke(audit.celery_task_id, terminate=False)
    audit.status = "cancelled"
    audit.stage = "cancelled"
    audit.finished_at = utcnow()
    events.record("audit.cancelled", organization_id=org.id, target=audit)
    db.session.commit()
