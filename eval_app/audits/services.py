from __future__ import annotations

from datetime import timedelta

from flask import current_app

from ..extensions import db
from ..models import Audit, Organization, Repository, Upload, utcnow
from ..security import events

ACTIVE_STATUSES = ("queued", "running")
MAX_ACTIVE_AUDITS_PER_ORG = 5


class AuditError(Exception):
    pass


QUEUED_EXPIRY = timedelta(hours=6)


def expire_stale_audits(org: Organization) -> int:
    """Fail audits that can no longer be running (lost worker or lost broker message), so they stop counting
    against the per-organization limit. A running audit is stale once Celery's hard time limit has passed."""
    now = utcnow()
    running_cutoff = now - timedelta(seconds=current_app.config["ANALYZER_TIMEOUT_SECONDS"] * 6 + 300)
    stale = db.session.execute(db.select(Audit).where(
        Audit.organization_id == org.id,
        db.or_(
            db.and_(Audit.status == "running", Audit.started_at < running_cutoff),
            db.and_(Audit.status == "queued", Audit.created_at < now - QUEUED_EXPIRY),
        ),
    )).scalars().all()
    for audit in stale:
        audit.status = audit.stage = "failed"
        audit.error = "The audit did not finish (worker or queue lost). Run it again."
        audit.finished_at = now
    if stale:
        db.session.commit()
    return len(stale)


def previous_successful(repo: Repository, before: Audit | None = None, branch: str | None = None) -> Audit | None:
    """Latest successful audit used as the lifecycle baseline.

    For GitHub repositories the baseline is the same branch (or, for PR audits, the PR's base branch), falling
    back to any branch when that branch has never been audited. PR audits never serve as a baseline."""
    q = db.select(Audit).where(
        Audit.repository_id == repo.id,
        Audit.organization_id == repo.organization_id,
        Audit.status == "succeeded",
        Audit.pr_number.is_(None),
    )
    if before is not None:
        q = q.where(Audit.id != before.id, Audit.created_at <= before.created_at)
    q = q.order_by(Audit.created_at.desc()).limit(1)
    if branch:
        same = db.session.execute(q.where(Audit.branch == branch)).scalar_one_or_none()
        if same is not None:
            return same
    return db.session.execute(q).scalar_one_or_none()


def create_pr_audit(org: Organization, repo: Repository, user_id, number: int, *, trigger: str = "api") -> Audit:
    """Audit a pull request's head commit; findings are compared with the base branch's latest audit."""
    from ..integrations.github import GitHubError
    from ..integrations.services import github_client

    if repo.source != "github":
        raise AuditError("Pull request audits require a GitHub repository.")
    try:
        client = github_client(repo.credential)
        pull = client.get_pull(repo.full_name, number)
        changed = client.list_pull_files(repo.full_name, number)
    except GitHubError as exc:
        raise AuditError(str(exc)) from exc
    if pull["state"] != "open":
        raise AuditError(f"Pull request #{number} is {pull['state']}.")
    return create_audit(org, repo, user_id, ref=pull["head_sha"], trigger=trigger,
                        pr={"number": pull["number"], "base_ref": pull["base_ref"], "head_ref": pull["head_ref"],
                            "changed_files": changed})


def create_audit(
    org: Organization, repo: Repository, user_id, *, ref: str = "", upload: Upload | None = None,
    trigger: str = "ui", pr: dict | None = None,
) -> Audit:
    from eval_engine.workspace import WorkspaceError, validate_ref

    expire_stale_audits(org)
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

    branch = ref if repo.source == "github" else ""
    baseline_branch = branch
    if pr:
        branch = pr.get("head_ref") or ref
        baseline_branch = pr["base_ref"]
    prev = previous_successful(repo, branch=baseline_branch or None)
    audit = Audit(
        organization_id=org.id,
        repository_id=repo.id,
        upload_id=upload.id if upload else None,
        requested_by_id=user_id,
        requested_ref=ref,
        branch=branch[:255],
        trigger=trigger if trigger in ("ui", "api", "pull_request") else "ui",
        pr_number=pr["number"] if pr else None,
        pr_base_ref=(pr["base_ref"] if pr else "")[:255],
        changed_files=list(pr["changed_files"])[:3000] if pr else [],
        previous_audit_id=prev.id if prev else None,
        status="queued",
        stage="queued",
    )
    db.session.add(audit)
    db.session.flush()
    events.record("audit.requested", organization_id=org.id, target=audit, ref=ref or None,
                  pr=pr["number"] if pr else None, trigger=trigger)
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
