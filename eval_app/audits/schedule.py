"""Scheduled re-audits (Celery beat) and daily housekeeping.

Every ``celery_app.SCHEDULER_INTERVAL`` seconds the beat process enqueues ``eval.scheduled_audits``, which starts an
audit of the default branch (or the latest upload) for each repository whose schedule is due, and reopens accepted
risks whose review date passed. A repository is due when its newest branch audit is older than its interval;
audits started for any other reason (a push, a person) count, so the schedule only fills gaps.
"""

from __future__ import annotations

from datetime import timedelta

from celery import shared_task
from flask import current_app

from ..extensions import db
from ..models import Audit, Organization, Repository, Upload, utcnow

SCHEDULES = {"off": None, "daily": timedelta(days=1), "weekly": timedelta(days=7)}
SLACK = timedelta(minutes=30)  # start a little early so a daily audit does not drift later every day


def due(repo: Repository, now=None) -> bool:
    interval = SCHEDULES.get(repo.schedule)
    if interval is None:
        return False
    now = now or utcnow()
    last = db.session.execute(
        db.select(Audit.created_at).where(Audit.repository_id == repo.id, Audit.pr_number.is_(None),
                                          Audit.status.in_(("queued", "running", "succeeded")))
        .order_by(Audit.created_at.desc()).limit(1)).scalar_one_or_none()
    if last is not None and last.tzinfo is None:
        from datetime import UTC

        last = last.replace(tzinfo=UTC)
    return last is None or now - last >= interval - SLACK


def run_due(now=None) -> list[str]:
    """Start audits for every due repository; returns their ids."""
    from .services import AuditError, create_audit

    started = []
    repos = db.session.execute(db.select(Repository).where(Repository.schedule != "off")).scalars().all()
    for repo in repos:
        if not due(repo, now):
            continue
        org = db.session.get(Organization, repo.organization_id)
        try:
            if repo.source == "upload":
                upload = db.session.execute(db.select(Upload).where(Upload.repository_id == repo.id)
                                            .order_by(Upload.created_at.desc()).limit(1)).scalar_one_or_none()
                if upload is None:
                    continue
                audit = create_audit(org, repo, None, upload=upload, trigger="schedule")
            else:
                audit = create_audit(org, repo, None, ref=repo.default_branch, trigger="schedule")
        except AuditError as exc:  # e.g. the organization's concurrency limit; retried next tick
            current_app.logger.info("scheduled audit for %s deferred: %s", repo.id, exc)
            continue
        started.append(str(audit.id))
    return started


def housekeeping() -> int:
    from ..findings.services import reopen_expired_triage

    orgs = db.session.execute(db.select(Organization.id)).scalars().all()
    return sum(reopen_expired_triage(org_id) for org_id in orgs)


@shared_task(name="eval.scheduled_audits", ignore_result=True)
def scheduled_audits() -> dict:
    reopened = housekeeping()
    return {"started": run_due(), "reopened": reopened}
