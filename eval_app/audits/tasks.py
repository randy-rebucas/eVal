"""Background audit execution."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from flask import current_app

from ..extensions import db
from ..models import Audit, utcnow

STAGE_PROGRESS_FLUSH_SECONDS = 1.0


class _Progress:
    """Persists pipeline progress, throttled, and detects cancellation between stages."""

    def __init__(self, audit: Audit):
        self.audit = audit
        self._last = 0.0

    def __call__(self, stage: str, percent: int, message: str = "") -> None:
        now = time.monotonic()
        self.audit.stage = stage[:64]
        self.audit.progress = max(0, min(100, int(percent)))
        if now - self._last >= STAGE_PROGRESS_FLUSH_SECONDS or percent >= 100:
            db.session.commit()
            self._last = now
        status = db.session.execute(db.select(Audit.status).where(Audit.id == self.audit.id)).scalar_one()
        if status == "cancelled":
            raise _Cancelled()


class _Cancelled(Exception):
    pass


@shared_task(name="eval.run_audit", bind=True, max_retries=0)
def run_audit(self, audit_id: str) -> str:
    from eval_engine.pipeline import PipelineConfig, run_pipeline
    from eval_engine.policy import PolicyError
    from eval_engine.workspace import WorkspaceError, remove_tree

    from ..policies import effective_policy
    from .persist import load_previous_fingerprints, persist_result
    from .workspaces import limits_from_config, prepare_workspace

    audit = db.session.get(Audit, uuid.UUID(audit_id))
    if audit is not None and audit.status == "running":
        # acks_late + reject_on_worker_lost redeliver the task when the worker process died (e.g. OOM-killed by
        # the container limit). Don't retry a repository that may have caused that; record the failure instead
        # of leaving the audit "running" forever.
        _fail(audit, "The audit worker stopped unexpectedly (possibly out of memory).")
        audit.finished_at = utcnow()
        db.session.commit()
        return "failed"
    if audit is None or audit.status != "queued":
        return "skipped"
    audit.status = "running"
    audit.stage = "starting"
    audit.started_at = utcnow()
    audit.celery_task_id = self.request.id or audit.celery_task_id
    db.session.commit()

    cfg = current_app.config
    limits = limits_from_config()
    workdir = Path(cfg.get("WORK_DIR") or cfg["DATA_DIR"] / "work") / audit_id
    progress = _Progress(audit)
    try:
        progress("fetching source", 2)
        root = prepare_workspace(audit, workdir, limits)
        policy, notes = effective_policy(audit, root)
        audit.policy = policy.to_dict()
        if notes:
            audit.stats = {**(audit.stats or {}), "policy_notes": notes}
        ai = _ai_enricher(audit)
        result = run_pipeline(
            root,
            PipelineConfig(
                limits=limits,
                tool_timeout=cfg["ANALYZER_TIMEOUT_SECONDS"],
                progress=progress,
                previous_fingerprints=load_previous_fingerprints(audit),
                ai=ai,
                policy=policy,
            ),
        )
        progress("saving results", 97)
        persist_result(audit, result)
        if audit.pr_number:
            _assess_change(audit)
        audit.status = "succeeded"
        audit.stage = "complete"
        audit.progress = 100
    except _Cancelled:
        db.session.rollback()
        return "cancelled"
    except (WorkspaceError, PolicyError) as exc:
        db.session.rollback()
        _fail(audit, str(exc))
    except SoftTimeLimitExceeded:
        db.session.rollback()
        _fail(audit, "The audit exceeded its time limit.")
    except Exception:  # noqa: BLE001 - convert any failure into a visible audit state
        db.session.rollback()
        current_app.logger.exception("audit %s failed", audit_id)
        _fail(audit, "Internal error while auditing. The incident was logged.")
    finally:
        remove_tree(workdir)
    audit.finished_at = utcnow()
    db.session.commit()
    _report(audit)
    return audit.status


def _assess_change(audit: Audit) -> None:
    """Change risk of the pull request (eval_engine.change_risk); stored with the audit's stats."""
    from eval_engine.change_risk import assess

    from ..findings.services import pr_introduced

    files = (audit.stats or {}).get("pr_files") or [[p, 0, 0] for p in audit.changed_files or []]
    risk = assess([(p, int(a), int(d)) for p, a, d in files], pr_introduced(audit))
    audit.stats = {**(audit.stats or {}), "change_risk": risk.to_dict()}


def _report(audit: Audit) -> None:
    """Publish the result where it was requested from (a GitHub check run); never fails the audit."""
    from .. import notifications
    from ..integrations import checks

    db.session.refresh(audit)  # the webhook may have attached a check run while the audit ran
    for report in (checks.complete, notifications.after_audit):
        try:
            report(audit)
        except Exception:  # noqa: BLE001 - reporting is best-effort
            db.session.rollback()
            current_app.logger.exception("reporting audit %s failed (%s)", audit.id, report.__module__)


def _fail(audit: Audit, message: str) -> None:
    audit.status = "failed"
    audit.error = message[:2000]
    audit.stage = "failed"


def _ai_enricher(audit: Audit):
    from ..ai_config import build_enricher

    return build_enricher(audit.organization_id)
