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
    from eval_engine.workspace import Limits, WorkspaceError, remove_tree

    from .persist import load_previous_fingerprints, persist_result
    from .workspaces import prepare_workspace

    audit = db.session.get(Audit, uuid.UUID(audit_id))
    if audit is None or audit.status != "queued":
        return "skipped"
    audit.status = "running"
    audit.stage = "starting"
    audit.started_at = utcnow()
    audit.celery_task_id = self.request.id or audit.celery_task_id
    db.session.commit()

    cfg = current_app.config
    limits = Limits(
        max_files=cfg["WORKSPACE_MAX_FILES"],
        max_total_bytes=cfg["WORKSPACE_MAX_TOTAL_MB"] * 1024 * 1024,
        max_file_bytes=cfg["WORKSPACE_MAX_FILE_MB"] * 1024 * 1024,
    )
    workdir = Path(cfg.get("WORK_DIR") or cfg["DATA_DIR"] / "work") / audit_id
    progress = _Progress(audit)
    try:
        progress("fetching source", 2)
        root = prepare_workspace(audit, workdir, limits)
        ai = _ai_enricher(audit)
        result = run_pipeline(
            root,
            PipelineConfig(
                limits=limits,
                tool_timeout=cfg["ANALYZER_TIMEOUT_SECONDS"],
                progress=progress,
                previous_fingerprints=load_previous_fingerprints(audit),
                ai=ai,
            ),
        )
        progress("saving results", 97)
        persist_result(audit, result)
        audit.status = "succeeded"
        audit.stage = "complete"
        audit.progress = 100
    except _Cancelled:
        db.session.rollback()
        return "cancelled"
    except WorkspaceError as exc:
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
    return audit.status


def _fail(audit: Audit, message: str) -> None:
    audit.status = "failed"
    audit.error = message[:2000]
    audit.stage = "failed"


def _ai_enricher(audit: Audit):
    from ..ai_config import build_enricher

    return build_enricher(audit.organization_id)
