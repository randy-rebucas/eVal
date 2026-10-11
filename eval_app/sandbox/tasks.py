"""Background preparation of sandbox terminals (runs on the audit workers' queue)."""

from __future__ import annotations

import uuid

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from flask import current_app

from ..extensions import db
from ..models import SandboxSession


@shared_task(name="eval.prepare_sandbox", bind=True, max_retries=0)
def prepare_sandbox(self, session_id: str) -> str:
    from .services import SandboxError, _fail, prepare

    session = db.session.get(SandboxSession, uuid.UUID(session_id))
    if session is None or session.status != "preparing":
        return "skipped"
    try:
        prepare(session)
    except SandboxError as exc:
        db.session.rollback()
        _fail(session, str(exc))
    except SoftTimeLimitExceeded:
        db.session.rollback()
        _fail(session, "Preparing the terminal took too long.")
    except Exception:  # noqa: BLE001 - surface any failure on the session
        db.session.rollback()
        current_app.logger.exception("sandbox %s failed", session_id)
        _fail(session, "Internal error while preparing the terminal. The incident was logged.")
    db.session.commit()
    return session.status
