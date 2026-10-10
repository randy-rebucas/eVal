"""Background fix generation (runs on the audit workers' queue)."""

from __future__ import annotations

import uuid

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from flask import current_app

from ..extensions import db
from ..models import FixProposal


@shared_task(name="eval.generate_fix", bind=True, max_retries=0)
def generate_fix(self, proposal_id: str) -> str:
    from .services import _fail, run_generation

    proposal = db.session.get(FixProposal, uuid.UUID(proposal_id))
    if proposal is None or proposal.status != "queued":
        if proposal is not None and proposal.status == "running":  # redelivered after the worker died
            _fail(proposal, "The worker stopped unexpectedly while generating the fix.")
            db.session.commit()
        return "skipped"
    proposal.status = "running"
    db.session.commit()
    try:
        run_generation(proposal)
    except SoftTimeLimitExceeded:
        db.session.rollback()
        _fail(proposal, "Generating the fix took too long.")
    except Exception:  # noqa: BLE001 - surface any failure on the proposal
        db.session.rollback()
        current_app.logger.exception("fix %s failed", proposal_id)
        _fail(proposal, "Internal error while generating the fix. The incident was logged.")
    db.session.commit()
    return proposal.status
