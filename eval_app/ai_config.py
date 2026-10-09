"""Builds the per-organization AI enricher used by the audit task. AI is disabled unless an org enables it."""

from __future__ import annotations

from .extensions import db
from .models import AISettings


def build_enricher(organization_id):
    settings = db.session.execute(
        db.select(AISettings).where(AISettings.organization_id == organization_id)
    ).scalar_one_or_none()
    if settings is None or not settings.enabled:
        return
    return  # provider wiring is added with the AI provider abstraction (Phase 5)
