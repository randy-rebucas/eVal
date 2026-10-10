"""Bridges engine results and the database: previous-state loading and result persistence."""

from __future__ import annotations

from sqlalchemy.exc import IntegrityError

from eval_engine.pipeline import AuditResult, PreviousState

from ..extensions import db
from ..models import TRIAGE_DISMISSED, Audit, Finding, ResolvedFinding, Rule, utcnow


def load_previous_fingerprints(audit: Audit) -> PreviousState:
    state = PreviousState()
    if audit.previous_audit_id:
        rows = db.session.execute(
            db.select(Finding.fingerprint, Finding.rule_id, Finding.title, Finding.severity, Finding.category,
                      Finding.file_path)
            .where(Finding.audit_id == audit.previous_audit_id, Finding.organization_id == audit.organization_id)
        ).all()
        state.previous = {
            r.fingerprint: {"rule_id": r.rule_id, "title": r.title, "severity": r.severity, "category": r.category,
                            "file_path": r.file_path}
            for r in rows
        }
    earlier = db.session.execute(
        db.select(Finding.fingerprint)
        .join(Audit, Audit.id == Finding.audit_id)
        .where(
            Audit.repository_id == audit.repository_id,
            Audit.organization_id == audit.organization_id,
            Audit.status == "succeeded",
            Audit.pr_number.is_(None),
            Audit.id != audit.id,
            Audit.created_at <= audit.created_at,
        )
        .distinct()
    ).scalars()
    state.ever_seen = set(earlier)
    return state


def _upsert_rules(result: AuditResult) -> None:
    by_rule = {}
    for f in result.findings:
        by_rule.setdefault(f.rule_id, f)
    if not by_rule:
        return
    existing = set(db.session.execute(db.select(Rule.rule_id).where(Rule.rule_id.in_(list(by_rule)))).scalars())
    for rule_id, f in by_rule.items():
        if rule_id in existing:
            continue
        try:
            with db.session.begin_nested():
                db.session.add(Rule(
                    rule_id=rule_id[:160], tool=rule_id.split(":", 1)[0][:40], title=f.title[:300],
                    category=str(f.category), default_severity=str(f.severity), references=f.references[:5],
                ))
        except IntegrityError:  # another worker inserted it concurrently
            pass


def _carried_triage(audit: Audit) -> dict[str, dict]:
    """Human triage decisions (false positive / accepted risk) follow the fingerprint to later audits, with their
    reason, owner and review date. 'fixed' is not carried: if the finding is detected again, it is open again.
    Decisions whose review date has passed are not carried; the finding comes back open."""
    if not audit.previous_audit_id:
        return {}
    today = utcnow().date()
    rows = db.session.execute(
        db.select(Finding).where(
            Finding.audit_id == audit.previous_audit_id,
            Finding.organization_id == audit.organization_id,
            Finding.triage_status.in_(TRIAGE_DISMISSED),
            db.or_(Finding.triage_expires_on.is_(None), Finding.triage_expires_on > today),
        )
    ).scalars()
    return {f.fingerprint: {"triage_status": f.triage_status, "triage_reason": f.triage_reason,
                            "triage_owner": f.triage_owner, "triage_expires_on": f.triage_expires_on,
                            "triaged_by_id": f.triaged_by_id, "triaged_at": f.triaged_at} for f in rows}


def persist_result(audit: Audit, result: AuditResult) -> None:
    card = result.scorecard
    audit.scores = card.to_dict()
    audit.overall_score = card.overall
    audit.risk_level = card.risk
    audit.severity_counts = card.severity_counts
    audit.tool_status = [o.to_dict() for o in result.outcomes]
    audit.languages = result.languages.to_dict()
    audit.engine_version = result.engine_version
    audit.ai_summary = result.ai_summary or {}
    audit.stats = {
        **(audit.stats or {}),
        **result.stats,
        "lifecycle": {
            "new": result.lifecycle.new,
            "existing": result.lifecycle.existing,
            "recurring": result.lifecycle.recurring,
            "resolved": len(result.lifecycle.resolved),
        },
    }
    _upsert_rules(result)
    carried = _carried_triage(audit)
    db.session.add_all(
        Finding(
            organization_id=audit.organization_id,
            audit_id=audit.id,
            rule_id=f.rule_id[:160],
            fingerprint=f.fingerprint,
            category=str(f.category),
            severity=str(f.severity),
            confidence=str(f.confidence),
            kind=str(f.kind),
            title=f.title[:300],
            description=f.description,
            remediation=f.remediation,
            file_path=f.file_path[:1000],
            line_start=f.line_start,
            line_end=f.line_end,
            evidence=f.evidence,
            sources=f.sources,
            references=f.references[:10],
            lifecycle=f.lifecycle,
            ai_explanation=f.ai_explanation or {},
            reachability=f.reachability,
            **carried.get(f.fingerprint, {"triage_status": "open"}),
        )
        for f in result.findings
    )
    db.session.add_all(
        ResolvedFinding(
            organization_id=audit.organization_id,
            audit_id=audit.id,
            fingerprint=r["fingerprint"],
            rule_id=r.get("rule_id", "")[:160],
            title=r.get("title", "")[:300],
            severity=r.get("severity", "info"),
            category=r.get("category", ""),
            file_path=r.get("file_path", "")[:1000],
        )
        for r in result.lifecycle.resolved
    )
    db.session.flush()
