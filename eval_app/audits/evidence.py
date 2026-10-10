"""Audit evidence pack: one ZIP an auditor can file, with a manifest of SHA-256 digests.

Contents: the HTML/JSON/SARIF reports, findings and compliance controls as CSV, the accepted-risk register for the
repository (reason, owner, review date, who accepted), the triage decisions on this audit's findings from the
security log, the effective policy, and analyzer coverage. Nothing in the pack is executable.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile

from eval_engine.compliance import FRAMEWORKS, summarize
from eval_engine.reports import COMPLIANCE_NOTE, DISCLAIMER, render

from ..extensions import db
from ..findings import services as findings_service
from ..models import Audit, AuditEvent, Finding, utcnow


def _csv(rows: list[list]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    for row in rows:
        # Neutralize spreadsheet formulas in user/repository-controlled text (CSV injection).
        writer.writerow(["'" + c if isinstance(c, str) and c[:1] in ("=", "+", "-", "@", "\t", "\r") else c
                         for c in row])
    return buf.getvalue()


def _findings_csv(model: dict) -> str:
    rows = [["severity", "title", "category", "kind", "confidence", "rule_id", "file", "line", "lifecycle",
             "triage_status", "triage_owner", "triage_review_date", *FRAMEWORKS, "remediation", "fingerprint"]]
    for f in model["findings"]:
        c = f.get("compliance") or {}
        t = f.get("triage") or {}
        rows.append([f["severity"], f["title"], f["category"], f["kind"], f["confidence"], f["rule_id"],
                     f["file_path"], f.get("line_start") or "", f.get("lifecycle", ""), t.get("status", ""),
                     t.get("owner", ""), t.get("expires_on") or "", *[" ".join(c.get(k, [])) for k in FRAMEWORKS],
                     f.get("remediation", ""), f.get("fingerprint", "")])
    return _csv(rows)


def _controls_csv(model: dict) -> str:
    from eval_engine.compliance import FRAMEWORK_TITLES

    open_findings = [f for f in model["findings"] if (f.get("triage") or {}).get("status", "open") == "open"
                     and f["kind"] != "ai_observation"]
    rows = [["framework", "control", "title", "open_findings", "critical", "high", "medium", "low", "info"]]
    for fw, controls in summarize(open_findings).items():
        for c in controls:
            sev = c["by_severity"]
            rows.append([FRAMEWORK_TITLES[fw], c["control"], c["title"], c["findings"], sev.get("critical", 0),
                         sev.get("high", 0), sev.get("medium", 0), sev.get("low", 0), sev.get("info", 0)])
    return _csv(rows)


def _risk_register_csv(audit: Audit) -> str:
    rows = [["title", "severity", "rule_id", "location", "status", "reason", "owner", "review_date", "accepted_by",
             "accepted_at"]]
    for f in audit.findings:
        if f.triage_status in ("accepted_risk", "false_positive"):
            rows.append([f.title, f.severity, f.rule_id, f.location, f.triage_status, f.triage_reason,
                         f.triage_owner, f.triage_expires_on.isoformat() if f.triage_expires_on else "",
                         f.triaged_by.email if f.triaged_by else "",
                         f.triaged_at.isoformat() if f.triaged_at else ""])
    return _csv(rows)


def _decisions_csv(audit: Audit) -> str:
    ids = [str(i) for i in db.session.execute(db.select(Finding.id).where(Finding.audit_id == audit.id)).scalars()]
    rows = [["time", "action", "actor", "finding_id", "details"]]
    if ids:
        events = db.session.execute(
            db.select(AuditEvent).where(AuditEvent.organization_id == audit.organization_id,
                                        AuditEvent.target_id.in_(ids + [str(audit.id)]))
            .order_by(AuditEvent.created_at)).scalars()
        from ..models import User

        for ev in events:
            actor = db.session.get(User, ev.actor_id) if ev.actor_id else None
            rows.append([ev.created_at.isoformat(), ev.action, actor.email if actor else "", ev.target_id,
                         json.dumps(ev.details, sort_keys=True)])
    return _csv(rows)


def build(audit: Audit) -> bytes:
    """The evidence pack for a succeeded audit, as ZIP bytes."""
    model = findings_service.report_model(audit, include_triaged=True)
    for f in model["findings"]:
        f.setdefault("compliance", findings_service.map_finding(f["rule_id"], f["category"], f["description"],
                                                                f["references"]))
    open_model = findings_service.report_model(audit)
    files = {
        "report.html": render(open_model, "html"),
        "report.json": render(model, "json"),
        "report.sarif": render(findings_service.report_model(audit, include_dismissed=True), "sarif"),
        "findings.csv": _findings_csv(model),
        "compliance-controls.csv": _controls_csv(model),
        "risk-register.csv": _risk_register_csv(audit),
        "decisions.csv": _decisions_csv(audit),
        "policy.json": json.dumps(audit.policy or {}, indent=2),
        "coverage.json": json.dumps(audit.tool_status or [], indent=2),
    }
    meta = model["meta"]
    manifest = {
        "generated_at": utcnow().isoformat(), "audit_id": str(audit.id), "repository": meta["repository"],
        "ref": meta["ref"], "commit": meta["commit"], "engine_version": audit.engine_version,
        "overall_score": audit.overall_score, "risk": audit.risk_level, "disclaimer": DISCLAIMER,
        "compliance_note": COMPLIANCE_NOTE,
        "files": {name: hashlib.sha256(body.encode("utf-8")).hexdigest() for name, body in sorted(files.items())},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in sorted(files.items()):
            z.writestr(name, body)
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
    return buf.getvalue()
