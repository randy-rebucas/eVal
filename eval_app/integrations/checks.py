"""GitHub check runs for audits started by the GitHub App: "in progress" when queued, then the policy gate's
verdict with inline annotations on the blocking findings."""

from __future__ import annotations

from flask import current_app, has_request_context, url_for

from eval_engine.redaction import redact

from ..extensions import db
from ..models import Audit, Organization
from .github import GitHubError
from .services import CredentialError, repo_client

CHECK_NAME = "eVal audit"
MAX_ANNOTATIONS = 50  # GitHub accepts at most 50 annotations per request


def _details_url(audit: Audit) -> str:
    """Link to the audit; the worker has no request, so it uses EVAL_PUBLIC_URL."""
    org = db.session.get(Organization, audit.organization_id)
    if has_request_context():
        return url_for("audits.detail", org_slug=org.slug, audit_id=audit.id, _external=True)
    base = (current_app.config.get("PUBLIC_URL") or "").rstrip("/")
    return f"{base}/o/{org.slug}/audits/{audit.id}" if base else ""


def start(audit: Audit, head_sha: str) -> None:
    """Create an in-progress check run for ``audit``; failures are logged, never raised."""
    try:
        run = repo_client(audit.repository).create_check_run(
            audit.repository.full_name, name=CHECK_NAME, head_sha=head_sha, details_url=_details_url(audit),
            external_id=str(audit.id), status="queued" if audit.status == "queued" else "in_progress",
            output={"title": "Audit queued", "summary": "eVal is auditing this commit."})
        audit.check_run_id = run["id"]
    except (GitHubError, CredentialError) as exc:
        current_app.logger.warning("check run for audit %s not created: %s", audit.id, exc)


def annotation(f, level: str) -> dict:
    line = f.line_start or 1
    message = (f.description or f.title)[:2000]
    if f.remediation:
        message += f"\n\nFix: {f.remediation[:1000]}"
    return {"path": f.file_path, "start_line": line, "end_line": max(line, f.line_end or line),
            "annotation_level": level, "title": f"[{f.severity}] {f.title}"[:255], "message": message}


def conclusion_payload(audit: Audit) -> dict:
    """The check run's final state: the gate decides success/failure; a failed audit is "neutral"."""
    from .. import policies

    if audit.status != "succeeded":
        return {"status": "completed", "conclusion": "cancelled" if audit.status == "cancelled" else "neutral",
                "output": {"title": f"Audit {audit.status}", "summary": redact(audit.error or "")[:1000]
                           or "The audit did not complete."}}
    gate = policies.evaluate(audit)
    candidates = policies.gate_candidates(audit)
    blocking = {id(f) for f in gate.blocking}
    ordered = [*gate.blocking, *[f for f in candidates if id(f) not in blocking]]
    notes = [annotation(f, "failure" if id(f) in blocking else "warning") for f in ordered if f.file_path]
    scope = "introduced by this pull request" if audit.pr_number else "open"
    lines = [f"**Overall score {audit.overall_score if audit.overall_score is not None else 'n/a'}** · "
             f"{audit.risk_level or 'n/a'} risk · gate threshold `{gate.fail_on}`", ""]
    lines += [f"- {r}" for r in gate.reasons] or [f"No {scope} finding at or above the gate threshold."]
    risk = (audit.stats or {}).get("change_risk")
    if risk:
        lines += ["", f"**Change risk: {risk['level']}** ({risk['score']}/100)"]
        lines += [f"- +{f['points']} {f['factor']}: {f['detail']}" for f in risk["factors"]]
    lines += ["", f"{len(candidates)} {scope} finding(s); {len(gate.blocking)} blocking.",
              "", "Static analysis only: scores are risk indicators, not guarantees."]
    title = "Gate passed" if gate.passed else f"Gate failed: {len(gate.blocking)} blocking finding(s)"
    if not gate.passed and not gate.blocking:
        title = "Gate failed"
    return {"status": "completed", "conclusion": "success" if gate.passed else "failure",
            "output": {"title": title, "summary": redact("\n".join(lines))[:60000],
                       "annotations": notes[:MAX_ANNOTATIONS]}}


def complete(audit: Audit) -> None:
    """Report the finished audit on its check run (no-op without one); failures are logged, never raised."""
    if not audit.check_run_id:
        return
    try:
        repo_client(audit.repository).update_check_run(audit.repository.full_name, audit.check_run_id,
                                                       **conclusion_payload(audit))
    except (GitHubError, CredentialError) as exc:
        current_app.logger.warning("check run %s for audit %s not updated: %s", audit.check_run_id, audit.id, exc)
