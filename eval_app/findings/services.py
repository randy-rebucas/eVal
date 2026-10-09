"""Findings queries, triage, audit comparison, report models, and GitHub issue creation."""

from __future__ import annotations

from dataclasses import dataclass

from flask import url_for

from eval_engine.findings import SEVERITY_ORDER
from eval_engine.redaction import redact

from ..extensions import db
from ..integrations.github import GitHubError
from ..integrations.services import CredentialError, github_client
from ..models import TRIAGE_STATUSES, Audit, Finding, GitHubIssueLink, Organization, ResolvedFinding
from ..security import events

PAGE_SIZE = 50
FILTERS = ("severity", "category", "kind", "lifecycle", "triage", "q")


class FindingError(Exception):
    pass


def severity_order_expr():
    return db.case({s: i for i, s in enumerate(SEVERITY_ORDER)}, value=Finding.severity, else_=99)


def filtered_findings(audit: Audit, args: dict, page: int = 1):
    q = db.select(Finding).where(Finding.audit_id == audit.id, Finding.organization_id == audit.organization_id)
    if args.get("severity") in SEVERITY_ORDER:
        q = q.where(Finding.severity == args["severity"])
    if args.get("category"):
        q = q.where(Finding.category == args["category"])
    if args.get("kind"):
        q = q.where(Finding.kind == args["kind"])
    if args.get("lifecycle"):
        q = q.where(Finding.lifecycle == args["lifecycle"])
    triage = args.get("triage", "open")
    if triage in TRIAGE_STATUSES:
        q = q.where(Finding.triage_status == triage)
    if args.get("q"):
        like = f"%{args['q'][:100]}%"
        q = q.where(db.or_(Finding.title.ilike(like), Finding.file_path.ilike(like), Finding.rule_id.ilike(like)))
    q = q.order_by(severity_order_expr(), Finding.category, Finding.file_path, Finding.line_start)
    return db.paginate(q, page=max(page, 1), per_page=PAGE_SIZE, error_out=False)


def set_triage(org: Organization, finding: Finding, status: str) -> None:
    if status not in TRIAGE_STATUSES:
        raise FindingError("Unknown triage status.")
    old = finding.triage_status
    finding.triage_status = status
    events.record("finding.triaged", organization_id=org.id, target=finding, old=old, new=status)
    db.session.commit()


@dataclass
class Comparison:
    base: Audit
    head: Audit
    introduced: list[Finding]
    persisting: list[Finding]
    fixed: list[Finding]
    category_delta: dict[str, tuple[float | None, float | None]]


def compare(base: Audit, head: Audit) -> Comparison:
    if base.repository_id != head.repository_id or base.organization_id != head.organization_id:
        raise FindingError("Audits belong to different repositories.")
    base_f = {f.fingerprint: f for f in base.findings}
    head_f = {f.fingerprint: f for f in head.findings}
    deltas = {}
    for name in (head.scores or {}).get("categories", {}):
        b = (base.scores or {}).get("categories", {}).get(name, {}).get("score")
        h = head.scores["categories"][name].get("score")
        deltas[name] = (b, h)
    return Comparison(
        base=base, head=head,
        introduced=[f for fp, f in head_f.items() if fp not in base_f],
        persisting=[f for fp, f in head_f.items() if fp in base_f],
        fixed=[f for fp, f in base_f.items() if fp not in head_f],
        category_delta=deltas,
    )


def finding_to_dict(f: Finding) -> dict:
    return {
        "id": str(f.id), "rule_id": f.rule_id, "fingerprint": f.fingerprint, "title": f.title,
        "category": f.category, "severity": f.severity, "confidence": f.confidence, "kind": f.kind,
        "description": f.description, "remediation": f.remediation, "file_path": f.file_path,
        "line_start": f.line_start, "line_end": f.line_end, "evidence": f.evidence, "sources": f.sources,
        "references": f.references, "lifecycle": f.lifecycle, "triage_status": f.triage_status,
        "ai_explanation": f.ai_explanation or {},
    }


def report_model(audit: Audit, include_triaged: bool = False) -> dict:
    """The engine's report model, rebuilt from persisted rows (so reports reflect triage decisions)."""
    findings = [f for f in audit.findings if include_triaged or f.triage_status == "open"]
    resolved = [{"fingerprint": r.fingerprint, "title": r.title, "severity": r.severity, "rule_id": r.rule_id,
                 "file_path": r.file_path} for r in audit.resolved]
    lifecycle = dict((audit.stats or {}).get("lifecycle") or {})
    lifecycle["resolved"] = resolved
    return {
        "meta": {
            "title": f"eVal audit: {audit.repository.name}",
            "repository": audit.repository.full_name or audit.repository.name,
            "ref": audit.branch or "uploaded archive",
            "commit": audit.commit_sha,
            "generated_at": (audit.finished_at or audit.created_at).strftime("%Y-%m-%d %H:%M UTC"),
            "audit_id": str(audit.id),
            "engine_version": audit.engine_version,
            "excluded_triaged": 0 if include_triaged else len(audit.findings) - len(findings),
        },
        "engine_version": audit.engine_version,
        "scores": audit.scores or {},
        "languages": audit.languages or {},
        "tools": audit.tool_status or [],
        "lifecycle": lifecycle,
        "stats": audit.stats or {},
        "ai_summary": audit.ai_summary or {},
        "findings": [finding_to_dict(f) for f in findings],
    }


# ----------------------------------------------------------------------------------------- GitHub issues
def issue_body(finding: Finding, audit: Audit, link: str) -> str:
    evidence = redact(finding.evidence or "").replace("```", "ʼʼʼ")
    lines = [
        f"**Severity:** {finding.severity} · **Category:** {finding.category} · **Type:** {finding.kind} · "
        f"**Confidence:** {finding.confidence}",
        f"**Location:** `{finding.location}` · **Rule:** `{finding.rule_id}`",
        f"**Commit audited:** `{audit.commit_sha or 'n/a'}`",
        "",
        finding.description,
        "",
    ]
    if evidence:
        lines += ["```", evidence, "```", ""]
    lines += [f"**Recommended remediation:** {finding.remediation}", ""]
    if finding.references:
        lines += ["References: " + ", ".join(finding.references[:5]), ""]
    lines += [f"<sub>Reported by eVal · [view in eVal]({link}) · fingerprint `{finding.fingerprint[:16]}`. "
              "Automated static analysis; verify before acting.</sub>"]
    return "\n".join(lines)


def create_github_issues(org: Organization, audit: Audit, finding_ids: list, user_id) -> dict:
    repo = audit.repository
    if repo.source != "github":
        raise FindingError("GitHub issues can only be created for GitHub repositories.")
    if repo.credential is None:
        raise FindingError("Attach a GitHub credential with Issues: write to this repository first.")
    findings = db.session.execute(
        db.select(Finding).where(Finding.id.in_(finding_ids), Finding.audit_id == audit.id,
                                 Finding.organization_id == org.id)
    ).scalars().all()
    if not findings:
        raise FindingError("Select at least one finding.")
    if len(findings) > 25:
        raise FindingError("Create at most 25 issues at a time.")
    try:
        client = github_client(repo.credential)
    except CredentialError as exc:
        raise FindingError(str(exc)) from exc
    created, skipped, errors = [], [], []
    for f in findings:
        existing = db.session.execute(
            db.select(GitHubIssueLink).where(GitHubIssueLink.repository_id == repo.id,
                                             GitHubIssueLink.fingerprint == f.fingerprint)
        ).scalar_one_or_none()
        if existing:
            skipped.append(existing.issue_url)
            continue
        link = url_for("findings.detail", org_slug=org.slug, finding_id=f.id, _external=True)
        try:
            issue = client.create_issue(repo.full_name, f"[eVal][{f.severity}] {f.title}"[:256],
                                        issue_body(f, audit, link), labels=["eval", f"severity:{f.severity}"])
        except GitHubError as exc:
            errors.append(f"{f.title[:60]}: {exc}")
            if exc.status in (401, 403, 404):
                break
            continue
        db.session.add(GitHubIssueLink(organization_id=org.id, repository_id=repo.id, fingerprint=f.fingerprint,
                                       issue_number=issue["number"], issue_url=issue["html_url"],
                                       created_by_id=user_id))
        events.record("github.issue_created", organization_id=org.id, target=f, issue=issue["number"])
        created.append(issue["html_url"])
    db.session.commit()
    return {"created": created, "skipped": skipped, "errors": errors}


def issue_links_for(audit: Audit) -> dict[str, GitHubIssueLink]:
    rows = db.session.execute(
        db.select(GitHubIssueLink).where(GitHubIssueLink.repository_id == audit.repository_id,
                                         GitHubIssueLink.organization_id == audit.organization_id)
    ).scalars()
    return {r.fingerprint: r for r in rows}


def resolved_for(audit: Audit) -> list[ResolvedFinding]:
    return list(audit.resolved)
