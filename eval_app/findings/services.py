"""Findings queries, triage, audit comparison, report models, and GitHub issue creation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from flask import current_app, url_for
from sqlalchemy import and_
from sqlalchemy import update as sa_update

from eval_engine.findings import SEVERITY_ORDER
from eval_engine.redaction import redact

from ..extensions import db
from ..integrations.github import GitHubError
from ..integrations.services import CredentialError, github_client
from ..models import (
    TRIAGE_DISMISSED,
    TRIAGE_STATUSES,
    Audit,
    Finding,
    GitHubIssueLink,
    Organization,
    ResolvedFinding,
    utcnow,
)
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


MIN_REASON_CHARS = 10


def today() -> date:
    return utcnow().date()


def _parse_date(value) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise FindingError("Review date must be a date (YYYY-MM-DD).") from exc


def set_triage(org: Organization, finding: Finding, status: str, *, reason: str = "", owner: str = "",
               expires_on=None, user_id=None) -> None:
    """Record a triage decision.

    * accepted_risk — needs a reason, an accountable owner (team or vendor) and a review date within
      ``ACCEPTED_RISK_MAX_DAYS``. On that date the finding reopens.
    * false_positive — needs a reason; a review date is optional (use one when the dismissal depends on
      something that may change, e.g. "feature flag is off").
    * open / fixed — clear any earlier justification.
    """
    if status not in TRIAGE_STATUSES:
        raise FindingError("Unknown triage status.")
    reason, owner = (reason or "").strip()[:4000], (owner or "").strip()[:200]
    expires = _parse_date(expires_on)
    max_days = current_app.config.get("ACCEPTED_RISK_MAX_DAYS", 365)
    if status in TRIAGE_DISMISSED:
        if len(reason) < MIN_REASON_CHARS:
            raise FindingError(f"Explain the decision (at least {MIN_REASON_CHARS} characters).")
        if status == "accepted_risk" and not owner:
            raise FindingError("Name who owns the fix: a team, or the vendor for third-party code.")
        if status == "accepted_risk" and expires is None:
            raise FindingError("Accepted risks need a review date.")
        if expires is not None and not today() < expires <= today() + timedelta(days=max_days):
            raise FindingError(f"The review date must be in the future and at most {max_days} days away.")
    else:
        reason, owner, expires = "", "", None
    old = finding.triage_status
    finding.triage_status = status
    finding.triage_reason, finding.triage_owner, finding.triage_expires_on = reason, owner, expires
    finding.triaged_by_id, finding.triaged_at = user_id, utcnow()
    events.record("finding.triaged", organization_id=org.id, target=finding, old=old, new=status,
                  reason=reason or None, owner=owner or None, expires_on=expires.isoformat() if expires else None)
    db.session.commit()


def reopen_expired_triage(organization_id) -> int:
    """Reopen findings whose accepted risk / false-positive review date has passed. The reason, owner and date
    are kept so the UI can show what lapsed. Returns the number of findings reopened."""
    expired = and_(Finding.organization_id == organization_id, Finding.triage_status.in_(TRIAGE_DISMISSED),
                   Finding.triage_expires_on.is_not(None), Finding.triage_expires_on <= today())
    count = db.session.scalar(db.select(db.func.count(Finding.id)).where(expired))
    if not count:
        return 0
    db.session.execute(sa_update(Finding).where(expired).values(triage_status="open")
                       .execution_options(synchronize_session=False))
    events.record("finding.triage_expired", organization_id=organization_id, count=count)
    db.session.commit()
    db.session.expire_all()
    return count


def risk_register(org: Organization) -> list[tuple[Finding, Audit]]:
    """Accepted risks and false positives in each repository's latest successful (non-PR) audit, soonest
    review date first — the list to walk through with owning teams and vendors."""
    latest = (
        db.select(Audit.repository_id, db.func.max(Audit.created_at).label("created_at"))
        .where(Audit.organization_id == org.id, Audit.status == "succeeded", Audit.pr_number.is_(None))
        .group_by(Audit.repository_id).subquery()
    )
    rows = db.session.execute(
        db.select(Finding, Audit).join(Audit, Audit.id == Finding.audit_id)
        .join(latest, and_(latest.c.repository_id == Audit.repository_id, latest.c.created_at == Audit.created_at))
        .where(Finding.organization_id == org.id, Audit.organization_id == org.id,
               Finding.triage_status.in_(TRIAGE_DISMISSED))
    ).all()
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(((f, a) for f, a in rows),
                  key=lambda r: (r[0].triage_expires_on or date.max, rank.get(r[0].severity, 9)))


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
        "triage": triage_to_dict(f),
        "ai_explanation": f.ai_explanation or {},
    }


def triage_to_dict(f: Finding) -> dict:
    return {
        "status": f.triage_status, "reason": f.triage_reason, "owner": f.triage_owner,
        "expires_on": f.triage_expires_on.isoformat() if f.triage_expires_on else None,
        "triaged_by": f.triaged_by.email if f.triaged_by else None,
        "triaged_at": f.triaged_at.isoformat() if f.triaged_at else None,
        # The finding was dismissed earlier and reopened because its review date passed.
        "expired": f.triage_status == "open" and f.triage_expires_on is not None,
    }


def report_model(audit: Audit, include_triaged: bool = False, include_dismissed: bool = False) -> dict:
    """The engine's report model, rebuilt from persisted rows (so reports reflect triage decisions).
    ``include_dismissed`` adds accepted risks and false positives (SARIF reports them as suppressed)."""
    findings = [f for f in audit.findings if include_triaged or f.triage_status == "open"
                or (include_dismissed and f.triage_status in TRIAGE_DISMISSED)]
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


# ------------------------------------------------------------------------------------------ pull requests
def pr_introduced(audit: Audit) -> list[Finding]:
    """Scored, open findings in files the PR changed that the base-branch baseline did not have."""
    changed = set(audit.changed_files or [])
    out = [f for f in audit.findings
           if f.kind != "ai_observation" and f.triage_status == "open" and f.lifecycle in ("new", "recurring")
           and f.file_path in changed]
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(out, key=lambda f: (rank.get(f.severity, 9), f.file_path, f.line_start or 0))


def pr_summary(audit: Audit) -> dict:
    introduced = pr_introduced(audit)
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for f in introduced:
        counts[f.severity] += 1
    return {"pr_number": audit.pr_number, "base_ref": audit.pr_base_ref, "changed_files": len(audit.changed_files),
            "baseline_audit_id": str(audit.previous_audit_id) if audit.previous_audit_id else None,
            "introduced_counts": counts, "introduced": [finding_to_dict(f) for f in introduced[:200]]}


def pr_comment_body(audit: Audit, link: str) -> str:
    s = pr_summary(audit)
    counts = s["introduced_counts"]
    total = sum(counts.values())
    score = audit.overall_score if audit.overall_score is not None else "n/a"
    lines = [f"### eVal audit of this pull request — {audit.risk_level or 'n/a'} overall risk",
             f"Overall score **{score}**."]
    if audit.previous_audit_id:
        lines.append(f"Compared with the latest audit of `{audit.pr_base_ref}`.")
    else:
        lines.append(f"No baseline audit of `{audit.pr_base_ref}` exists yet; all findings in changed files count "
                     "as new.")
    lines.append("")
    if total:
        breakdown = ", ".join(f"{k}: {v}" for k, v in counts.items() if v)
        lines.append(f"**{total} finding(s) introduced in changed files:** {breakdown}")
    else:
        lines.append("**No new findings in changed files.**")
    lines.append("")
    for f in pr_introduced(audit)[:15]:
        lines.append(f"- **{f.severity.upper()}** {f.title} — `{f.location}`")
    lines += ["", f"[Full report]({link}) · automated static analysis; scores are risk indicators, not guarantees."]
    return redact("\n".join(lines))


def post_pr_comment(org: Organization, audit: Audit, link: str) -> str:
    repo = audit.repository
    if not audit.pr_number or repo.source != "github" or repo.credential is None:
        raise FindingError("PR comments need a GitHub pull request audit and a repository credential.")
    try:
        result = github_client(repo.credential).create_issue_comment(repo.full_name, audit.pr_number,
                                                                     pr_comment_body(audit, link))
    except (GitHubError, CredentialError) as exc:
        raise FindingError(str(exc)) from exc
    events.record("github.pr_comment", organization_id=org.id, target=audit, pr=audit.pr_number)
    db.session.commit()
    return result["html_url"]


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
