"""JSON API v1 (bearer tokens). Documented in docs/API.md. Every lookup is scoped to the token's organization."""

from __future__ import annotations

from flask import Blueprint, Response, abort, g, jsonify, request, url_for

from eval_engine.findings import SEVERITY_ORDER
from eval_engine.reports import CONTENT_TYPES, FORMATS, render

from ..audits.services import AuditError, create_audit, create_pr_audit
from ..extensions import db
from ..findings import services as findings_service
from ..models import Audit, Finding, Project, Repository
from ..projects import repositories as repo_service
from ..security.tenancy import get_scoped_or_404, scoped_select
from .auth import api_auth
from .cors import add_cors_headers

bp = Blueprint("api", __name__, url_prefix="/api/v1")
bp.after_request(add_cors_headers)


def _audit_json(a: Audit, detail: bool = False) -> dict:
    data = {
        "id": str(a.id), "repository_id": str(a.repository_id), "status": a.status, "stage": a.stage,
        "progress": a.progress, "error": a.error if a.status == "failed" else "", "trigger": a.trigger,
        "branch": a.branch, "commit_sha": a.commit_sha, "pr_number": a.pr_number,
        "overall_score": a.overall_score, "risk_level": a.risk_level or None,
        "severity_counts": a.severity_counts or {}, "created_at": a.created_at.isoformat(),
        "finished_at": a.finished_at.isoformat() if a.finished_at else None,
        "url": url_for("audits.detail", org_slug=g.org.slug, audit_id=a.id, _external=True),
    }
    if detail and a.status == "succeeded":
        data.update(scores=a.scores, lifecycle=(a.stats or {}).get("lifecycle", {}), tools=a.tool_status,
                    languages=a.languages, ai_summary={k: v for k, v in (a.ai_summary or {}).items()
                                                       if k in ("summary", "top_risks", "error", "model")})
        from .. import policies

        data["gate"] = {**policies.evaluate(a).to_dict(), "policy": a.policy or {}}
        if a.pr_number:
            summary = findings_service.pr_summary(a)
            summary.pop("introduced")
            data["pull_request"] = summary
    return data


def _repo_json(r: Repository) -> dict:
    return {"id": str(r.id), "project_id": str(r.project_id), "name": r.name, "source": r.source,
            "full_name": r.full_name, "default_branch": r.default_branch, "has_credential": r.credential_id is not None}


@bp.get("/me")
@api_auth()
def me():
    return jsonify(organization={"id": str(g.org.id), "slug": g.org.slug, "name": g.org.name},
                   user={"id": str(g.api_token.user_id), "email": g.api_token.user.email}, role=g.membership.role,
                   token={"name": g.api_token.name, "prefix": g.api_token.prefix})


@bp.get("/projects")
@api_auth()
def projects():
    rows = db.session.execute(scoped_select(Project).order_by(Project.name)).scalars()
    return jsonify(projects=[{"id": str(p.id), "name": p.name, "slug": p.slug,
                              "repositories": [_repo_json(r) for r in p.repositories]} for p in rows])


@bp.get("/repositories/<repo_id>")
@api_auth()
def repository(repo_id):
    repo = get_scoped_or_404(Repository, repo_id)
    audits = db.session.execute(scoped_select(Audit).where(Audit.repository_id == repo.id)
                                .order_by(Audit.created_at.desc()).limit(20)).scalars()
    return jsonify(repository=_repo_json(repo), audits=[_audit_json(a) for a in audits])


@bp.post("/repositories/<repo_id>/audits")
@api_auth("member")
def start_audit(repo_id):
    repo = get_scoped_or_404(Repository, repo_id)
    try:
        if repo.source == "upload":
            archive = request.files.get("archive")
            if archive is None:
                return jsonify(error="Send the source as a multipart 'archive' .zip file."), 400
            upload = repo_service.store_upload(g.org, repo, archive, g.api_token.user_id)
            db.session.commit()
            audit = create_audit(g.org, repo, g.api_token.user_id, upload=upload, trigger="api")
        else:
            body = request.get_json(silent=True) or {}
            ref = body.get("ref") if isinstance(body.get("ref"), str) else ""
            audit = create_audit(g.org, repo, g.api_token.user_id, ref=ref, trigger="api")
    except (AuditError, repo_service.RepositoryError) as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 422
    return jsonify(audit=_audit_json(audit)), 202


@bp.post("/repositories/<repo_id>/pulls/<int:number>/audits")
@api_auth("member")
def start_pr_audit(repo_id, number):
    repo = get_scoped_or_404(Repository, repo_id)
    try:
        audit = create_pr_audit(g.org, repo, g.api_token.user_id, number, trigger="pull_request")
    except AuditError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 422
    return jsonify(audit=_audit_json(audit)), 202


@bp.get("/audits/<audit_id>")
@api_auth()
def audit(audit_id):
    return jsonify(audit=_audit_json(get_scoped_or_404(Audit, audit_id), detail=True))


@bp.get("/audits/<audit_id>/findings")
@api_auth()
def findings(audit_id):
    a = get_scoped_or_404(Audit, audit_id)
    if a.status != "succeeded":
        return jsonify(error=f"Audit is {a.status}."), 409
    if request.args.get("introduced") == "1":
        if not a.pr_number:
            return jsonify(error="introduced=1 is only available for pull request audits."), 400
        items = findings_service.pr_introduced(a)
        return jsonify(findings=[findings_service.finding_to_dict(f) for f in items], total=len(items))
    args = {k: request.args.get(k, "") for k in findings_service.FILTERS}
    if "triage" not in request.args:
        args["triage"] = "open"
    if args["severity"] and args["severity"] not in SEVERITY_ORDER:
        return jsonify(error="Unknown severity."), 400
    page = findings_service.filtered_findings(a, args, request.args.get("page", 1, type=int))
    return jsonify(findings=[findings_service.finding_to_dict(f) for f in page.items], page=page.page,
                   pages=page.pages, total=page.total)


@bp.get("/audits/<audit_id>/report.<fmt>")
@api_auth()
def report(audit_id, fmt):
    if fmt not in FORMATS:
        abort(404)
    a = get_scoped_or_404(Audit, audit_id)
    if a.status != "succeeded":
        return jsonify(error=f"Audit is {a.status}."), 409
    body = render(findings_service.report_model(a, include_triaged=request.args.get("all") == "1",
                                                include_dismissed=fmt == "sarif"), fmt)
    return Response(body, headers={"Content-Type": CONTENT_TYPES[fmt]})


@bp.post("/findings/<finding_id>/triage")
@api_auth("member")
def triage(finding_id):
    """Record a triage decision: JSON ``{"status", "reason", "owner", "expires_on": "YYYY-MM-DD"}``."""
    f = get_scoped_or_404(Finding, finding_id)
    body = request.get_json(silent=True) or {}
    text = {k: body.get(k) if isinstance(body.get(k), str) else "" for k in ("status", "reason", "owner", "expires_on")}
    try:
        findings_service.set_triage(g.org, f, text["status"], reason=text["reason"], owner=text["owner"],
                                    expires_on=text["expires_on"] or None, user_id=g.api_token.user_id)
    except findings_service.FindingError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 422
    return jsonify(finding=findings_service.finding_to_dict(f))


@bp.get("/risks")
@api_auth()
def risks():
    """Risk register: accepted risks and false positives in each repository's latest audit, by review date."""
    return jsonify(risks=[{**findings_service.finding_to_dict(f), "audit_id": str(a.id),
                           "repository_id": str(a.repository_id)} for f, a in findings_service.risk_register(g.org)])


@bp.post("/audits/<audit_id>/pr-comment")
@api_auth("member")
def pr_comment(audit_id):
    """Explicit opt-in: post the PR summary as a comment on the pull request."""
    a = get_scoped_or_404(Audit, audit_id)
    if a.status != "succeeded":
        return jsonify(error=f"Audit is {a.status}."), 409
    try:
        url = findings_service.post_pr_comment(
            g.org, a, url_for("audits.detail", org_slug=g.org.slug, audit_id=a.id, _external=True))
    except findings_service.FindingError as exc:
        return jsonify(error=str(exc)), 422
    return jsonify(comment_url=url), 201
