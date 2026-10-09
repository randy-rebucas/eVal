from __future__ import annotations

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from flask_login import current_user

from ..extensions import db
from ..models import TRIAGE_STATUSES, Audit, Finding
from ..security.tenancy import get_scoped_or_404, org_required, parse_uuid_or_404
from . import services

bp = Blueprint("findings", __name__, url_prefix="/o/<org_slug>")


@bp.get("/findings/<finding_id>")
@org_required()
def detail(org_slug, finding_id):
    finding = get_scoped_or_404(Finding, finding_id)
    issue = services.issue_links_for(finding.audit).get(finding.fingerprint)
    history = db.session.execute(
        db.select(Finding, Audit).join(Audit, Audit.id == Finding.audit_id)
        .where(Finding.fingerprint == finding.fingerprint, Finding.organization_id == g.org.id,
               Audit.repository_id == finding.audit.repository_id)
        .order_by(Audit.created_at.desc()).limit(20)
    ).all()
    return render_template("findings/detail.html", f=finding, audit=finding.audit, issue=issue, history=history,
                           triage_statuses=TRIAGE_STATUSES)


@bp.post("/findings/<finding_id>/triage")
@org_required("member")
def triage(org_slug, finding_id):
    finding = get_scoped_or_404(Finding, finding_id)
    try:
        services.set_triage(g.org, finding, request.form.get("status", ""))
        flash("Triage status updated.", "success")
    except services.FindingError as exc:
        flash(str(exc), "danger")
    return redirect(request.form.get("next_url") if (request.form.get("next_url") or "").startswith("/o/")
                    else url_for("findings.detail", org_slug=org_slug, finding_id=finding.id))


@bp.post("/audits/<audit_id>/issues")
@org_required("member")
def create_issues(org_slug, audit_id):
    audit = get_scoped_or_404(Audit, audit_id)
    ids = [parse_uuid_or_404(x) for x in request.form.getlist("finding_ids")][:100]
    if not ids:
        abort(400)
    try:
        result = services.create_github_issues(g.org, audit, ids, current_user.id)
    except services.FindingError as exc:
        flash(str(exc), "danger")
    else:
        if result["created"]:
            flash(f"Created {len(result['created'])} GitHub issue(s).", "success")
        if result["skipped"]:
            flash(f"{len(result['skipped'])} finding(s) already had an issue; skipped.", "info")
        for err in result["errors"][:5]:
            flash(f"GitHub error: {err}", "danger")
    return redirect(url_for("audits.detail", org_slug=org_slug, audit_id=audit.id))
