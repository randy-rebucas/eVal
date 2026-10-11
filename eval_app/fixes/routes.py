from __future__ import annotations

import re

from flask import Blueprint, Response, abort, flash, g, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

from ..extensions import db
from ..models import Audit, Finding, FixProposal
from ..security.tenancy import get_scoped_or_404, org_required, parse_uuid_or_404
from . import services

bp = Blueprint("fixes", __name__, url_prefix="/o/<org_slug>")


@bp.post("/audits/<audit_id>/fixes")
@org_required("member")
def create(org_slug, audit_id):
    audit = get_scoped_or_404(Audit, audit_id)
    ids = [parse_uuid_or_404(x) for x in request.form.getlist("finding_ids")][:100]
    back = request.form.get("next_url") or ""
    back = back if back.startswith(f"/o/{org_slug}/") else url_for("audits.detail", org_slug=org_slug,
                                                                     audit_id=audit.id)
    if not ids:
        flash("Select the findings to fix.", "danger")
        return redirect(back)
    try:
        proposal = services.create_proposal(g.org, audit, ids, current_user.id)
    except services.FixError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(back)
    return redirect(url_for("fixes.detail", org_slug=org_slug, fix_id=proposal.id))


@bp.get("/fixes/<fix_id>")
@org_required()
def detail(org_slug, fix_id):
    proposal = get_scoped_or_404(FixProposal, fix_id)
    findings = {str(f.id): f for f in services.proposal_findings(proposal)}
    return render_template("fixes/detail.html", fix=proposal, audit=proposal.audit, findings=findings,
                           diff_lines=proposal.diff.splitlines(), verification=proposal.verification or {},
                           revision=services.current_revision(proposal),
                           ide_links=services.ide_links(proposal), ide_branch=services.ide_branch(proposal),
                           max_kb=services.MAX_SOURCE_BYTES // 1024)


STAGES = {"running": (50, "generating fix"), "verifying": (60, "re-auditing your edit"), "queued": (10, "queued")}


@bp.get("/fixes/<fix_id>/status")
@org_required()
def status(org_slug, fix_id):
    proposal = get_scoped_or_404(FixProposal, fix_id)
    # Shaped like the audit status endpoint so the same progress poller drives the page.
    done = {"ready": "succeeded", "pr_opened": "succeeded", "failed": "failed"}
    progress, stage = STAGES.get(proposal.status, STAGES["queued"])
    return jsonify(status=done.get(proposal.status, proposal.status), progress=progress, stage=stage)


@bp.post("/fixes/<fix_id>/files")
@org_required("member")
def edit(org_slug, fix_id):
    proposal = get_scoped_or_404(FixProposal, fix_id)
    # The form is multipart (one part per file), so its in-memory limit is per file: see LARGE_FORM_ENDPOINTS.
    paths, contents = request.form.getlist("path"), request.form.getlist("content")
    try:
        base = int(request.form.get("revision", ""))
    except ValueError:
        abort(400)
    if len(paths) != len(contents) or len(paths) != len(set(paths)):
        abort(400)
    try:
        services.save_edits(g.org, proposal, dict(zip(paths, contents, strict=True)), base, current_user)
        flash("Edit saved. eVal re-audits the changed files now.", "success")
    except services.FixError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("fixes.detail", org_slug=org_slug, fix_id=proposal.id))


@bp.get("/fixes/<fix_id>/revisions/<int:number>.patch")
@org_required()
def revision_patch(org_slug, fix_id, number):
    proposal = get_scoped_or_404(FixProposal, fix_id)
    rev = next((r for r in proposal.revisions or [] if r.get("number") == number), None)
    if rev is None or not rev.get("diff"):
        abort(404)
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", proposal.audit.repository.name)[:60]
    resp = Response(rev["diff"], mimetype="text/x-diff")
    resp.headers["Content-Disposition"] = (f'attachment; filename="eval-fix-{name}-{proposal.id.hex[:8]}'
                                           f'-r{number}.patch"')
    return resp


@bp.post("/fixes/<fix_id>/pull-request")
@org_required("member")
def pull_request(org_slug, fix_id):
    proposal = get_scoped_or_404(FixProposal, fix_id)
    try:
        url = services.open_pull_request(g.org, proposal, current_user.id,
                                         accept_regression=request.form.get("accept_regression") == "on")
        flash(f"Opened pull request #{proposal.pr_number}: {url}", "success")
    except services.FixError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("fixes.detail", org_slug=org_slug, fix_id=proposal.id))


@bp.get("/fixes/<fix_id>.patch")
@org_required()
def patch(org_slug, fix_id):
    proposal = get_scoped_or_404(FixProposal, fix_id)
    if not proposal.diff:
        abort(404)
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", proposal.audit.repository.name)[:60]
    resp = Response(proposal.diff, mimetype="text/x-diff")
    resp.headers["Content-Disposition"] = f'attachment; filename="eval-fix-{name}-{proposal.id.hex[:8]}.patch"'
    return resp


@bp.post("/findings/<finding_id>/fix")
@org_required("member")
def fix_one(org_slug, finding_id):
    finding = get_scoped_or_404(Finding, finding_id)
    try:
        proposal = services.create_proposal(g.org, finding.audit, [finding.id], current_user.id)
    except services.FixError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(url_for("findings.detail", org_slug=org_slug, finding_id=finding.id))
    return redirect(url_for("fixes.detail", org_slug=org_slug, fix_id=proposal.id))
