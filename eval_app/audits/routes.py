from __future__ import annotations

import re

from flask import Blueprint, Response, abort, flash, g, jsonify, redirect, render_template, request, url_for

from eval_engine.findings import CATEGORY_LABELS, SEVERITY_ORDER, Category
from eval_engine.reports import CONTENT_TYPES, FORMATS, render

from ..extensions import db
from ..findings import services as findings_service
from ..models import Audit
from ..security import events
from ..security.tenancy import get_scoped_or_404, org_required
from . import services

bp = Blueprint("audits", __name__, url_prefix="/o/<org_slug>/audits")


def _history(audit: Audit, limit: int = 20) -> list[Audit]:
    return list(reversed(db.session.execute(
        db.select(Audit).where(Audit.repository_id == audit.repository_id, Audit.organization_id == g.org.id,
                               Audit.status == "succeeded", Audit.created_at <= audit.created_at)
        .order_by(Audit.created_at.desc()).limit(limit)
    ).scalars().all()))


@bp.get("/<audit_id>")
@org_required()
def detail(org_slug, audit_id):
    audit = get_scoped_or_404(Audit, audit_id)
    ctx = {"audit": audit, "category_labels": {c.value: CATEGORY_LABELS[c] for c in Category}}
    if audit.status == "succeeded":
        args = {k: request.args.get(k, "") for k in findings_service.FILTERS}
        if "triage" not in request.args:
            args["triage"] = "open"
        page = request.args.get("page", 1, type=int)
        ctx.update(
            page=findings_service.filtered_findings(audit, args, page),
            filters=args,
            issue_links=findings_service.issue_links_for(audit),
            history=_history(audit),
            severity_order=SEVERITY_ORDER,
            triaged_count=sum(1 for f in audit.findings if f.triage_status != "open"),
        )
    return render_template("audits/detail.html", **ctx)


@bp.get("/<audit_id>/status")
@org_required()
def status(org_slug, audit_id):
    audit = get_scoped_or_404(Audit, audit_id)
    return jsonify(status=audit.status, stage=audit.stage, progress=audit.progress,
                   error=audit.error if audit.status == "failed" else "")


@bp.post("/<audit_id>/cancel")
@org_required("member")
def cancel(org_slug, audit_id):
    audit = get_scoped_or_404(Audit, audit_id)
    try:
        services.cancel_audit(g.org, audit)
        flash("Audit cancelled.", "success")
    except services.AuditError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("audits.detail", org_slug=org_slug, audit_id=audit.id))


@bp.get("/<audit_id>/report.<fmt>")
@org_required()
def report(org_slug, audit_id, fmt):
    if fmt not in FORMATS:
        abort(404)
    audit = get_scoped_or_404(Audit, audit_id)
    if audit.status != "succeeded":
        abort(404)
    include_triaged = request.args.get("all") == "1"
    body = render(findings_service.report_model(audit, include_triaged=include_triaged), fmt)
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", audit.repository.name)[:60]
    ext = {"md": "md", "json": "json", "html": "html", "sarif": "sarif"}[fmt]
    resp = Response(body, mimetype=CONTENT_TYPES[fmt].split(";")[0])
    resp.headers["Content-Type"] = CONTENT_TYPES[fmt]
    resp.headers["Content-Disposition"] = f'attachment; filename="eval-{name}-{str(audit.id)[:8]}.{ext}"'
    # The HTML report carries its own inline CSS and no scripts.
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    events.record("report.exported", organization_id=g.org.id, target=audit, format=fmt)
    db.session.commit()
    return resp


@bp.get("/<audit_id>/compare")
@org_required()
def compare(org_slug, audit_id):
    head = get_scoped_or_404(Audit, audit_id)
    base_id = request.args.get("base") or (str(head.previous_audit_id) if head.previous_audit_id else None)
    if not base_id:
        flash("There is no earlier successful audit to compare with.", "info")
        return redirect(url_for("audits.detail", org_slug=org_slug, audit_id=head.id))
    base = get_scoped_or_404(Audit, base_id)
    if base.status != "succeeded" or head.status != "succeeded":
        abort(404)
    try:
        cmp = findings_service.compare(base, head)
    except findings_service.FindingError:
        abort(404)
    options = _history(head, limit=50)
    return render_template("audits/compare.html", cmp=cmp, options=options,
                           category_labels={c.value: CATEGORY_LABELS[c] for c in Category})
