from __future__ import annotations

from flask import Blueprint, flash, g, jsonify, redirect, render_template, url_for

from ..extensions import db
from ..models import Audit
from ..security.tenancy import get_scoped_or_404, org_required
from . import services

bp = Blueprint("audits", __name__, url_prefix="/o/<org_slug>/audits")


@bp.get("/<audit_id>")
@org_required()
def detail(org_slug, audit_id):
    audit = get_scoped_or_404(Audit, audit_id)
    return render_template("audits/detail.html", audit=audit)


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
