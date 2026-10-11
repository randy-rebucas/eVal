"""Organization security settings: MFA requirement, SSO (OIDC) connection, SCIM tokens, and the audit log."""

from __future__ import annotations

import csv
import io
import json

from flask import Blueprint, Response, flash, g, make_response, redirect, render_template, request, url_for
from flask_login import current_user

from .auth import sso
from .extensions import db
from .models import AuditEvent, ScimToken, SsoConnection, User, utcnow
from .scim import create_token
from .security import crypto, events
from .security.tenancy import get_scoped_or_404, org_required

bp = Blueprint("security_settings", __name__, url_prefix="/o/<org_slug>/settings")
LOG_PAGE = 100


def _domains(text: str) -> list[str]:
    out = []
    for d in (text or "").replace(",", " ").split():
        d = d.strip().lower().lstrip("@")
        if d and "." in d and len(d) <= 253 and all(c.isalnum() or c in "-." for c in d):
            out.append(d)
    return list(dict.fromkeys(out))[:50]


@bp.route("/security", methods=["GET", "POST"])
@org_required("admin")
def security(org_slug):
    conn = sso.connection_for(g.org)
    new_token = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "mfa":
            g.org.require_mfa = request.form.get("require_mfa") == "on"
            if g.org.require_mfa and not current_user.mfa_enabled:
                g.org.require_mfa = False
                flash("Turn on two-factor authentication for your own account first, so you are not locked out.",
                      "danger")
            else:
                events.record("org.mfa_policy", organization_id=g.org.id, required=g.org.require_mfa)
                flash("MFA requirement saved.", "success")
            db.session.commit()
        elif action == "sandbox":
            g.org.allow_sandbox = request.form.get("allow_sandbox") == "on"
            events.record("org.sandbox_policy", organization_id=g.org.id, allowed=g.org.allow_sandbox)
            db.session.commit()
            flash("Sandbox terminals " + ("allowed." if g.org.allow_sandbox else "turned off."), "success")
        elif action == "sso":
            try:
                issuer = sso.validate_issuer(request.form.get("issuer", ""))
                client_id = request.form.get("client_id", "").strip()[:255]
                secret = request.form.get("client_secret", "").strip()
                if not client_id or (conn is None and not secret):
                    raise sso.SSOError("Client ID and client secret are required.")
                domains = _domains(request.form.get("domains", ""))
                if not domains:
                    raise sso.SSOError("List at least one email domain this identity provider is authoritative for.")
                sso.discovery(issuer)  # fail now rather than at the first sign-in
            except sso.SSOError as exc:
                flash(f"SSO not saved: {exc}", "danger")
                return redirect(url_for("security_settings.security", org_slug=org_slug))
            role = request.form.get("default_role", "member")
            if conn is None:
                conn = SsoConnection(organization_id=g.org.id, issuer=issuer, client_id=client_id,
                                     encrypted_client_secret=crypto.encrypt(secret))
                db.session.add(conn)
            conn.issuer, conn.client_id, conn.domains = issuer, client_id, domains
            if secret:
                conn.encrypted_client_secret = crypto.encrypt(secret)
            conn.default_role = role if role in ("viewer", "member", "admin") else "member"
            conn.auto_provision = request.form.get("auto_provision") == "on"
            conn.enforce = request.form.get("enforce") == "on"
            conn.enabled = request.form.get("enabled") == "on"
            db.session.flush()
            events.record("org.sso_configured", organization_id=g.org.id, target=conn, issuer=issuer,
                          enforce=conn.enforce, enabled=conn.enabled)
            db.session.commit()
            flash("Single sign-on saved.", "success")
        elif action == "sso_delete" and conn is not None:
            events.record("org.sso_removed", organization_id=g.org.id, target=conn)
            db.session.delete(conn)
            db.session.commit()
            flash("Single sign-on removed.", "success")
        elif action == "scim_token":
            _, new_token = create_token(g.org, current_user.id)
        if new_token is None:
            return redirect(url_for("security_settings.security", org_slug=org_slug))
        conn = sso.connection_for(g.org)
    tokens = db.session.execute(db.select(ScimToken).where(ScimToken.organization_id == g.org.id)
                                .order_by(ScimToken.created_at.desc())).scalars().all()
    resp = make_response(render_template("settings/security.html", conn=conn, tokens=tokens, new_token=new_token,
                                         sso_url=url_for("sso.start_org", org_slug=g.org.slug, _external=True),
                                         callback_url=url_for("sso.callback", _external=True),
                                         scim_url=url_for("scim.users", _external=True).rsplit("/Users", 1)[0]))
    if new_token:
        resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.post("/security/scim-tokens/<token_id>/revoke")
@org_required("admin")
def revoke_scim(org_slug, token_id):
    token = get_scoped_or_404(ScimToken, token_id)
    if token.revoked_at is None:
        token.revoked_at = utcnow()
        events.record("scim.token_revoked", organization_id=g.org.id, target=token)
        db.session.commit()
    flash("SCIM token revoked.", "success")
    return redirect(url_for("security_settings.security", org_slug=org_slug))


def _log_query():
    q = db.select(AuditEvent).where(AuditEvent.organization_id == g.org.id)
    action = request.args.get("action", "").strip()
    if action:
        q = q.where(AuditEvent.action.startswith(action[:64]))
    return q.order_by(AuditEvent.created_at.desc())


@bp.get("/audit-log")
@org_required("admin")
def audit_log(org_slug):
    page = db.paginate(_log_query(), page=request.args.get("page", 1, type=int), per_page=LOG_PAGE,
                       error_out=False)
    actors = {u.id: u.email for u in db.session.execute(db.select(User).where(
        User.id.in_({e.actor_id for e in page.items if e.actor_id}))).scalars()} if page.items else {}
    return render_template("settings/audit_log.html", page=page, actors=actors,
                           action=request.args.get("action", ""))


@bp.get("/audit-log.csv")
@org_required("admin")
def audit_log_csv(org_slug):
    rows = db.session.execute(_log_query().limit(50_000)).scalars().all()
    actors = {u.id: u.email for u in db.session.execute(db.select(User).where(
        User.id.in_({e.actor_id for e in rows if e.actor_id}))).scalars()} if rows else {}
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["time", "action", "actor", "target_type", "target_id", "ip", "details"])
    for e in rows:
        cells = [e.created_at.isoformat(), e.action, actors.get(e.actor_id, ""), e.target_type, e.target_id, e.ip,
                 json.dumps(e.details, sort_keys=True)]
        w.writerow(["'" + c if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in cells])
    events.record("audit_log.exported", organization_id=g.org.id, rows=len(rows))
    db.session.commit()
    resp = Response(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="eval-audit-log-{g.org.slug}.csv"'
    return resp
