"""SSO sign-in routes: start from an email address or an organization, the OIDC callback, linking."""

from __future__ import annotations

import hmac
import time
import uuid

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user

from ..extensions import db
from ..models import Organization, SsoConnection
from ..security import events, ratelimit
from . import sso
from .mfa import complete_login

bp = Blueprint("sso", __name__)
SESSION_KEY = "sso_pending"
MAX_AGE = 600


def _start(conn: SsoConnection, link: bool, next_url: str | None = None):
    if not conn.enabled:
        abort(404)
    if not ratelimit.hit("sso", request.remote_addr or "?", 30, 300):
        abort(429)
    try:
        url, pending = sso.begin(conn, url_for("sso.callback", _external=True))
    except sso.SSOError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("sso.start"))
    pending["link_user"] = str(current_user.id) if link and current_user.is_authenticated else None
    pending["next"] = next_url if next_url and next_url.startswith("/o/") else None
    session[SESSION_KEY] = pending
    return redirect(url)


@bp.route("/sso", methods=["GET", "POST"])
def start():
    if request.method == "POST":
        conn = sso.connection_for_email(request.form.get("email", ""))
        if conn is None:
            flash("No single sign-on is set up for that email domain.", "warning")
            return redirect(url_for("sso.start"))
        return _start(conn, link=False)
    return render_template("auth/sso.html")


@bp.get("/sso/o/<org_slug>")
def start_org(org_slug):
    org = db.session.execute(db.select(Organization).where(Organization.slug == org_slug)).scalar_one_or_none()
    conn = sso.connection_for(org) if org else None
    if conn is None or not conn.enabled:
        abort(404)
    return _start(conn, link=request.args.get("link") == "1", next_url=request.args.get("next"))


@bp.get("/sso/callback")
def callback():
    pending = session.pop(SESSION_KEY, None) or {}
    if not pending.get("state") or not hmac.compare_digest(pending["state"], request.args.get("state", "")) \
            or time.time() - pending.get("at", 0) > MAX_AGE:
        flash("Single sign-on expired or did not match. Please try again.", "danger")
        return redirect(url_for("sso.start"))
    conn = db.session.get(SsoConnection, uuid.UUID(pending["conn"]))
    if conn is None or not conn.enabled:
        abort(404)
    linking = None
    if pending.get("link_user"):
        if not current_user.is_authenticated or str(current_user.id) != pending["link_user"]:
            abort(403)
        linking = current_user._get_current_object()
    if request.args.get("error"):
        flash("Single sign-on was cancelled.", "warning")
        return redirect(url_for("sso.start"))
    org = db.session.get(Organization, conn.organization_id)
    try:
        token = sso.exchange(conn, request.args.get("code", ""), url_for("sso.callback", _external=True),
                             pending["verifier"])
        claims = sso.verify_id_token(conn, token, pending["nonce"])
        user = sso.resolve_user(conn, claims, linking_user=linking)
        db.session.flush()
    except sso.SSOError as exc:
        db.session.rollback()
        events.record("auth.login_failed", organization_id=org.id, method="sso")
        db.session.commit()
        flash(str(exc), "danger")
        return redirect(url_for("auth.account") if linking else url_for("sso.start"))
    if linking:
        events.record("auth.sso_linked", organization_id=org.id, target=user)
        db.session.commit()
    return complete_login(user, "sso", pending.get("next") or url_for("orgs.dashboard", org_slug=org.slug),
                          sso_org=str(org.id))
