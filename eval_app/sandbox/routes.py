from __future__ import annotations

from urllib.parse import urlsplit

from flask import Blueprint, abort, current_app, flash, g, jsonify, make_response, redirect, render_template, url_for
from flask_login import current_user

from ..extensions import db
from ..models import FixProposal, SandboxSession
from ..security.tenancy import get_scoped_or_404, org_required
from . import services

bp = Blueprint("sandbox", __name__, url_prefix="/o/<org_slug>")


def _own_session(session_id) -> SandboxSession:
    """A terminal is personal: only the member who opened it may see, use or save from it."""
    session = get_scoped_or_404(SandboxSession, session_id)
    if session.user_id != current_user.id:
        abort(404)
    return session


@bp.post("/fixes/<fix_id>/sandbox")
@org_required("member")
def open_terminal(org_slug, fix_id):
    proposal = get_scoped_or_404(FixProposal, fix_id)
    try:
        session = services.open_session(g.org, proposal, current_user)
    except services.SandboxError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(url_for("fixes.detail", org_slug=org_slug, fix_id=proposal.id))
    return redirect(url_for("sandbox.terminal", org_slug=org_slug, session_id=session.id))


XTERM = "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/"
XTERM_FIT = "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/"


def terminal_csp() -> str:
    """The app-wide policy, plus xterm (pinned, with SRI in the page), the sandbox websocket origin, and inline
    styles, which xterm's renderer injects. Only this page gets it."""
    parts = urlsplit(current_app.config["SANDBOX_PUBLIC_URL"])
    ws_origin = f"{parts.scheme}://{parts.netloc}"
    bootstrap = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/"
    icons = "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/"
    return (
        "default-src 'self'; "
        f"style-src 'self' 'unsafe-inline' {bootstrap} {icons} {XTERM}; "
        f"script-src 'self' {bootstrap} {XTERM} {XTERM_FIT}; "
        f"connect-src 'self' {ws_origin}; "
        f"img-src 'self' data:; font-src 'self' {icons}; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )


@bp.get("/sandbox/<session_id>")
@org_required("member")
def terminal(org_slug, session_id):
    session = _own_session(session_id)
    resp = make_response(render_template("sandbox/terminal.html", session=session, fix=session.fix,
                                         audit=session.fix.audit))
    resp.headers["Content-Security-Policy"] = terminal_csp()
    return resp


@bp.get("/sandbox/<session_id>/status")
@org_required("member")
def status(org_slug, session_id):
    session = _own_session(session_id)
    # Shaped like the audit status endpoint so the same progress poller drives the page while it prepares.
    done = {"ready": "succeeded", "failed": "failed", "ended": "cancelled"}
    return jsonify(status=done.get(session.status, "running"), progress=40, stage="preparing the workspace")


@bp.post("/sandbox/<session_id>/token")
@org_required("member")
def token(org_slug, session_id):
    session = _own_session(session_id)
    try:
        return jsonify(services.terminal_token(session, current_user))
    except services.SandboxError as exc:
        return jsonify(error=str(exc)), 410


@bp.post("/sandbox/<session_id>/save")
@org_required("member")
def save(org_slug, session_id):
    session = _own_session(session_id)
    try:
        revision = services.save_back(g.org, session, current_user)
        flash(f"Saved the terminal's files as revision {revision}. eVal re-audits them now.", "success")
    except services.SandboxError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("sandbox.terminal", org_slug=org_slug, session_id=session.id))


@bp.post("/sandbox/<session_id>/end")
@org_required("member")
def end(org_slug, session_id):
    session = _own_session(session_id)
    services.end_session(session, current_user)
    flash("Terminal ended. Its container and files are gone.", "success")
    return redirect(url_for("fixes.detail", org_slug=org_slug, fix_id=session.fix_id))
