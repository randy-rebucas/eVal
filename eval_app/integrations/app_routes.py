"""GitHub App routes: the webhook receiver, and installing the App for an organization.

Linking an installation to an organization is the security-critical step: GitHub's setup redirect carries an
``installation_id`` anyone could forge, so the callback requires the user-authorization ``code`` GitHub sends when the
App has "Request user authorization (OAuth) during installation" enabled, and checks that the signed-in GitHub
user can actually access that installation before linking it.
"""

from __future__ import annotations

import hmac
import json
import secrets
import time

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, request, session, url_for
from flask_login import current_user, login_required
from flask_wtf.csrf import validate_csrf
from wtforms.validators import ValidationError

from ..extensions import db
from ..models import GitHubInstallation
from ..security.tenancy import get_scoped_or_404, load_membership, org_required, role_at_least
from . import app_events, github, github_app, services

STATE_KEY = "github_app_install"
STATE_MAX_AGE = 1800
MAX_WEBHOOK_BYTES = 5 * 1024 * 1024

webhook_bp = Blueprint("github_webhook", __name__)
setup_bp = Blueprint("github_app", __name__, url_prefix="/integrations/github/app")
org_bp = Blueprint("github_app_org", __name__, url_prefix="/o/<org_slug>/settings/github-app")


@webhook_bp.post("/webhooks/github")
def webhook():
    if not github_app.enabled():
        abort(404)
    body = request.get_data(cache=False)
    if len(body) > MAX_WEBHOOK_BYTES:
        abort(413)
    if not github_app.verify_signature(body, request.headers.get("X-Hub-Signature-256", "")):
        abort(401)
    try:
        payload = json.loads(body)
    except ValueError:
        abort(400)
    if not isinstance(payload, dict):
        abort(400)
    event = request.headers.get("X-GitHub-Event", "")
    result = app_events.handle(event, payload)
    return jsonify(result), 202


@org_bp.get("/install")
@org_required("admin")
def install(org_slug):
    # A link (CSP form-action would block a cross-site form redirect); the CSRF token in the query stops another
    # site from starting an installation flow bound to this organization.
    if current_app.config.get("WTF_CSRF_ENABLED", True):
        try:
            validate_csrf(request.args.get("csrf", ""))
        except ValidationError:
            abort(400)
    if not github_app.enabled() or not current_app.config.get("GITHUB_APP_SLUG"):
        flash("The GitHub App is not configured on this server.", "danger")
        return redirect(url_for("integrations.index", org_slug=org_slug))
    state = secrets.token_urlsafe(32)
    session[STATE_KEY] = {"state": state, "org": org_slug, "at": int(time.time())}
    return redirect(github_app.install_url(state))


@org_bp.post("/<inst_id>/unlink")
@org_required("admin")
def unlink(org_slug, inst_id):
    inst = get_scoped_or_404(GitHubInstallation, inst_id)
    app_events.remove_installation(inst, "github_app.unlinked")
    db.session.commit()
    flash("GitHub App installation unlinked. Uninstall it on GitHub to revoke its access completely.", "success")
    return redirect(url_for("integrations.index", org_slug=org_slug))


@setup_bp.get("/setup")
@login_required
def setup():
    pending = session.pop(STATE_KEY, None) or {}
    state = request.args.get("state", "")
    if not pending.get("state") or not hmac.compare_digest(pending["state"], state) \
            or time.time() - pending.get("at", 0) > STATE_MAX_AGE:
        flash("The GitHub App installation could not be matched to an organization. Start again from "
              "Settings → Integrations.", "danger")
        return redirect(url_for("orgs.list_orgs"))
    found = load_membership(current_user.id, pending["org"])
    if not found or not role_at_least(found[1].role, "admin"):
        abort(403)
    org = found[0]
    back = url_for("integrations.index", org_slug=org.slug)
    try:
        installation_id = int(request.args.get("installation_id", ""))
    except ValueError:
        flash("GitHub did not report an installation.", "danger")
        return redirect(back)
    cfg = current_app.config
    code = request.args.get("code", "")
    if not code or not cfg.get("GITHUB_APP_CLIENT_ID") or not cfg.get("GITHUB_APP_CLIENT_SECRET"):
        flash("Enable “Request user authorization (OAuth) during installation” on the GitHub App and set "
              "GITHUB_APP_CLIENT_ID / GITHUB_APP_CLIENT_SECRET, so eVal can verify the installation.", "danger")
        return redirect(back)
    try:
        token = github.exchange_oauth_code(services.github_web_url(), cfg["GITHUB_APP_CLIENT_ID"],
                                           cfg["GITHUB_APP_CLIENT_SECRET"], code,
                                           url_for("github_app.setup", _external=True))
        if installation_id not in services.github_client_for_token(token).user_installation_ids():
            flash("Your GitHub account cannot access that installation.", "danger")
            return redirect(back)
        inst = app_events.link_installation(org, installation_id, current_user.id)
    except (github.GitHubError, ValueError) as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(back)
    flash(f"GitHub App installed for {inst.account_login}. Pull requests in its repositories are now audited "
          "automatically.", "success")
    return redirect(back)


def installations_for(org) -> list[GitHubInstallation]:
    return list(db.session.execute(
        db.select(GitHubInstallation).where(GitHubInstallation.organization_id == org.id)
        .order_by(GitHubInstallation.created_at)).scalars())
