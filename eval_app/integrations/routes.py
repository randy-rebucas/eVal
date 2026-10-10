from __future__ import annotations

import hmac
import secrets
import time
from urllib.parse import urlencode

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.csrf import validate_csrf
from werkzeug.exceptions import NotFound
from wtforms import PasswordField, SelectField, StringField
from wtforms.validators import DataRequired, Length, ValidationError

from eval_engine.ai import MODEL_SUGGESTIONS, PROVIDERS

from .. import ai_config
from ..api.auth import create_token, revoke_token
from ..extensions import db
from ..models import ApiToken, IntegrationCredential, Project
from ..security import events, ratelimit
from ..security.tenancy import get_scoped_or_404, load_membership, org_required, role_at_least
from . import github, github_app, services
from .app_routes import installations_for

bp = Blueprint("integrations", __name__, url_prefix="/o/<org_slug>/settings")


class CredentialForm(FlaskForm):
    provider = SelectField("Provider", choices=list(services.PROVIDERS.items()))
    label = StringField("Label", validators=[Length(max=120)])
    secret = PasswordField("Token / API key", validators=[DataRequired(), Length(min=8, max=4096)])


@bp.route("/integrations", methods=["GET", "POST"])
@org_required("viewer")
def index(org_slug):
    form = CredentialForm()
    can_manage = g.membership.role in ("admin", "owner")
    if form.is_submitted():
        if not can_manage:
            flash("Only admins can manage integrations.", "danger")
        elif form.validate():
            try:
                services.add_credential(g.org, form.provider.data, form.label.data or "", form.secret.data,
                                        current_user.id)
                flash("Credential saved (encrypted).", "success")
            except services.CredentialError as exc:
                db.session.rollback()
                flash(str(exc), "danger")
        return redirect(url_for("integrations.index", org_slug=org_slug))
    creds = services.org_credentials(g.org)
    return render_template("integrations/index.html", creds=creds, form=form, can_manage=can_manage,
                           ai=ai_config.get_settings(g.org.id), ai_providers=PROVIDERS,
                           ai_models=MODEL_SUGGESTIONS, gh_oauth=services.github_oauth_enabled(),
                           ai_base_urls=ai_config.allowed_base_urls(),
                           ai_creds=[c for c in creds if c.provider in PROVIDERS],
                           installations=installations_for(g.org), gh_app=github_app.enabled())


@bp.post("/ai")
@org_required("admin")
def save_ai(org_slug):
    f = request.form
    try:
        ai_config.save_settings(
            g.org, enabled=f.get("enabled") == "on", provider=f.get("provider", ""),
            # "model" is the picker; its "Other…" entry is empty and defers to the typed-in name.
            model=f.get("model") or f.get("model_custom", ""),
            base_url=f.get("base_url", ""), credential_id=f.get("credential_id") or None,
            max_findings=f.get("max_findings", type=int) or 15,
        )
        flash("AI settings saved.", "success")
    except ai_config.AISettingsError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("integrations.index", org_slug=org_slug))


@bp.post("/ai/models")
@org_required("admin")
def ai_models(org_slug):
    # Each call decrypts a key and makes an outbound request, so it is throttled per org.
    if not ratelimit.hit("ai-models", str(g.org.id), 30, 300):
        return jsonify(error="Too many model lookups; try again in a few minutes."), 429
    f = request.form
    try:
        models = ai_config.fetch_models(g.org, provider=f.get("provider", ""),
                                        credential_id=f.get("credential_id") or None,
                                        base_url=f.get("base_url", ""))
    except ai_config.AISettingsError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(models=models)


OAUTH_SESSION_KEY = "gh_oauth"
OAUTH_MAX_AGE = 600  # seconds the user has to finish signing in on GitHub


def _safe_next(org_slug: str) -> str:
    """Where to land after connecting: the add-repository page of a project in this org, else Integrations."""
    project_id = request.args.get("project_id", "")
    try:
        project = get_scoped_or_404(Project, project_id) if project_id else None
    except NotFound:
        project = None
    return url_for("repos.new", org_slug=org_slug, project_id=project.id) if project else \
        url_for("integrations.index", org_slug=org_slug)


@bp.get("/github/connect")
@org_required("admin")
def github_connect(org_slug):
    # A link, not a form: CSP form-action 'self' would block the cross-site redirect. The CSRF token in the
    # query keeps another site from silently binding the admin's GitHub account to this organization.
    if current_app.config.get("WTF_CSRF_ENABLED", True):
        try:
            validate_csrf(request.args.get("csrf", ""))
        except ValidationError:
            abort(400)
    nxt = _safe_next(org_slug)
    if not services.github_oauth_enabled():
        flash("GitHub sign-in is not configured. Set GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET.",
              "danger")
        return redirect(nxt)
    state = secrets.token_urlsafe(32)
    session[OAUTH_SESSION_KEY] = {"state": state, "org": org_slug, "next": nxt, "at": int(time.time())}
    return redirect(github.oauth_authorize_url(
        services.github_web_url(), current_app.config["GITHUB_OAUTH_CLIENT_ID"],
        url_for("github_oauth.callback", _external=True), state))


oauth_bp = Blueprint("github_oauth", __name__, url_prefix="/integrations/github")


@oauth_bp.get("/callback")
@login_required
def callback():
    pending = session.pop(OAUTH_SESSION_KEY, None) or {}
    state = request.args.get("state", "")
    if not pending.get("state") or not hmac.compare_digest(pending["state"], state) \
            or time.time() - pending.get("at", 0) > OAUTH_MAX_AGE:
        flash("GitHub sign-in expired or did not match. Please try connecting again.", "danger")
        return redirect(url_for("orgs.list_orgs"))
    found = load_membership(current_user.id, pending["org"])
    if not found or not role_at_least(found[1].role, "admin"):
        abort(403)
    org = found[0]
    nxt = pending["next"]
    if request.args.get("error"):  # the user pressed Cancel on GitHub
        flash("GitHub connection was cancelled.", "warning")
        return redirect(nxt)
    cfg = current_app.config
    try:
        token = github.exchange_oauth_code(services.github_web_url(), cfg["GITHUB_OAUTH_CLIENT_ID"],
                                           cfg["GITHUB_OAUTH_CLIENT_SECRET"], request.args.get("code", ""),
                                           url_for("github_oauth.callback", _external=True))
        cred = services.save_github_oauth_token(org, token, current_user.id)
    except (github.GitHubError, services.CredentialError) as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(nxt)
    flash(f"Connected {cred.label}.", "success")
    if "/repos/new" in nxt:
        nxt += "?" + urlencode({"browse": 1, "credential_id": cred.id})
    return redirect(nxt)


@bp.route("/tokens", methods=["GET", "POST"])
@org_required("viewer")
def tokens(org_slug):
    new_token = None
    if request.method == "POST":
        _, new_token = create_token(g.org, current_user, request.form.get("name", ""))
    mine = db.session.execute(
        db.select(ApiToken).where(ApiToken.organization_id == g.org.id, ApiToken.user_id == current_user.id)
        .order_by(ApiToken.created_at.desc())
    ).scalars().all()
    # The plaintext token is rendered once in this response and never stored or flashed into the session.
    resp = make_response(render_template("integrations/tokens.html", tokens=mine, new_token=new_token))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.post("/tokens/<token_id>/revoke")
@org_required("viewer")
def revoke(org_slug, token_id):
    token = get_scoped_or_404(ApiToken, token_id)
    if token.user_id != current_user.id and g.membership.role not in ("admin", "owner"):
        abort(404)
    revoke_token(g.org, token)
    flash("Token revoked.", "success")
    return redirect(url_for("integrations.tokens", org_slug=org_slug))


@bp.post("/integrations/<cred_id>/delete")
@org_required("admin")
def delete(org_slug, cred_id):
    cred = get_scoped_or_404(IntegrationCredential, cred_id)
    services.delete_credential(g.org, cred)
    flash("Credential deleted.", "success")
    return redirect(url_for("integrations.index", org_slug=org_slug))


@bp.route("/policy", methods=["GET", "POST"])
@org_required("viewer")
def policy(org_slug):
    from eval_engine.policy import PolicyError

    from .. import policies
    from ..models import Repository

    can_manage = g.membership.role in ("admin", "owner")
    repo = get_scoped_or_404(Repository, request.values["repo"]) if request.values.get("repo") else None
    if request.method == "POST":
        if not can_manage:
            abort(403)
        text = request.form.get("policy_toml", "")
        try:
            text = policies.validate_text(text)
        except PolicyError as exc:
            flash(f"Policy not saved: {exc}", "danger")
            return render_template("integrations/policy.html", repo=repo, text=text, can_manage=can_manage,
                                   template=policies.TEMPLATE, repos=_policy_repos()), 400
        target = repo or g.org
        target.policy_toml = text
        if repo is None:
            g.org.allow_repo_policy_file = request.form.get("allow_repo_policy_file") == "on"
        events.record("policy.updated", organization_id=g.org.id, target=target,
                      scope="repository" if repo else "organization")
        db.session.commit()
        flash("Policy saved. It applies to audits started from now on.", "success")
        return redirect(url_for("integrations.policy", org_slug=org_slug, repo=repo.id if repo else None))
    text = (repo.policy_toml if repo else g.org.policy_toml) or ""
    return render_template("integrations/policy.html", repo=repo, text=text, can_manage=can_manage,
                           template=policies.TEMPLATE, repos=_policy_repos())


def _policy_repos():
    from ..models import Repository

    return list(db.session.execute(
        db.select(Repository).where(Repository.organization_id == g.org.id).order_by(Repository.name)
    ).scalars())


@bp.route("/notifications", methods=["GET", "POST"])
@org_required("viewer")
def notifications(org_slug):
    from .. import notifications as notify
    from ..models import NotificationChannel

    can_manage = g.membership.role in ("admin", "owner")
    new_secret = None
    if request.method == "POST":
        if not can_manage:
            abort(403)
        try:
            channel, new_secret = notify.add_channel(g.org, request.form.get("kind", ""), request.form.get("label", ""),
                                                     request.form.get("url", ""), request.form.getlist("events"),
                                                     current_user.id)
            flash(f"Channel added ({channel.url_host}).", "success")
        except notify.NotificationError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        if new_secret is None:
            return redirect(url_for("integrations.notifications", org_slug=org_slug))
    channels = db.session.execute(db.select(NotificationChannel).where(NotificationChannel.organization_id == g.org.id)
                                  .order_by(NotificationChannel.created_at)).scalars().all()
    resp = make_response(render_template("integrations/notifications.html", channels=channels, can_manage=can_manage,
                                         kinds=notify.KINDS, events=notify.EVENTS, new_secret=new_secret))
    if new_secret:
        resp.headers["Cache-Control"] = "no-store"  # the signing secret is shown once
    return resp


@bp.post("/notifications/<channel_id>/delete")
@org_required("admin")
def delete_channel(org_slug, channel_id):
    from ..models import NotificationChannel

    channel = get_scoped_or_404(NotificationChannel, channel_id)
    events.record("notification.channel_deleted", organization_id=g.org.id, target=channel, kind=channel.kind)
    db.session.delete(channel)
    db.session.commit()
    flash("Channel removed.", "success")
    return redirect(url_for("integrations.notifications", org_slug=org_slug))


@bp.post("/notifications/<channel_id>/test")
@org_required("admin")
def test_channel(org_slug, channel_id):
    from .. import notifications as notify
    from ..models import NotificationChannel

    channel = get_scoped_or_404(NotificationChannel, channel_id)
    if not ratelimit.hit("notify-test", str(g.org.id), 10, 3600):
        flash("Too many test messages; try again later.", "danger")
        return redirect(url_for("integrations.notifications", org_slug=org_slug))
    msg = {"title": "eVal test notification", "text": f"Channel {channel.label} is connected.", "link": "",
           "payload": {"event": "test", "organization": g.org.slug}}
    try:
        channel.last_status = notify.deliver(channel, msg)[:200]
    except notify.NotificationError as exc:
        channel.last_status = f"error: {exc}"[:200]
    db.session.commit()
    flash(f"Test sent: {channel.last_status}", "info")
    return redirect(url_for("integrations.notifications", org_slug=org_slug))
