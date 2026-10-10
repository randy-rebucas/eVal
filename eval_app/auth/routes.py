from __future__ import annotations

import hmac
import secrets
import time
from urllib.parse import urlsplit

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import validate_csrf
from wtforms import EmailField, PasswordField, StringField
from wtforms.validators import DataRequired, Length, ValidationError

from ..extensions import db
from ..security import events, ratelimit
from . import social
from .mfa import complete_login
from .services import AuthError, authenticate, link_identity, register_user, social_sign_in, unlink_identity

bp = Blueprint("auth", __name__)


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Length(max=320)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=256)])


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[Length(max=120)])
    email = EmailField("Email", validators=[DataRequired(), Length(max=320)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12, max=256)])
    org_name = StringField("Organization name", validators=[DataRequired(), Length(min=2, max=120)])


def _safe_next(target: str | None) -> str | None:
    """Only allow same-site relative redirects (prevents open redirect)."""
    if not target:
        return None
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//"):
        return None
    return target


@bp.get("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("orgs.list_orgs"))
    return render_template("landing.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if not current_app.config["ALLOW_REGISTRATION"]:
        abort(404)
    form = RegisterForm()
    if form.validate_on_submit():
        if not ratelimit.hit("register", request.remote_addr or "?", 10, 3600):
            abort(429)
        try:
            user, org = register_user(
                email=form.email.data, password=form.password.data, name=form.name.data or "",
                org_name=form.org_name.data,
            )
        except AuthError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            session.clear()
            login_user(user)
            flash("Welcome to eVal.", "success")
            return redirect(url_for("orgs.dashboard", org_slug=org.slug))
    return render_template("auth/register.html", form=form, social_providers=social.enabled_providers())


@bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        ident = f"{request.remote_addr}|{(form.email.data or '').lower()}"
        # Per IP+email stops guessing one account; per IP stops spraying many accounts from one address.
        if not (ratelimit.hit("login-ip", request.remote_addr or "?", current_app.config["LOGIN_IP_RATE_LIMIT"], 300)
                and ratelimit.hit("login", ident, current_app.config["LOGIN_RATE_LIMIT"], 300)):
            events.record("auth.login_rate_limited", email_domain=(form.email.data or "").rpartition("@")[2])
            db.session.commit()
            abort(429)
        user = authenticate(form.email.data, form.password.data)
        if user is None:
            events.record("auth.login_failed")
            db.session.commit()
            flash("Invalid email or password.", "danger")
        else:
            return complete_login(user, "password", _safe_next(request.args.get("next")))
    return render_template("auth/login.html", form=form, social_providers=social.enabled_providers())


SOCIAL_SESSION_KEY = "social_oauth"
SOCIAL_MAX_AGE = 600  # seconds to finish signing in at the provider


def _start_social(provider: str, link: bool):
    p = social.get_provider(provider)
    if p is None:
        abort(404)
    if not ratelimit.hit("social-login", request.remote_addr or "?", 30, 300):
        abort(429)
    state = secrets.token_urlsafe(32)
    session[SOCIAL_SESSION_KEY] = {
        "provider": p.key, "state": state, "at": int(time.time()),
        "link_user": str(current_user.id) if link else None,
        "next": _safe_next(request.args.get("next")),
    }
    return redirect(social.authorize_url(p.key, url_for("auth.social_callback", provider=p.key, _external=True),
                                         state))


@bp.get("/login/<provider>")
def social_login(provider):
    if current_user.is_authenticated:
        return redirect(url_for("orgs.list_orgs"))
    return _start_social(provider, link=False)


@bp.get("/account/connect/<provider>")
@login_required
def social_connect(provider):
    # A link (CSP form-action 'self' blocks cross-site redirects from forms), so the CSRF token rides along.
    if current_app.config.get("WTF_CSRF_ENABLED", True):
        try:
            validate_csrf(request.args.get("csrf", ""))
        except ValidationError:
            abort(400)
    return _start_social(provider, link=True)


@bp.get("/login/<provider>/callback")
def social_callback(provider):
    pending = session.pop(SOCIAL_SESSION_KEY, None) or {}
    p = social.get_provider(provider)
    link_user = pending.get("link_user")
    fail_to = url_for("auth.account") if link_user else url_for("auth.login")
    if p is None or pending.get("provider") != provider or not pending.get("state") \
            or not hmac.compare_digest(pending["state"], request.args.get("state", "")) \
            or time.time() - pending.get("at", 0) > SOCIAL_MAX_AGE:
        flash("Sign-in expired or did not match. Please try again.", "danger")
        return redirect(fail_to)
    if link_user and (not current_user.is_authenticated or str(current_user.id) != link_user):
        abort(403)
    if request.args.get("error"):
        flash(f"{p.label} sign-in was cancelled.", "warning")
        return redirect(fail_to)
    try:
        token = social.exchange_code(provider, request.args.get("code", ""),
                                     url_for("auth.social_callback", provider=provider, _external=True))
        profile = social.fetch_profile(provider, token)
        if link_user:
            link_identity(current_user, provider, p.label, profile)
            db.session.commit()
            flash(f"{p.label} connected. You can now sign in with it.", "success")
            return redirect(url_for("auth.account"))
        user, org = social_sign_in(provider, p.label, profile)
    except (social.SocialAuthError, AuthError) as exc:
        db.session.rollback()
        events.record("auth.login_failed", method=provider)
        db.session.commit()
        flash(str(exc), "danger")
        return redirect(fail_to)
    if org is not None:
        flash("Welcome to eVal.", "success")
    return complete_login(user, provider, url_for("orgs.dashboard", org_slug=org.slug) if org is not None
                          else pending.get("next"))


@bp.get("/account")
@login_required
def account():
    linked = {i.provider: i for i in current_user.identities}
    return render_template("auth/account.html", providers=list(social.PROVIDERS.values()), linked=linked,
                           enabled={p.key for p in social.enabled_providers()})


@bp.post("/account/identities/<provider>/delete")
@login_required
def social_disconnect(provider):
    identity = next((i for i in current_user.identities if i.provider == provider), None)
    if identity is None:
        abort(404)
    try:
        unlink_identity(current_user, identity)
        db.session.commit()
        flash(f"{social.PROVIDERS[provider].label} disconnected.", "success")
    except AuthError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("auth.account"))


@bp.post("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))
