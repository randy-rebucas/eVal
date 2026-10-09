from __future__ import annotations

from urllib.parse import urlsplit

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField
from wtforms.validators import DataRequired, Length

from ..extensions import db
from ..security import events, ratelimit
from .services import AuthError, authenticate, register_user

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
    return redirect(url_for("auth.login"))


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
    return render_template("auth/register.html", form=form)


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
            session.clear()  # prevent session fixation
            login_user(user)
            events.record("auth.login", actor_id=user.id)
            db.session.commit()
            return redirect(_safe_next(request.args.get("next")) or url_for("orgs.list_orgs"))
    return render_template("auth/login.html", form=form)


@bp.post("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))
