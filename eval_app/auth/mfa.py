"""Second factor: TOTP enrolment, the sign-in challenge, recovery codes.

Every interactive sign-in ends in ``complete_login``. For a user with TOTP enabled it does not log in; it parks the
user id in the session and redirects to the challenge, so password and social sign-in both require the code. SSO
sign-ins rely on the organization's identity provider for the second factor and skip the challenge.
"""

from __future__ import annotations

import time
import uuid

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user

from ..extensions import db
from ..models import User, utcnow
from ..security import crypto, events, ratelimit, totp

bp = Blueprint("mfa", __name__)
PENDING_KEY = "mfa_pending"
SETUP_KEY = "mfa_setup"
PENDING_MAX_AGE = 300


def complete_login(user: User, method: str, next_url: str | None, sso_org: str | None = None):
    """Finish a sign-in (after the first factor): challenge for TOTP when enabled, else log in. Returns a response."""
    session.clear()  # prevent session fixation
    if user.mfa_enabled and method != "sso":
        session[PENDING_KEY] = {"uid": str(user.id), "method": method, "next": next_url, "at": int(time.time())}
        return redirect(url_for("mfa.challenge"))
    return _login(user, method, next_url, sso_org=sso_org, mfa=False)


def _login(user: User, method: str, next_url: str | None, sso_org: str | None, mfa: bool):
    login_user(user)
    session["auth_method"] = method
    session["mfa_verified"] = mfa
    if sso_org:
        session["sso_org"] = sso_org
    user.last_login_at = utcnow()
    events.record("auth.login", actor_id=user.id, method=method, mfa=mfa or None)
    db.session.commit()
    return redirect(next_url or url_for("orgs.list_orgs"))


def _check(user: User, code: str) -> bool:
    """Accept a TOTP code (advancing the replay guard) or consume a recovery code."""
    step = totp.verify(crypto.decrypt(user.mfa_secret_enc), code, user.mfa_last_step)
    if step is not None:
        user.mfa_last_step = step
        return True
    remaining = totp.use_recovery_code(user.mfa_recovery or [], code)
    if remaining is not None:
        user.mfa_recovery = remaining
        events.record("auth.mfa_recovery_used", actor_id=user.id, remaining=len(remaining))
        return True
    return False


@bp.route("/login/mfa", methods=["GET", "POST"])
def challenge():
    pending = session.get(PENDING_KEY) or {}
    if not pending or time.time() - pending.get("at", 0) > PENDING_MAX_AGE:
        session.pop(PENDING_KEY, None)
        flash("Sign in again to continue.", "warning")
        return redirect(url_for("auth.login"))
    user = db.session.get(User, uuid.UUID(pending["uid"]))
    if user is None or not user.is_active or not user.mfa_enabled:
        session.pop(PENDING_KEY, None)
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        if not ratelimit.hit("mfa", str(user.id), current_app.config["LOGIN_RATE_LIMIT"], 300):
            abort(429)
        if _check(user, request.form.get("code", "")):
            session.pop(PENDING_KEY, None)
            return _login(user, pending["method"], pending.get("next"), sso_org=None, mfa=True)
        events.record("auth.mfa_failed", actor_id=user.id)
        db.session.commit()
        flash("That code is not valid. Use the current code from your authenticator app, or a recovery code.",
              "danger")
    return render_template("auth/mfa_challenge.html")


@bp.route("/account/mfa", methods=["GET", "POST"])
@login_required
def settings():
    user = current_user
    codes = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "start" and not user.mfa_enabled:
            session[SETUP_KEY] = crypto.encrypt(totp.new_secret()).decode()
        elif action == "enable" and not user.mfa_enabled and session.get(SETUP_KEY):
            secret = crypto.decrypt(session[SETUP_KEY].encode())
            step = totp.verify(secret, request.form.get("code", ""), None)
            if step is None:
                flash("That code does not match. Check the time on your device and try again.", "danger")
            else:
                codes, hashes = totp.new_recovery_codes()
                user.mfa_secret_enc, user.mfa_enabled_at = crypto.encrypt(secret), utcnow()
                user.mfa_last_step, user.mfa_recovery = step, hashes
                session.pop(SETUP_KEY, None)
                session["mfa_verified"] = True
                events.record("auth.mfa_enabled", actor_id=user.id)
                db.session.commit()
                flash("Two-factor authentication is on.", "success")
        elif action in ("disable", "recovery") and user.mfa_enabled:
            if not ratelimit.hit("mfa", str(user.id), current_app.config["LOGIN_RATE_LIMIT"], 300):
                abort(429)
            if not _check(user, request.form.get("code", "")):
                db.session.commit()  # a consumed recovery code stays consumed
                flash("That code is not valid.", "danger")
            elif action == "disable":
                user.mfa_secret_enc = user.mfa_enabled_at = user.mfa_last_step = None
                user.mfa_recovery = []
                events.record("auth.mfa_disabled", actor_id=user.id)
                db.session.commit()
                flash("Two-factor authentication is off.", "warning")
            else:
                codes, user.mfa_recovery = totp.new_recovery_codes()
                events.record("auth.mfa_recovery_regenerated", actor_id=user.id)
                db.session.commit()
    setup_secret = crypto.decrypt(session[SETUP_KEY].encode()) if session.get(SETUP_KEY) and not user.mfa_enabled \
        else None
    resp = current_app.make_response(render_template(
        "auth/mfa_settings.html", setup_secret=setup_secret, recovery_codes=codes,
        uri=totp.provisioning_uri(setup_secret, user.email) if setup_secret else None,
        remaining=len(user.mfa_recovery or [])))
    resp.headers["Cache-Control"] = "no-store"  # secrets and recovery codes are shown on this page
    return resp


def satisfies_org_mfa(org) -> bool:
    """Whether the current session meets an organization's MFA requirement."""
    if not org.require_mfa:
        return True
    # Every password or social sign-in of an account with TOTP passes the challenge (complete_login), so an enabled
    # second factor is enough here.
    return bool(current_user.mfa_enabled) or session.get("sso_org") == str(org.id)
