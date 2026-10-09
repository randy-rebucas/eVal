from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, SelectField, StringField
from wtforms.validators import DataRequired, Length

from eval_engine.ai import PROVIDERS

from .. import ai_config
from ..extensions import db
from ..models import IntegrationCredential
from ..security.tenancy import get_scoped_or_404, org_required
from . import services

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
                           ai_base_urls=ai_config.allowed_base_urls(),
                           ai_creds=[c for c in creds if c.provider in PROVIDERS])


@bp.post("/ai")
@org_required("admin")
def save_ai(org_slug):
    f = request.form
    try:
        ai_config.save_settings(
            g.org, enabled=f.get("enabled") == "on", provider=f.get("provider", ""), model=f.get("model", ""),
            base_url=f.get("base_url", ""), credential_id=f.get("credential_id") or None,
            max_findings=f.get("max_findings", type=int) or 15,
        )
        flash("AI settings saved.", "success")
    except ai_config.AISettingsError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("integrations.index", org_slug=org_slug))


@bp.post("/integrations/<cred_id>/delete")
@org_required("admin")
def delete(org_slug, cred_id):
    cred = get_scoped_or_404(IntegrationCredential, cred_id)
    services.delete_credential(g.org, cred)
    flash("Credential deleted.", "success")
    return redirect(url_for("integrations.index", org_slug=org_slug))
