from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, SelectField, StringField
from wtforms.validators import DataRequired, Length

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
    return render_template("integrations/index.html", creds=creds, form=form, can_manage=can_manage, ai_form=None)


@bp.post("/integrations/<cred_id>/delete")
@org_required("admin")
def delete(org_slug, cred_id):
    cred = get_scoped_or_404(IntegrationCredential, cred_id)
    services.delete_credential(g.org, cred)
    flash("Credential deleted.", "success")
    return redirect(url_for("integrations.index", org_slug=org_slug))
