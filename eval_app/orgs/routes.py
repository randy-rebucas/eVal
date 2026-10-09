from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from wtforms import EmailField, SelectField, StringField
from wtforms.validators import DataRequired, Length

from ..auth.services import AuthError, create_organization
from ..extensions import db
from ..models import ROLES, Audit, Membership, Project, Repository
from ..security.tenancy import get_scoped_or_404, org_required, scoped_select
from . import services

bp = Blueprint("orgs", __name__)


class OrgForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(min=2, max=120)])


class MemberForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Length(max=320)])
    role = SelectField("Role", choices=[(r, r.title()) for r in ROLES], default="member")


@bp.route("/orgs", methods=["GET", "POST"])
@login_required
def list_orgs():
    form = OrgForm()
    if form.validate_on_submit():
        try:
            org = create_organization(form.name.data, current_user)
            db.session.commit()
        except AuthError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            return redirect(url_for("orgs.dashboard", org_slug=org.slug))
    orgs = services.user_orgs(current_user)
    if len(orgs) == 1 and request.method == "GET" and not request.args.get("all"):
        return redirect(url_for("orgs.dashboard", org_slug=orgs[0][0].slug))
    return render_template("orgs/list.html", orgs=orgs, form=form)


@bp.get("/o/<org_slug>")
@org_required()
def dashboard(org_slug):
    projects = db.session.execute(scoped_select(Project).order_by(Project.name)).scalars().all()
    recent = (
        db.session.execute(
            scoped_select(Audit).join(Repository).order_by(Audit.created_at.desc()).limit(10)
        )
        .scalars()
        .all()
    )
    return render_template("orgs/dashboard.html", projects=projects, recent_audits=recent,
                           portfolio=services.portfolio(g.org))


@bp.route("/o/<org_slug>/members", methods=["GET", "POST"])
@org_required()
def members(org_slug):
    form = MemberForm()
    if request.method == "POST":
        if g.membership.role not in ("admin", "owner"):
            flash("Only admins can manage members.", "danger")
        elif form.validate_on_submit():
            try:
                services.add_member(g.org, g.membership, form.email.data, form.role.data)
                flash("Member added.", "success")
            except services.OrgError as exc:
                db.session.rollback()
                flash(str(exc), "danger")
        return redirect(url_for("orgs.members", org_slug=org_slug))
    return render_template("orgs/members.html", members=services.members(g.org), form=form, roles=ROLES)


@bp.post("/o/<org_slug>/members/<member_id>/role")
@org_required("admin")
def change_role(org_slug, member_id):
    membership = get_scoped_or_404(Membership, member_id)
    try:
        services.change_role(g.org, g.membership, membership, request.form.get("role", ""))
        flash("Role updated.", "success")
    except services.OrgError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("orgs.members", org_slug=org_slug))


@bp.post("/o/<org_slug>/members/<member_id>/remove")
@org_required("admin")
def remove_member(org_slug, member_id):
    membership = get_scoped_or_404(Membership, member_id)
    try:
        services.remove_member(g.org, g.membership, membership)
        flash("Member removed.", "success")
    except services.OrgError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("orgs.members", org_slug=org_slug))
