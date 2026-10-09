from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy.orm import selectinload
from wtforms import EmailField, SelectField, StringField
from wtforms.validators import DataRequired, Length

from eval_engine.findings import CATEGORY_LABELS, Category

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
    project = request.args.get("project", "")
    project_obj = next((p for p in projects if str(p.id) == project), None)
    recent_q = scoped_select(Audit).join(Repository).options(selectinload(Audit.repository))
    if project_obj:
        recent_q = recent_q.where(Repository.project_id == project_obj.id)
    recent = db.session.execute(recent_q.order_by(Audit.created_at.desc()).limit(10)).scalars().all()

    # The project is the scope: the directive, title block, notes and rail all describe it. Risk, state and
    # pattern are drill-downs inside that scope and only narrow the register.
    rows = [r for r in services.portfolio(g.org) if not project_obj or r.repo.project_id == project_obj.id]
    summary = services.portfolio_summary(rows)
    risk = request.args.get("risk", "")
    risk = risk if risk in services.PORTFOLIO_RANK else ""
    state = request.args.get("state", "")
    state = state if state in services.STATES else ""
    pattern = request.args.get("pattern", "")
    pattern = pattern if pattern in summary["pattern_counts"] else ""
    due_by = services.due_date()
    shown = [r for r in rows if (not risk or r.risk == risk) and (not state or r.in_state(state, due_by))
             and (not pattern or pattern in r.flagged)]
    return render_template("orgs/dashboard.html", projects=projects, has_projects=bool(projects),
                           recent_audits=recent, portfolio=shown, summary=summary,
                           risk_filter=risk, state_filter=state, pattern_filter=pattern,
                           project_filter=str(project_obj.id) if project_obj else "", project_obj=project_obj,
                           stale_days=services.STALE_AFTER_DAYS, due_days=services.ACCEPTED_DUE_DAYS,
                           category_count=len(Category),
                           category_codes=[(services.CATEGORY_CODES[c], CATEGORY_LABELS[c]) for c in Category],
                           due_by=due_by)


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
