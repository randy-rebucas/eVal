from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Length

from ..extensions import db
from ..models import Project
from ..security.tenancy import get_scoped_or_404, org_required, require_role, scoped_select
from . import services

bp = Blueprint("projects", __name__, url_prefix="/o/<org_slug>/projects")


class ProjectForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(min=2, max=120)])
    description = TextAreaField("Description", validators=[Length(max=2000)])


@bp.route("", methods=["GET", "POST"])
@org_required()
def index(org_slug):
    form = ProjectForm()
    if form.is_submitted():
        require_role("member")
        if form.validate():
            try:
                project = services.create_project(g.org, form.name.data, form.description.data or "")
            except services.ProjectError as exc:
                db.session.rollback()
                flash(str(exc), "danger")
            else:
                return redirect(url_for("projects.detail", org_slug=org_slug, project_id=project.id))
    projects = db.session.execute(scoped_select(Project).order_by(Project.name)).scalars().all()
    return render_template("projects/index.html", projects=projects, form=form)


@bp.get("/<project_id>")
@org_required()
def detail(org_slug, project_id):
    project = get_scoped_or_404(Project, project_id)
    return render_template("projects/detail.html", project=project)


@bp.post("/<project_id>/delete")
@org_required("admin")
def delete(org_slug, project_id):
    project = get_scoped_or_404(Project, project_id)
    services.delete_project(g.org, project)
    flash("Project deleted.", "success")
    return redirect(url_for("projects.index", org_slug=org_slug))
