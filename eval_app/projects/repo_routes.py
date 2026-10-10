from __future__ import annotations

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SelectField, StringField
from wtforms.validators import DataRequired, Length

from ..audits.services import AuditError, create_audit, create_pr_audit
from ..extensions import db
from ..integrations.github import GitHubError
from ..integrations.services import CredentialError, github_oauth_enabled, org_credentials, repo_client
from ..models import Audit, Project, Repository
from ..security import ratelimit
from ..security.tenancy import get_scoped_or_404, org_required, require_role
from . import repositories as repo_service

bp = Blueprint("repos", __name__, url_prefix="/o/<org_slug>")


class GitHubRepoForm(FlaskForm):
    full_name = StringField("Repository (owner/name)", validators=[DataRequired(), Length(max=200)])
    credential_id = SelectField("Credential", choices=[], validate_choice=False)


class BulkConnectForm(FlaskForm):
    """CSRF only; the selected ``repos`` and ``credential_id`` are read from the request and checked server-side."""


class UploadRepoForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(min=2, max=200)])
    archive = FileField("Source archive (.zip)", validators=[FileRequired()])


class UploadForm(FlaskForm):
    archive = FileField("New source archive (.zip)", validators=[FileRequired()])


class RunAuditForm(FlaskForm):
    ref = StringField("Branch, tag, or commit SHA", validators=[Length(max=255)])


def _credential_choices():
    if g.membership.role not in ("admin", "owner"):
        return [("", "None (public repository)")]
    return [("", "None (public repository)")] + [
        (str(c.id), f"{c.label} (…{c.last4})") for c in org_credentials(g.org, "github")
    ]


@bp.route("/projects/<project_id>/repos/new", methods=["GET", "POST"])
@org_required("member")
def new(org_slug, project_id):
    project = get_scoped_or_404(Project, project_id)
    gh_form = GitHubRepoForm(prefix="gh")
    gh_form.credential_id.choices = _credential_choices()
    up_form = UploadRepoForm(prefix="up")
    if request.method == "POST":
        kind = request.form.get("kind")
        if kind == "github_bulk" and BulkConnectForm().validate_on_submit():
            credential_id = request.form.get("credential_id") or None
            if credential_id:
                require_role("admin")
            try:
                added, errors = repo_service.add_github_repositories(
                    g.org, project, request.form.getlist("repos"), credential_id)
            except repo_service.RepositoryError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("repos.new", org_slug=org_slug, project_id=project.id))
            if added:
                flash(f"Connected {len(added)} repositor{'y' if len(added) == 1 else 'ies'}.", "success")
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("projects.detail", org_slug=org_slug, project_id=project.id))
        if kind == "github" and gh_form.validate_on_submit():
            credential_id = gh_form.credential_id.data or None
            if credential_id:
                require_role("admin")  # binding an org credential to a repository is an admin action
            try:
                repo = repo_service.add_github_repository(g.org, project, gh_form.full_name.data, credential_id)
            except repo_service.RepositoryError as exc:
                db.session.rollback()
                flash(str(exc), "danger")
            else:
                flash("Repository connected. Choose a branch or commit and run an audit.", "success")
                return redirect(url_for("repos.detail", org_slug=org_slug, repo_id=repo.id))
        elif kind == "upload" and up_form.validate_on_submit():
            try:
                repo = repo_service.create_upload_repository(g.org, project, up_form.name.data)
                upload = repo_service.store_upload(g.org, repo, up_form.archive.data, current_user.id)
                db.session.commit()
                audit = create_audit(g.org, repo, current_user.id, upload=upload)
            except (repo_service.RepositoryError, AuditError) as exc:
                db.session.rollback()
                flash(str(exc), "danger")
            else:
                return redirect(url_for("audits.detail", org_slug=org_slug, audit_id=audit.id))
    choices = _credential_choices()
    browse = _browse(project, choices)
    return render_template("repos/new.html", project=project, gh_form=gh_form, up_form=up_form,
                           credential_choices=choices, bulk_form=BulkConnectForm(),
                           can_connect=g.membership.role in ("admin", "owner"),
                           gh_oauth=github_oauth_enabled(), **browse)


def _browse(project, choices):
    """Repository listing for ``?browse=1&credential_id=…&owner=…``. Admins with a connected GitHub account
    see the newest one's repositories straight away."""
    a = request.args
    out = {"browse_cred": a.get("credential_id", ""), "browse_owner": a.get("owner", "").strip()[:100],
           "gh_repos": None, "browse_error": None}
    if not a.get("browse"):
        if request.method != "GET" or len(choices) < 2:
            return out
        out["browse_cred"] = choices[-1][0]
    if out["browse_cred"] and g.membership.role not in ("admin", "owner"):
        out["browse_error"] = "Only admins can browse with an organization credential."
    elif not ratelimit.hit("gh-browse", str(g.org.id), 30, 300):
        out["browse_error"] = "Too many GitHub lookups; try again in a few minutes."
    else:
        try:
            out["gh_repos"] = repo_service.browse_github_repositories(
                g.org, project, out["browse_cred"] or None, out["browse_owner"])
        except repo_service.RepositoryError as exc:
            out["browse_error"] = str(exc)
    return out


@bp.get("/repos/<repo_id>")
@org_required()
def detail(org_slug, repo_id):
    repo = get_scoped_or_404(Repository, repo_id)
    audits = db.session.execute(
        db.select(Audit).where(Audit.repository_id == repo.id, Audit.organization_id == g.org.id)
        .order_by(Audit.created_at.desc()).limit(50)
    ).scalars().all()
    branches, commits, gh_error = [], [], None
    selected_branch = request.args.get("branch") or repo.default_branch
    if repo.source == "github":
        try:
            client = repo_client(repo)
            branches = client.list_branches(repo.full_name)
            if selected_branch:
                commits = client.list_commits(repo.full_name, selected_branch, limit=15)
        except (GitHubError, CredentialError, repo_service.RepositoryError) as exc:
            gh_error = str(exc)
    return render_template(
        "repos/detail.html", repo=repo, audits=audits, branches=branches, commits=commits, gh_error=gh_error,
        selected_branch=selected_branch, run_form=RunAuditForm(), upload_form=UploadForm(),
        latest_upload=repo_service.latest_upload(repo) if repo.source == "upload" else None,
        credential_choices=_credential_choices() if repo.source == "github" else [],
    )


@bp.post("/repos/<repo_id>/audits")
@org_required("member")
def run(org_slug, repo_id):
    repo = get_scoped_or_404(Repository, repo_id)
    form = RunAuditForm()
    if not form.validate_on_submit():
        abort(400)
    try:
        if repo.source == "upload":
            upload = repo_service.latest_upload(repo)
            audit = create_audit(g.org, repo, current_user.id, upload=upload)
        else:
            audit = create_audit(g.org, repo, current_user.id, ref=form.ref.data or repo.default_branch)
    except AuditError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(url_for("repos.detail", org_slug=org_slug, repo_id=repo.id))
    return redirect(url_for("audits.detail", org_slug=org_slug, audit_id=audit.id))


@bp.post("/repos/<repo_id>/pulls")
@org_required("member")
def run_pr(org_slug, repo_id):
    repo = get_scoped_or_404(Repository, repo_id)
    number = request.form.get("number", type=int)
    if not number or number < 1:
        flash("Enter a pull request number.", "danger")
        return redirect(url_for("repos.detail", org_slug=org_slug, repo_id=repo.id))
    try:
        audit = create_pr_audit(g.org, repo, current_user.id, number, trigger="pull_request")
    except AuditError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(url_for("repos.detail", org_slug=org_slug, repo_id=repo.id))
    return redirect(url_for("audits.detail", org_slug=org_slug, audit_id=audit.id))


@bp.post("/repos/<repo_id>/upload")
@org_required("member")
def upload(org_slug, repo_id):
    repo = get_scoped_or_404(Repository, repo_id)
    form = UploadForm()
    if not form.validate_on_submit():
        flash("Choose a .zip file to upload.", "danger")
        return redirect(url_for("repos.detail", org_slug=org_slug, repo_id=repo.id))
    try:
        up = repo_service.store_upload(g.org, repo, form.archive.data, current_user.id)
        db.session.commit()
        audit = create_audit(g.org, repo, current_user.id, upload=up)
    except (repo_service.RepositoryError, AuditError) as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(url_for("repos.detail", org_slug=org_slug, repo_id=repo.id))
    return redirect(url_for("audits.detail", org_slug=org_slug, audit_id=audit.id))


@bp.post("/repos/<repo_id>/credential")
@org_required("admin")
def set_credential(org_slug, repo_id):
    repo = get_scoped_or_404(Repository, repo_id)
    try:
        repo_service.set_repository_credential(g.org, repo, request.form.get("credential_id") or None)
        flash("Repository credential updated.", "success")
    except repo_service.RepositoryError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("repos.detail", org_slug=org_slug, repo_id=repo.id))


@bp.post("/repos/<repo_id>/automation")
@org_required("admin")
def automation(org_slug, repo_id):
    from ..audits.schedule import SCHEDULES
    from ..security import events

    repo = get_scoped_or_404(Repository, repo_id)
    schedule = request.form.get("schedule", "off")
    if schedule not in SCHEDULES:
        abort(400)
    repo.schedule = schedule
    if repo.source == "github":
        repo.auto_audit = request.form.get("auto_audit") == "on"
    events.record("repository.automation", organization_id=g.org.id, target=repo, schedule=schedule,
                  auto_audit=repo.auto_audit)
    db.session.commit()
    flash("Automation settings saved.", "success")
    return redirect(url_for("repos.detail", org_slug=org_slug, repo_id=repo.id))


@bp.post("/repos/<repo_id>/delete")
@org_required("admin")
def delete(org_slug, repo_id):
    repo = get_scoped_or_404(Repository, repo_id)
    require_role("admin")
    project_id = repo.project_id
    repo_service.delete_repository(g.org, repo)
    flash("Repository and its audits deleted.", "success")
    return redirect(url_for("projects.detail", org_slug=org_slug, project_id=project_id))
