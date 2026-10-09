from __future__ import annotations

from ..auth.services import slugify
from ..extensions import db
from ..models import Organization, Project, Repository, Upload
from ..security import events


class ProjectError(Exception):
    pass


def create_project(org: Organization, name: str, description: str = "") -> Project:
    name = name.strip()
    if not 2 <= len(name) <= 120:
        raise ProjectError("Project name must be 2–120 characters.")
    slug = slugify(name)
    exists = db.session.execute(
        db.select(Project.id).where(Project.organization_id == org.id, Project.slug == slug)
    ).first()
    if exists:
        raise ProjectError("A project with that name already exists.")
    project = Project(organization_id=org.id, name=name, slug=slug, description=description.strip()[:2000])
    db.session.add(project)
    db.session.flush()
    events.record("project.created", organization_id=org.id, target=project)
    db.session.commit()
    return project


def delete_project(org: Organization, project: Project) -> None:
    """Delete the project, its repositories and audits, and the uploaded source archives on disk."""
    from .repositories import upload_path

    uploads = db.session.execute(
        db.select(Upload).join(Repository, Repository.id == Upload.repository_id)
        .where(Repository.project_id == project.id, Upload.organization_id == org.id)
    ).scalars().all()
    paths = [upload_path(u) for u in uploads]
    events.record("project.deleted", organization_id=org.id, target=project, name=project.name)
    db.session.delete(project)
    db.session.commit()
    for p in paths:
        p.unlink(missing_ok=True)
