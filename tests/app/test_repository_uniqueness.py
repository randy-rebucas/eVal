"""A GitHub repository is connected to a project at most once, even under concurrent requests."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from eval_app.models import Organization, Project, Repository
from eval_app.projects import repositories as repo_service
from tests.app.helpers import make_project


def _org_project(alice, db):
    c, slug = alice["client"], alice["org"]
    make_project(c, slug)
    org = db.session.execute(db.select(Organization).where(Organization.slug == slug)).scalar_one()
    project = db.session.execute(db.select(Project).where(Project.organization_id == org.id)).scalar_one()
    return org, project


def test_database_rejects_a_second_connection_of_the_same_repository(alice, db):
    org, project = _org_project(alice, db)
    for _ in range(2):
        db.session.add(Repository(organization_id=org.id, project_id=project.id, source="github",
                                  name="octo/shop", full_name="octo/shop"))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_uploads_are_not_constrained(alice, db):
    org, project = _org_project(alice, db)
    repo_service.create_upload_repository(org, project, "first upload")
    repo_service.create_upload_repository(org, project, "second upload")
    db.session.commit()  # both have full_name "": the index only covers GitHub rows


def test_concurrent_connect_reports_already_connected(alice, db, fake_github, monkeypatch):
    org, project = _org_project(alice, db)
    db.session.add(Repository(organization_id=org.id, project_id=project.id, source="github",
                              name="octo/shop", full_name="octo/shop"))
    db.session.commit()

    class Missed:  # the other request inserted its row after this one's existence check
        def first(self):
            return None

    real_execute = db.session.execute
    monkeypatch.setattr(db.session, "execute", lambda stmt, *a, **kw: Missed() if "repositories.id" in str(stmt)
                        else real_execute(stmt, *a, **kw))
    with pytest.raises(repo_service.RepositoryError, match="already connected"):
        repo_service.add_github_repository(org, project, "octo/shop")
