from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path

import pytest

from eval_app.integrations.github import GitHubClient, GitHubError
from eval_app.models import Audit, Finding, IntegrationCredential, Repository, ResolvedFinding, Upload
from tests.conftest import FIXTURES

FAST = ["secrets", "devops", "api_security", "database", "testing"]


@pytest.fixture(autouse=True)
def fast_analyzers(monkeypatch):
    """App tests exercise the web/worker flow; restrict to built-in analyzers to keep them fast."""
    from eval_engine.analyzers import registry

    real_get = registry.get
    monkeypatch.setattr(registry, "get", lambda names: real_get(names if names is not None else FAST))


def zip_bytes(src: Path, mutate=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*")):
            if p.is_file():
                z.write(p, f"myrepo-main/{p.relative_to(src).as_posix()}")
        if mutate:
            mutate(z)
    return buf.getvalue()


def make_project(client, org):
    resp = client.post(f"/o/{org}/projects", data={"name": "Shop"})
    return resp.headers["Location"].rsplit("/", 1)[-1]


def upload_new(client, org, pid, data: bytes, name="vulnapp"):
    return client.post(
        f"/o/{org}/projects/{pid}/repos/new",
        data={"kind": "upload", "up-name": name, "up-archive": (io.BytesIO(data), "src.zip")},
        content_type="multipart/form-data",
    )


def test_upload_runs_audit_and_persists_findings(alice, db, app):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    resp = upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    assert resp.status_code == 302 and "/audits/" in resp.headers["Location"]
    audit = db.session.execute(db.select(Audit)).scalar_one()
    assert audit.status == "succeeded", audit.error
    assert audit.risk_level == "Critical" and audit.overall_score is not None
    assert audit.progress == 100 and audit.stats["lifecycle"]["new"] > 0
    rules = {f.rule_id for f in audit.findings}
    assert "eval:secrets.aws-access-key" in rules and "eval:database.sql-string-formatting" in rules
    assert all(f.organization_id == audit.organization_id for f in audit.findings)
    aws = next(f for f in audit.findings if f.rule_id == "eval:secrets.aws-access-key")
    assert "AKIAIOSFODNN7EXAMPLE" not in aws.evidence
    # the work directory is removed after the audit
    assert not any((app.config["DATA_DIR"] / "work").glob("*"))
    page = c.get(resp.headers["Location"])
    assert page.status_code == 200 and b"Critical" in page.data
    status = c.get(resp.headers["Location"] + "/status").get_json()
    assert status["status"] == "succeeded" and status["progress"] == 100


def test_reaudit_tracks_lifecycle_and_carries_triage(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    first = db.session.execute(db.select(Audit)).scalar_one()
    fp_finding = next(f for f in first.findings if f.rule_id == "eval:api.mass-assignment")
    fp_finding.triage_status = "false_positive"
    db.session.commit()
    repo = db.session.execute(db.select(Repository)).scalar_one()
    src = Path(alice["client"].application.config["DATA_DIR"]) / "v2"
    shutil.copytree(FIXTURES / "vulnapp", src)
    (src / "Dockerfile").unlink()
    resp = c.post(f"/o/{org}/repos/{repo.id}/upload",
                  data={"archive": (io.BytesIO(zip_bytes(src)), "v2.zip")}, content_type="multipart/form-data")
    assert resp.status_code == 302
    second = db.session.execute(db.select(Audit).order_by(Audit.created_at.desc()).limit(1)).scalar_one()
    assert second.status == "succeeded" and second.previous_audit_id == first.id
    assert {f.lifecycle for f in second.findings} == {"existing"}
    resolved = db.session.execute(db.select(ResolvedFinding).where(ResolvedFinding.audit_id == second.id)).scalars()
    assert "Container runs as root" in {r.title for r in resolved}
    carried = next(f for f in second.findings if f.rule_id == "eval:api.mass-assignment")
    assert carried.triage_status == "false_positive"


def test_malicious_archive_fails_audit_safely(alice, db, app):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    evil = zip_bytes(FIXTURES / "cleanapp", mutate=lambda z: z.writestr("../../escape.py", "x"))
    upload_new(c, org, pid, evil)
    audit = db.session.execute(db.select(Audit)).scalar_one()
    assert audit.status == "failed" and "traversal" in audit.error
    assert not (app.config["DATA_DIR"] / "escape.py").exists()
    assert not (app.config["DATA_DIR"].parent / "escape.py").exists()


def test_non_zip_upload_rejected(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    resp = upload_new(c, org, pid, b"#!/bin/sh\nrm -rf /\n")
    assert resp.status_code == 200 and b"not a valid ZIP" in resp.data
    assert db.session.scalar(db.select(db.func.count(Upload.id))) == 0
    assert db.session.scalar(db.select(db.func.count(Repository.id))) == 0


def test_viewer_cannot_upload_or_run(app, alice, db):
    from tests.conftest import register

    v = app.test_client()
    register(v, "v@example.com", "Other")
    alice["client"].post(f"/o/{alice['org']}/members", data={"email": "v@example.com", "role": "viewer"})
    pid = make_project(alice["client"], alice["org"])
    assert upload_new(v, alice["org"], pid, zip_bytes(FIXTURES / "cleanapp")).status_code == 403


def test_audits_are_tenant_isolated(alice, bob, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    repo = db.session.execute(db.select(Repository)).scalar_one()
    b = bob["client"]
    for url in (f"/o/{bob['org']}/audits/{audit.id}", f"/o/{bob['org']}/audits/{audit.id}/status",
                f"/o/{bob['org']}/repos/{repo.id}", f"/o/{org}/audits/{audit.id}"):
        assert b.get(url).status_code == 404, url
    assert b.post(f"/o/{bob['org']}/repos/{repo.id}/audits", data={"ref": "main"}).status_code == 404
    assert b.post(f"/o/{bob['org']}/audits/{audit.id}/cancel").status_code == 404


# ------------------------------------------------------------------------------------------------- GitHub
@pytest.fixture
def fake_github(monkeypatch):
    calls = []
    repos = {
        "octo/shop": {"full_name": "octo/shop", "default_branch": "main", "private": False, "size": 120,
                      "html_url": "https://github.com/octo/shop", "clone_url": "https://github.com/octo/shop.git"},
        "octo/huge": {"full_name": "octo/huge", "default_branch": "main", "private": True, "size": 10_000_000},
    }

    def fake_request(self, method, path, **kwargs):
        calls.append((method, path, self._headers.get("Authorization")))
        if path == "/user":
            if self._headers.get("Authorization") != "Bearer ghp_validtoken1234567890":
                raise GitHubError("GitHub rejected the credential (401).", 401)
            return {"login": "octocat"}
        if path.startswith("/repos/") and path.count("/") == 3:
            name = path[len("/repos/"):]
            if name not in repos:
                raise GitHubError("Not found on GitHub, or the credential lacks access.", 404)
            return repos[name]
        if path.endswith("/branches"):
            return [{"name": "main"}, {"name": "develop"}]
        if path.endswith("/commits"):
            return [{"sha": "a" * 40, "commit": {"message": "Fix bug\n\nbody", "author": {"name": "Ann"}}}]
        if path.endswith("/issues") and method == "POST":
            return {"number": 7, "html_url": "https://github.com/octo/shop/issues/7"}
        raise AssertionError(path)

    monkeypatch.setattr(GitHubClient, "_request", fake_request)
    return calls


def test_github_credential_is_verified_encrypted_and_never_rendered(alice, db, fake_github):
    c, org = alice["client"], alice["org"]
    bad = c.post(f"/o/{org}/settings/integrations",
                 data={"provider": "github", "label": "", "secret": "ghp_wrongtoken0000000000"})
    assert bad.status_code == 302
    assert db.session.scalar(db.select(db.func.count(IntegrationCredential.id))) == 0
    c.post(f"/o/{org}/settings/integrations",
           data={"provider": "github", "label": "", "secret": "ghp_validtoken1234567890"})
    cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    assert cred.label == "GitHub (octocat)" and cred.last4 == "7890"
    assert b"validtoken" not in cred.encrypted_secret
    page = c.get(f"/o/{org}/settings/integrations")
    assert b"ghp_validtoken" not in page.data and b"7890" in page.data


def test_connect_github_repo_and_select_branch(alice, db, fake_github, monkeypatch):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    resp = c.post(f"/o/{org}/projects/{pid}/repos/new",
                  data={"kind": "github", "gh-full_name": "https://github.com/octo/shop.git", "gh-credential_id": ""})
    assert resp.status_code == 302
    repo = db.session.execute(db.select(Repository)).scalar_one()
    assert (repo.full_name, repo.default_branch, repo.source) == ("octo/shop", "main", "github")
    page = c.get(f"/o/{org}/repos/{repo.id}?branch=develop")
    assert b"develop" in page.data and b"Fix bug" in page.data and b"aaaaaaaa" in page.data

    captured = {}

    def fake_clone(url, dest, ref, **kw):
        captured.update(url=url, ref=ref, token=kw.get("token"))
        shutil.copytree(FIXTURES / "cleanapp", dest, dirs_exist_ok=True)
        from eval_engine.workspace import CloneResult

        return CloneResult(commit_sha="b" * 40, ref=ref)

    monkeypatch.setattr("eval_app.audits.workspaces.clone_repo", fake_clone)
    c.post(f"/o/{org}/repos/{repo.id}/audits", data={"ref": "a" * 40})
    audit = db.session.execute(db.select(Audit)).scalar_one()
    assert audit.status == "succeeded", audit.error
    assert captured == {"url": "https://github.com/octo/shop.git", "ref": "a" * 40, "token": None}
    assert audit.commit_sha == "b" * 40


def test_invalid_ref_rejected(alice, db, fake_github):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    c.post(f"/o/{org}/projects/{pid}/repos/new", data={"kind": "github", "gh-full_name": "octo/shop"})
    repo = db.session.execute(db.select(Repository)).scalar_one()
    c.post(f"/o/{org}/repos/{repo.id}/audits", data={"ref": "--upload-pack=touch /tmp/x"})
    assert db.session.scalar(db.select(db.func.count(Audit.id))) == 0


def test_oversized_github_repo_rejected(alice, db, fake_github):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    resp = c.post(f"/o/{org}/projects/{pid}/repos/new", data={"kind": "github", "gh-full_name": "octo/huge"})
    assert resp.status_code == 200 and b"limit" in resp.data


def test_credential_from_other_org_cannot_be_used(alice, bob, db, fake_github):
    bob["client"].post(f"/o/{bob['org']}/settings/integrations",
                       data={"provider": "github", "label": "", "secret": "ghp_validtoken1234567890"})
    bob_cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    pid = make_project(alice["client"], alice["org"])
    resp = alice["client"].post(f"/o/{alice['org']}/projects/{pid}/repos/new",
                                data={"kind": "github", "gh-full_name": "octo/shop",
                                      "gh-credential_id": str(bob_cred.id)})
    assert b"Unknown credential" in resp.data
    assert db.session.scalar(db.select(db.func.count(Repository.id))) == 0


# ---------------------------------------------------------------------------------------- queue behaviour
def test_queued_audit_can_be_cancelled_and_worker_skips_it(tmp_path):
    """With a real (in-memory) broker the audit stays queued until a worker picks it up."""
    from eval_app import create_app
    from eval_app.audits.tasks import run_audit
    from eval_app.extensions import db
    from tests.conftest import org_slug_from, register

    app = create_app("testing", {"DATA_DIR": tmp_path, "CELERY_TASK_ALWAYS_EAGER": False,
                                 "CELERY_BROKER_URL": "memory://", "CELERY_RESULT_BACKEND": "cache+memory://"})
    with app.app_context():
        db.create_all()
        c = app.test_client()
        org = org_slug_from(register(c, "q@example.com", "Queue Org"))
        pid = make_project(c, org)
        upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
        audit = db.session.execute(db.select(Audit)).scalar_one()
        assert audit.status == "queued" and audit.celery_task_id
        assert c.post(f"/o/{org}/audits/{audit.id}/cancel").status_code == 302
        db.session.refresh(audit)
        assert audit.status == "cancelled"
        assert run_audit.run(str(audit.id)) == "skipped"  # a late worker does not resurrect it
        db.drop_all()


def test_findings_count_matches_detail(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    count = db.session.scalar(db.select(db.func.count(Finding.id)).where(Finding.audit_id == audit.id))
    assert count == len(audit.findings) > 5
