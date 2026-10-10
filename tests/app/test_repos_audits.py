from __future__ import annotations

import io
import shutil
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from eval_app.models import Audit, Finding, IntegrationCredential, Repository, ResolvedFinding, Upload
from tests.app.helpers import make_project, upload_new, zip_bytes
from tests.conftest import FIXTURES


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


def test_browse_github_with_credential_and_connect_selected(alice, db, fake_github):
    c, org = alice["client"], alice["org"]
    c.post(f"/o/{org}/settings/integrations",
           data={"provider": "github", "label": "", "secret": "ghp_validtoken1234567890"})
    cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    pid = make_project(c, org)
    page = c.get(f"/o/{org}/projects/{pid}/repos/new?browse=1&credential_id={cred.id}")
    assert b"octo/shop" in page.data and b"octo/huge" in page.data and b"2 found" in page.data

    resp = c.post(f"/o/{org}/projects/{pid}/repos/new",
                  data={"kind": "github_bulk", "credential_id": str(cred.id), "repos": ["octo/shop", "octo/huge"]})
    assert resp.status_code == 302
    repo = db.session.execute(db.select(Repository)).scalar_one()  # octo/huge is over the size limit
    assert (repo.full_name, repo.credential_id) == ("octo/shop", cred.id)
    page = c.get(f"/o/{org}/projects/{pid}/repos/new?browse=1&credential_id={cred.id}")
    assert b"connected" in page.data


def test_browse_public_owner_without_credential(alice, db, fake_github):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    page = c.get(f"/o/{org}/projects/{pid}/repos/new?browse=1&owner=octo")
    assert b"octo/shop" in page.data and b"octo/huge" not in page.data
    page = c.get(f"/o/{org}/projects/{pid}/repos/new?browse=1")
    assert b"Choose a GitHub credential" in page.data
    page = c.get(f"/o/{org}/projects/{pid}/repos/new?browse=1&owner=../etc")
    assert b"Owner must be" in page.data


def test_browse_rejects_other_orgs_credential(alice, bob, db, fake_github):
    bob["client"].post(f"/o/{bob['org']}/settings/integrations",
                       data={"provider": "github", "label": "", "secret": "ghp_validtoken1234567890"})
    bob_cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    pid = make_project(alice["client"], alice["org"])
    page = alice["client"].get(f"/o/{alice['org']}/projects/{pid}/repos/new?browse=1&credential_id={bob_cred.id}")
    assert b"Unknown credential" in page.data and b"octo/shop" not in page.data
    alice["client"].post(f"/o/{alice['org']}/projects/{pid}/repos/new",
                         data={"kind": "github_bulk", "credential_id": str(bob_cred.id), "repos": ["octo/shop"]})
    assert db.session.scalar(db.select(db.func.count(Repository.id))) == 0


def _start_oauth(c, org, pid):
    resp = c.get(f"/o/{org}/settings/github/connect?project_id={pid}")
    assert resp.status_code == 302
    query = parse_qs(urlsplit(resp.headers["Location"]).query)
    assert resp.headers["Location"].startswith("https://github.com/login/oauth/authorize?")
    assert query["scope"] == ["repo"] and query["client_id"] == ["cid"]
    return query["state"][0]


def test_connect_github_oauth_stores_token_and_lists_repos(app, alice, db, fake_github, monkeypatch):
    app.config.update(GITHUB_OAUTH_CLIENT_ID="cid", GITHUB_OAUTH_CLIENT_SECRET="csecret")
    exchanged = []

    def fake_exchange(web_url, client_id, client_secret, code, redirect_uri):
        exchanged.append((web_url, code, redirect_uri))
        return "ghp_validtoken1234567890"

    monkeypatch.setattr("eval_app.integrations.github.exchange_oauth_code", fake_exchange)
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    state = _start_oauth(c, org, pid)

    bad = c.get("/integrations/github/callback?code=abc&state=forged")
    assert bad.status_code == 302 and not exchanged  # wrong state: no exchange, and the pending state is spent
    state = _start_oauth(c, org, pid)
    resp = c.get(f"/integrations/github/callback?code=abc&state={state}")
    assert resp.status_code == 302 and f"/projects/{pid}/repos/new?browse=1" in resp.headers["Location"]
    assert exchanged == [("https://github.com", "abc", "http://localhost/integrations/github/callback")]
    cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    assert cred.label == "GitHub (octocat)" and b"validtoken" not in cred.encrypted_secret

    page = c.get(f"/o/{org}/projects/{pid}/repos/new")  # newest account's repositories load straight away
    assert b"octo/shop" in page.data and b"Connect another GitHub account" in page.data

    state = _start_oauth(c, org, pid)  # reconnecting the same account updates the credential in place
    c.get(f"/integrations/github/callback?code=def&state={state}")
    assert db.session.scalar(db.select(db.func.count(IntegrationCredential.id))) == 1


def test_connect_github_requires_config_admin_and_own_session(app, alice, bob, db, fake_github):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    resp = c.get(f"/o/{org}/settings/github/connect?project_id={pid}", follow_redirects=True)
    assert b"not configured" in resp.data
    app.config.update(GITHUB_OAUTH_CLIENT_ID="cid", GITHUB_OAUTH_CLIENT_SECRET="csecret")
    state = _start_oauth(c, org, pid)
    # Another user cannot finish alice's sign-in: the state lives in alice's session only.
    bob["client"].get(f"/integrations/github/callback?code=abc&state={state}")
    assert db.session.scalar(db.select(db.func.count(IntegrationCredential.id))) == 0
    # A project id from another org falls back to the Integrations page rather than leaking a redirect.
    resp = bob["client"].get(f"/o/{bob['org']}/settings/github/connect?project_id={pid}")
    state = parse_qs(urlsplit(resp.headers["Location"]).query)["state"][0]
    resp = bob["client"].get(f"/integrations/github/callback?error=access_denied&state={state}")
    assert resp.headers["Location"].endswith(f"/o/{bob['org']}/settings/integrations")


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
        db.session.remove()  # release row locks before DDL (PostgreSQL would block DROP TABLE)
        db.drop_all()
        db.engine.dispose()


def test_findings_count_matches_detail(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    count = db.session.scalar(db.select(db.func.count(Finding.id)).where(Finding.audit_id == audit.id))
    assert count == len(audit.findings) > 5


def test_running_audit_shows_toggleable_progress_log(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    audit.status = "running"
    audit.stage = "analyzing: Ruff"
    audit.progress = 25
    db.session.commit()

    page = c.get(f"/o/{org}/audits/{audit.id}")
    assert page.status_code == 200
    assert b"<details class=\"audit-log" in page.data
    assert b"<summary>Running logs</summary>" in page.data
    assert b"analyzing: Ruff" in page.data and b"25%" in page.data
