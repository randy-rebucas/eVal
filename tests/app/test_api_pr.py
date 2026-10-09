from __future__ import annotations

import io
import re
import shutil
import sys
from pathlib import Path

import pytest

from eval_app.models import ApiToken, Audit, IntegrationCredential, Membership, Repository, User
from eval_engine.workspace import CloneResult
from tests.app.helpers import make_project, upload_new, zip_bytes
from tests.conftest import FIXTURES, register


def new_token(client, org, name="ci") -> str:
    resp = client.post(f"/o/{org}/settings/tokens", data={"name": name})
    assert resp.headers["Cache-Control"] == "no-store"
    match = re.search(r"(evl_[A-Za-z0-9_\-]{40,})", resp.data.decode())
    assert match
    return match.group(1)


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_token_is_shown_once_and_stored_hashed(alice, db):
    c, org = alice["client"], alice["org"]
    raw = new_token(c, org)
    stored = db.session.execute(db.select(ApiToken)).scalar_one()
    assert raw not in stored.token_hash and stored.prefix == raw[:12]
    assert raw not in c.get(f"/o/{org}/settings/tokens").data.decode()


def test_api_authentication(alice, db):
    c, org = alice["client"], alice["org"]
    assert c.get("/api/v1/me").status_code == 401
    assert c.get("/api/v1/me", headers=auth("evl_" + "x" * 43)).status_code == 401
    assert c.get("/api/v1/me", headers={"Authorization": "Basic abc"}).status_code == 401
    raw = new_token(c, org)
    me = c.get("/api/v1/me", headers=auth(raw)).get_json()
    assert me["organization"]["slug"] == org and me["role"] == "owner"
    token = db.session.execute(db.select(ApiToken)).scalar_one()
    c.post(f"/o/{org}/settings/tokens/{token.id}/revoke")
    assert c.get("/api/v1/me", headers=auth(raw)).status_code == 401


def test_api_is_csrf_exempt_but_session_cookies_do_not_authenticate(tmp_path):
    from eval_app import create_app
    from eval_app.extensions import db
    from tests.conftest import org_slug_from

    app = create_app("testing", {"WTF_CSRF_ENABLED": True, "DATA_DIR": tmp_path})
    with app.app_context():
        db.create_all()
        c = app.test_client()
        app.config["WTF_CSRF_ENABLED"] = False
        org_slug_from(register(c, "csrf@example.com", "Csrf Org"))
        app.config["WTF_CSRF_ENABLED"] = True
        assert c.get("/api/v1/me").status_code == 401  # logged-in browser session is not API auth
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


def test_api_role_and_membership_checked_per_request(app, alice, db):
    viewer = app.test_client()
    register(viewer, "apiviewer@example.com", "Viewer Co")
    alice["client"].post(f"/o/{alice['org']}/members", data={"email": "apiviewer@example.com", "role": "viewer"})
    viewer.get(f"/o/{alice['org']}")
    raw = new_token(viewer, alice["org"])
    pid = make_project(alice["client"], alice["org"])
    upload_new(alice["client"], alice["org"], pid, zip_bytes(FIXTURES / "cleanapp"))
    repo = db.session.execute(db.select(Repository)).scalar_one()
    assert viewer.get(f"/api/v1/repositories/{repo.id}", headers=auth(raw)).status_code == 200
    resp = viewer.post(f"/api/v1/repositories/{repo.id}/audits", headers=auth(raw))
    assert resp.status_code == 403
    membership = db.session.execute(db.select(Membership).join(User).where(
        User.email == "apiviewer@example.com", Membership.organization_id == repo.organization_id)).scalar_one()
    alice["client"].post(f"/o/{alice['org']}/members/{membership.id}/remove")
    assert viewer.get("/api/v1/me", headers=auth(raw)).status_code == 401


def test_api_tenant_isolation(alice, bob, db):
    pid = make_project(alice["client"], alice["org"])
    upload_new(alice["client"], alice["org"], pid, zip_bytes(FIXTURES / "cleanapp"))
    repo = db.session.execute(db.select(Repository)).scalar_one()
    audit = db.session.execute(db.select(Audit)).scalar_one()
    bob_token = new_token(bob["client"], bob["org"])
    for url in (f"/api/v1/repositories/{repo.id}", f"/api/v1/audits/{audit.id}",
                f"/api/v1/audits/{audit.id}/findings", f"/api/v1/audits/{audit.id}/report.json"):
        assert bob["client"].get(url, headers=auth(bob_token)).status_code == 404, url
    assert bob["client"].get("/api/v1/projects", headers=auth(bob_token)).get_json() == {"projects": []}


def test_api_upload_audit_findings_and_report(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
    repo = db.session.execute(db.select(Repository)).scalar_one()
    raw = new_token(c, org)
    resp = c.post(f"/api/v1/repositories/{repo.id}/audits", headers=auth(raw),
                  data={"archive": (io.BytesIO(zip_bytes(FIXTURES / "vulnapp")), "v.zip")},
                  content_type="multipart/form-data")
    assert resp.status_code == 202
    audit_id = resp.get_json()["audit"]["id"]
    detail = c.get(f"/api/v1/audits/{audit_id}", headers=auth(raw)).get_json()["audit"]
    assert detail["status"] == "succeeded" and detail["risk_level"] == "Critical" and detail["trigger"] == "api"
    assert detail["scores"]["categories"]["security"]["assessed"] is True
    crit = c.get(f"/api/v1/audits/{audit_id}/findings?severity=critical", headers=auth(raw)).get_json()
    assert crit["total"] >= 1 and all(f["severity"] == "critical" for f in crit["findings"])
    assert c.get(f"/api/v1/audits/{audit_id}/findings?severity=bogus", headers=auth(raw)).status_code == 400
    sarif = c.get(f"/api/v1/audits/{audit_id}/report.sarif", headers=auth(raw))
    assert sarif.status_code == 200 and sarif.get_json()["version"] == "2.1.0"
    assert c.post(f"/api/v1/repositories/{repo.id}/audits", headers=auth(raw)).status_code == 400


# ------------------------------------------------------------------------------------------ pull requests
@pytest.fixture
def gh_repo(alice, db, fake_github, monkeypatch):
    c, org = alice["client"], alice["org"]
    c.post(f"/o/{org}/settings/integrations",
           data={"provider": "github", "label": "", "secret": "ghp_validtoken1234567890"})
    cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    pid = make_project(c, org, name="PR Shop")
    c.post(f"/o/{org}/projects/{pid}/repos/new",
           data={"kind": "github", "gh-full_name": "octo/shop", "gh-credential_id": str(cred.id)})
    repo = db.session.execute(db.select(Repository)).scalar_one()
    trees = {}

    def fake_clone(url, dest, ref, **kw):
        shutil.copytree(trees.get(ref, FIXTURES / "vulnapp"), dest, dirs_exist_ok=True)
        return CloneResult(commit_sha=ref if len(ref) == 40 else "e" * 40, ref=ref)

    monkeypatch.setattr("eval_app.audits.workspaces.clone_repo", fake_clone)
    return {**alice, "repo": repo, "trees": trees, "gh": fake_github}


def test_pr_audit_reports_only_findings_introduced_in_changed_files(gh_repo, db, app):
    c, org, repo = gh_repo["client"], gh_repo["org"], gh_repo["repo"]
    c.post(f"/o/{org}/repos/{repo.id}/audits", data={"ref": "main"})
    base = db.session.execute(db.select(Audit)).scalar_one()
    assert base.status == "succeeded" and base.branch == "main"

    pr_tree = Path(app.config["DATA_DIR"]) / "pr-tree"
    shutil.copytree(FIXTURES / "vulnapp", pr_tree)
    (pr_tree / "export.py").write_text(
        "def export(db, name):\n    return db.execute(f\"SELECT * FROM orders WHERE name = '{name}'\")\n")
    (pr_tree / "app.py").write_text((pr_tree / "app.py").read_text() + "\nDEBUG_PASSWORD = 'Zx81kLq0PwN3'\n")
    gh_repo["trees"]["d" * 40] = pr_tree

    resp = c.post(f"/o/{org}/repos/{repo.id}/pulls", data={"number": "5"})
    assert resp.status_code == 302
    pr_audit = db.session.execute(db.select(Audit).where(Audit.pr_number == 5)).scalar_one()
    assert pr_audit.status == "succeeded", pr_audit.error
    assert pr_audit.previous_audit_id == base.id and pr_audit.pr_base_ref == "main"
    assert pr_audit.changed_files == ["export.py"] and pr_audit.branch == "feature/export"

    from eval_app.findings.services import pr_introduced

    introduced = pr_introduced(pr_audit)
    assert {(f.rule_id, f.file_path) for f in introduced} == {("eval:database.sql-string-formatting", "export.py")}
    # app.py also gained a new finding, but app.py is not in the PR's changed files list
    assert any(f.file_path == "app.py" and f.lifecycle == "new" for f in pr_audit.findings)

    page = c.get(f"/o/{org}/audits/{pr_audit.id}").data.decode()
    assert "Pull request #5" in page and "1</strong> finding(s) introduced" in page

    raw = new_token(c, org)
    api_introduced = c.get(f"/api/v1/audits/{pr_audit.id}/findings?introduced=1", headers=auth(raw)).get_json()
    assert [f["file_path"] for f in api_introduced["findings"]] == ["export.py"]
    detail = c.get(f"/api/v1/audits/{pr_audit.id}", headers=auth(raw)).get_json()["audit"]
    assert detail["pull_request"]["introduced_counts"]["high"] == 1

    c.post(f"/o/{org}/audits/{pr_audit.id}/pr-comment")
    assert len(gh_repo["gh"]["comments"]) == 1
    comment = gh_repo["gh"]["comments"][0]
    assert "1 finding(s) introduced" in comment and "export.py" in comment and "Zx81kLq0" not in comment

    # PR audits never become the baseline for later branch audits
    c.post(f"/o/{org}/repos/{repo.id}/audits", data={"ref": "main"})
    latest = db.session.execute(db.select(Audit).order_by(Audit.created_at.desc()).limit(1)).scalar_one()
    assert latest.previous_audit_id == base.id


def test_closed_pr_rejected(gh_repo, db):
    gh_repo["gh"]["pull_state"]["state"] = "closed"
    raw = new_token(gh_repo["client"], gh_repo["org"])
    resp = gh_repo["client"].post(f"/api/v1/repositories/{gh_repo['repo'].id}/pulls/5/audits", headers=auth(raw))
    assert resp.status_code == 422 and "closed" in resp.get_json()["error"]


def test_ci_script_end_to_end_against_api(gh_repo, db, monkeypatch, tmp_path, capsys):
    """Drive scripts/eval_ci.py through the Flask test client instead of real HTTP."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
    import eval_ci

    c, org, repo = gh_repo["client"], gh_repo["org"], gh_repo["repo"]
    raw = new_token(c, org)

    def call(base, token, method, path, body=None, raw_out=False, **kw):
        resp = c.open("/api/v1" + path, method=method, json=body, headers=auth(token))
        if resp.status_code >= 400:
            raise SystemExit(f"HTTP {resp.status_code}")
        return resp.data.decode() if (raw_out or kw.get("raw")) else resp.get_json()

    monkeypatch.setattr(eval_ci, "call", call)
    monkeypatch.setenv("EVAL_TOKEN", raw)
    sarif = tmp_path / "out.sarif"
    code = eval_ci.main(["--url", "https://eval.test", "--repository", str(repo.id), "--fail-on", "critical",
                         "--sarif", str(sarif)])
    assert code == 1 and sarif.exists()  # vulnapp has a critical (AWS key) open finding
    assert "FAIL" in capsys.readouterr().err
    code = eval_ci.main(["--url", "https://eval.test", "--repository", str(repo.id), "--pr", "5",
                         "--fail-on", "critical"])
    assert code == 0  # nothing critical introduced by the PR (its tree equals main here)
