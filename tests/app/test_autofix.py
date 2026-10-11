"""AI auto-fix in the app: generate a reviewed diff, download it as a patch, open it as a pull request."""

from __future__ import annotations

import re
import shutil

import pytest

from eval_app.models import Audit, Finding, FixProposal, IntegrationCredential, Repository
from eval_engine.ai import StaticProvider
from tests.app.helpers import make_project, upload_new, zip_bytes
from tests.app.test_ai_settings import add_anthropic_key
from tests.conftest import FIXTURES

SQL_FIND = "conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"
SQL_FIX = "conn.execute(\"SELECT * FROM users WHERE name = ?\", (name,))"


@pytest.fixture
def ai_on(alice, db, monkeypatch):
    c, org = alice["client"], alice["org"]
    add_anthropic_key(c, org)
    cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    c.post(f"/o/{org}/settings/ai", data={"enabled": "on", "provider": "anthropic", "credential_id": str(cred.id)})
    prompts = []

    def responder(system, user, schema):
        prompts.append(user)
        if "fixes" not in schema["properties"]:  # audit-time enrichment: explain nothing
            return {"explanations": []} if "explanations" in schema["properties"] else \
                {"summary": "", "top_risks": [], "observations": []}
        ids = re.findall(r'"id": "([0-9a-f-]{36})"', user)
        return {"fixes": [{"id": ids[0], "summary": "Use a parameterised query.",
                           "edits": [{"file": "app.py", "find": SQL_FIND, "replace": SQL_FIX}]}]
                + [{"id": i, "summary": "Needs a design decision.", "edits": []} for i in ids[1:]]}

    monkeypatch.setattr("eval_app.ai_config.build_provider",
                        lambda name, **kw: StaticProvider(responder, name="anthropic", model="claude-opus-5-5"))
    return {**alice, "prompts": prompts}


def _finding(db, rule):
    return db.session.execute(db.select(Finding).where(Finding.rule_id == rule)).scalars().first()


def test_fix_upload_repo_produces_reviewable_patch(ai_on, db):
    c, org = ai_on["client"], ai_on["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    sql, key = _finding(db, "eval:database.sql-string-formatting"), _finding(db, "eval:secrets.aws-access-key")
    page = c.get(f"/o/{org}/audits/{audit.id}").data.decode()
    assert "Fix selected with AI" in page

    resp = c.post(f"/o/{org}/audits/{audit.id}/fixes", data={"finding_ids": [str(sql.id), str(key.id)]})
    fix = db.session.execute(db.select(FixProposal)).scalar_one()
    assert resp.headers["Location"].endswith(f"/fixes/{fix.id}")
    assert fix.status == "ready" and fix.ai_model == "anthropic claude-opus-5-5"
    assert "AKIAIOSFODNN7EXAMPLE" not in ai_on["prompts"][-1]  # secrets masked before sending
    assert f"-    rows = {SQL_FIND}" in fix.diff and f"+    rows = {SQL_FIX}" in fix.diff
    assert fix.diff.startswith("diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n")
    assert [x["id"] for x in fix.results["fixed"]] == [str(sql.id)]
    assert fix.results["failed"][0]["reason"] == "Needs a design decision."
    # The patched tree was re-audited: the SQL finding is gone and nothing new appeared in app.py.
    assert fix.verification["verdict"] == "passed", fix.verification
    assert fix.verification["resolved"] == [str(sql.id)] and fix.verification["introduced"] == []
    assert "database" in fix.verification["analyzers"] and "osv" not in fix.verification["analyzers"]

    page = c.get(f"/o/{org}/fixes/{fix.id}").data.decode()
    assert "Verified: every fixed finding is gone" in page
    assert "Proposed changes" in page and "Download .patch" in page and "Open pull request" not in page
    patch = c.get(f"/o/{org}/fixes/{fix.id}.patch")
    assert patch.status_code == 200 and patch.data.decode() == fix.diff
    assert "attachment" in patch.headers["Content-Disposition"]
    resp = c.post(f"/o/{org}/fixes/{fix.id}/pull-request", follow_redirects=True)
    assert b"download the patch instead" in resp.data


def test_fix_github_repo_opens_pull_request(ai_on, db, fake_github, monkeypatch):
    c, org = ai_on["client"], ai_on["org"]
    c.post(f"/o/{org}/settings/integrations",
           data={"provider": "github", "label": "", "secret": "ghp_validtoken1234567890"})
    gh = db.session.execute(db.select(IntegrationCredential).where(IntegrationCredential.provider == "github")) \
        .scalar_one()
    pid = make_project(c, org)
    c.post(f"/o/{org}/projects/{pid}/repos/new",
           data={"kind": "github", "gh-full_name": "octo/shop", "gh-credential_id": str(gh.id)})
    repo = db.session.execute(db.select(Repository)).scalar_one()

    def fake_clone(url, dest, ref, **kw):
        shutil.copytree(FIXTURES / "vulnapp", dest, dirs_exist_ok=True)
        from eval_engine.workspace import CloneResult

        return CloneResult(commit_sha="c" * 40, ref=ref)

    monkeypatch.setattr("eval_app.audits.workspaces.clone_repo", fake_clone)
    c.post(f"/o/{org}/repos/{repo.id}/audits", data={"ref": "main"})
    sql = _finding(db, "eval:database.sql-string-formatting")
    c.post(f"/o/{org}/findings/{sql.id}/fix")  # single-finding button
    fix = db.session.execute(db.select(FixProposal)).scalar_one()
    assert fix.status == "ready" and fix.files[0]["blob_sha"] == "blob-app.py"
    assert ("GET", "/repos/octo/shop/contents/app.py", "Bearer ghp_validtoken1234567890") in fake_github["calls"]

    resp = c.post(f"/o/{org}/fixes/{fix.id}/pull-request")
    assert resp.status_code == 302
    db.session.refresh(fix)
    assert (fix.status, fix.pr_number, fix.branch) == ("pr_opened", 7, f"eval/fix-{fix.id.hex[:10]}")
    (_, _, ref), (_, put_path, put), (_, _, pull) = fake_github["writes"]
    assert ref == {"ref": f"refs/heads/{fix.branch}", "sha": "c" * 40}
    assert put_path == "/repos/octo/shop/contents/app.py" and put["sha"] == "blob-app.py"
    assert put["branch"] == fix.branch
    assert pull["head"] == fix.branch and pull["base"] == "main" and "SQL statement" in pull["body"]
    assert "Verified by re-audit" in pull["body"] and "Re-audited with:" in pull["body"]
    # A published fix cannot be pushed twice.
    c.post(f"/o/{org}/fixes/{fix.id}/pull-request")
    assert len(fake_github["writes"]) == 3
    assert b"View PR #7" in c.get(f"/o/{org}/fixes/{fix.id}").data


def test_fix_that_introduces_a_finding_is_flagged_and_gated(ai_on, db, fake_github, monkeypatch):
    c, org = ai_on["client"], ai_on["org"]
    bad_fix = SQL_FIX + '\n    token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"'

    def responder(system, user, schema):
        if "fixes" not in schema["properties"]:
            return {"explanations": []} if "explanations" in schema["properties"] else \
                {"summary": "", "top_risks": [], "observations": []}
        fid = re.findall(r'"id": "([0-9a-f-]{36})"', user)[0]
        return {"fixes": [{"id": fid, "summary": "Parameterised.",
                           "edits": [{"file": "app.py", "find": SQL_FIND, "replace": bad_fix}]}]}

    monkeypatch.setattr("eval_app.ai_config.build_provider",
                        lambda name, **kw: StaticProvider(responder, name="anthropic", model="claude-opus-5-5"))
    c.post(f"/o/{org}/settings/integrations",
           data={"provider": "github", "label": "", "secret": "ghp_validtoken1234567890"})
    gh = db.session.execute(db.select(IntegrationCredential).where(IntegrationCredential.provider == "github")) \
        .scalar_one()
    pid = make_project(c, org)
    c.post(f"/o/{org}/projects/{pid}/repos/new",
           data={"kind": "github", "gh-full_name": "octo/shop", "gh-credential_id": str(gh.id)})
    repo = db.session.execute(db.select(Repository)).scalar_one()

    def fake_clone(url, dest, ref, **kw):
        shutil.copytree(FIXTURES / "vulnapp", dest, dirs_exist_ok=True)
        from eval_engine.workspace import CloneResult

        return CloneResult(commit_sha="c" * 40, ref=ref)

    monkeypatch.setattr("eval_app.audits.workspaces.clone_repo", fake_clone)
    c.post(f"/o/{org}/repos/{repo.id}/audits", data={"ref": "main"})
    sql = _finding(db, "eval:database.sql-string-formatting")
    c.post(f"/o/{org}/findings/{sql.id}/fix")
    fix = db.session.execute(db.select(FixProposal)).scalar_one()
    v = fix.verification
    assert v["verdict"] == "regressed" and v["resolved"] == [str(sql.id)], v
    assert any(i["file_path"] == "app.py" and i["rule_id"].startswith("eval:secrets") for i in v["introduced"])
    assert "re-audit found new problems" in c.get(f"/o/{org}/fixes/{fix.id}").data.decode()

    # Opening the PR needs an explicit acknowledgement.
    resp = c.post(f"/o/{org}/fixes/{fix.id}/pull-request", follow_redirects=True)
    assert b"confirm that you want to open" in resp.data and fake_github["writes"] == []
    c.post(f"/o/{org}/fixes/{fix.id}/pull-request", data={"accept_regression": "on"})
    db.session.refresh(fix)
    assert fix.status == "pr_opened"
    assert "Re-audit found new problems" in fake_github["writes"][-1][2]["body"]


def test_fix_requires_ai_member_role_and_tenant(alice, bob, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    sql = _finding(db, "eval:database.sql-string-formatting")
    page = c.get(f"/o/{org}/audits/{audit.id}").data.decode()
    assert "Fix selected with AI" not in page  # AI not enabled
    resp = c.post(f"/o/{org}/findings/{sql.id}/fix", follow_redirects=True)
    assert b"Enable AI" in resp.data
    assert db.session.scalar(db.select(db.func.count(FixProposal.id))) == 0
    # Another organization cannot request fixes for (or see) alice's findings.
    assert bob["client"].post(f"/o/{bob['org']}/findings/{sql.id}/fix").status_code == 404
    assert bob["client"].post(f"/o/{alice['org']}/findings/{sql.id}/fix").status_code == 404


def _ready_fix(ai_on, db):
    c, org = ai_on["client"], ai_on["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    sql = _finding(db, "eval:database.sql-string-formatting")
    c.post(f"/o/{org}/findings/{sql.id}/fix")
    fix = db.session.execute(db.select(FixProposal)).scalar_one()
    assert fix.status == "ready" and fix.revisions == []
    return fix


def _edit(client, org, fix, content, revision=None, path="app.py"):
    return client.post(f"/o/{org}/fixes/{fix.id}/files", content_type="multipart/form-data", follow_redirects=True,
                       data={"revision": str(revision or len(fix.revisions) or 1), "path": path, "content": content})


def test_hand_edit_is_reaudited_and_kept_as_a_revision(ai_on, db):
    c, org = ai_on["client"], ai_on["org"]
    fix = _ready_fix(ai_on, db)
    ai_diff = fix.diff
    page = c.get(f"/o/{org}/fixes/{fix.id}").data.decode()
    assert "Edit the fix" in page and "Save and re-audit" in page and 'name="revision" value="1"' in page
    edited = fix.files[0]["after"].replace(SQL_FIX, SQL_FIX + "  # reviewed").replace("\n", "\r\n")

    resp = _edit(c, org, fix, edited)
    assert b"Edit saved" in resp.data
    db.session.refresh(fix)
    assert fix.status == "ready" and fix.is_edited
    assert "\r" not in fix.files[0]["after"]  # browser CRLF folded back to the file's LF line endings
    assert f"+    rows = {SQL_FIX}  # reviewed" in fix.diff
    assert fix.verification["verdict"] == "passed", fix.verification
    assert [(r["number"], r["kind"], r["verdict"]) for r in fix.revisions] == [(1, "ai", "passed"),
                                                                               (2, "edit", "passed")]
    assert fix.revisions[0]["diff"] == ai_diff and fix.revisions[1]["author"] == "alice@example.com"
    page = c.get(f"/o/{org}/fixes/{fix.id}").data.decode()
    assert "AI-generated, edited by hand" in page and "Revisions" in page and 'value="2"' in page
    old = c.get(f"/o/{org}/fixes/{fix.id}/revisions/1.patch")
    assert old.status_code == 200 and old.data.decode() == ai_diff

    from eval_app.fixes.services import pr_body

    body = pr_body(fix, {str(f.id): f for f in [_finding(db, "eval:database.sql-string-formatting")]}, "link")
    assert "Edited by hand in eVal" in body and "alice@example.com" in body
    assert "Generated by AI and edited by hand" in body


def test_hand_edit_that_adds_a_problem_is_flagged(ai_on, db):
    c, org = ai_on["client"], ai_on["org"]
    fix = _ready_fix(ai_on, db)
    bad = fix.files[0]["after"].replace(SQL_FIX, SQL_FIX + '\n    token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"')
    _edit(c, org, fix, bad)
    db.session.refresh(fix)
    assert fix.verification["verdict"] == "regressed" and fix.revisions[-1]["verdict"] == "regressed"


def test_hand_edit_rejections(ai_on, db):
    c, org = ai_on["client"], ai_on["org"]
    fix = _ready_fix(ai_on, db)
    after = fix.files[0]["after"]
    assert b"Nothing changed" in _edit(c, org, fix, after).data
    assert b"undo every change" in _edit(c, org, fix, after.replace(SQL_FIX, SQL_FIND)).data
    assert b"Only the files in this fix" in _edit(c, org, fix, "x = 1\n", path="other.py").data
    # Larger than the default 500 KB form limit: parsed (no 413), then refused by the file-size rule.
    assert b"at most 512 KB" in _edit(c, org, fix, "#" * (600 * 1024)).data
    _edit(c, org, fix, after + "# one\n")
    db.session.refresh(fix)
    assert len(fix.revisions) == 2
    # A form opened before that save is stale.
    assert b"changed since you opened it" in _edit(c, org, fix, after + "# two\n", revision=1).data
    db.session.refresh(fix)
    assert len(fix.revisions) == 2


def test_hand_edit_needs_member_open_fix_and_tenant(ai_on, bob, db, app):
    from tests.conftest import register

    c, org = ai_on["client"], ai_on["org"]
    fix = _ready_fix(ai_on, db)
    after = fix.files[0]["after"] + "# edit\n"
    viewer = app.test_client()
    register(viewer, "fixviewer@example.com", "Viewer Co")
    c.post(f"/o/{org}/members", data={"email": "fixviewer@example.com", "role": "viewer"})
    assert "Edit the fix" not in viewer.get(f"/o/{org}/fixes/{fix.id}").data.decode()
    assert _edit(viewer, org, fix, after).status_code == 403
    assert bob["client"].post(f"/o/{bob['org']}/fixes/{fix.id}/files", data={"revision": "1"}).status_code == 404
    assert bob["client"].get(f"/o/{bob['org']}/fixes/{fix.id}/revisions/1.patch").status_code == 404
    fix.status = "pr_opened"
    db.session.commit()
    assert b"not been opened as a pull request" in _edit(c, org, fix, after).data
    db.session.refresh(fix)
    assert fix.revisions == []


def test_fix_page_is_tenant_scoped(ai_on, bob, db):
    c, org = ai_on["client"], ai_on["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    sql = _finding(db, "eval:database.sql-string-formatting")
    c.post(f"/o/{org}/findings/{sql.id}/fix")
    fix = db.session.execute(db.select(FixProposal)).scalar_one()
    assert bob["client"].get(f"/o/{bob['org']}/fixes/{fix.id}").status_code == 404
    assert bob["client"].get(f"/o/{bob['org']}/fixes/{fix.id}.patch").status_code == 404
