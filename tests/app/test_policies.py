"""Organization/repository policies in the app: editing, layering with .eval.toml, gates in the UI and API."""

from __future__ import annotations

import io

from eval_app.models import Audit, Repository
from tests.app.helpers import make_project, upload_new, zip_bytes
from tests.app.test_api_pr import auth, new_token
from tests.conftest import FIXTURES, register


def _latest(db):
    return db.session.execute(db.select(Audit).order_by(Audit.created_at.desc())).scalars().first()


def test_org_policy_is_validated_and_applied(alice, db):
    c, org = alice["client"], alice["org"]
    resp = c.post(f"/o/{org}/settings/policy", data={"policy_toml": "[gate]\nfail_on = 'sometimes'"})
    assert resp.status_code == 400 and b"Policy not saved" in resp.data
    resp = c.post(f"/o/{org}/settings/policy", data={
        "policy_toml": "[rules]\ndisable = ['eval:secrets.*']\n[gate]\nfail_on = 'critical'",
        "allow_repo_policy_file": "on"})
    assert resp.status_code == 302
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    audit = _latest(db)
    assert audit.status == "succeeded"
    assert audit.policy["gate"]["fail_on"] == "critical" and audit.policy["sources"] == ["organization"]
    assert not any(f.rule_id.startswith("eval:secrets") for f in audit.findings)
    assert audit.stats["policy"]["disabled"] > 0
    page = c.get(f"/o/{org}/audits/{audit.id}").data.decode()
    assert "gate passed" in page or "gate failed" in page


def test_repo_policy_file_layers_with_repo_override(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    archive = zip_bytes(FIXTURES / "vulnapp",
                        mutate=lambda z: z.writestr("myrepo-main/.eval.toml", "[gate]\nfail_on = 'never'\n"))
    upload_new(c, org, pid, archive)
    audit = _latest(db)
    assert audit.policy["sources"] == ["file"] and audit.policy["gate"]["fail_on"] == "never"
    raw = new_token(c, org)
    gate = c.get(f"/api/v1/audits/{audit.id}", headers=auth(raw)).get_json()["audit"]["gate"]
    assert gate["passed"] is True and gate["fail_on"] == "never"

    # The repository override sits between the organization and the file; the file still decides fail_on.
    repo = db.session.execute(db.select(Repository)).scalar_one()
    resp = c.post(f"/o/{org}/settings/policy", data={"repo": str(repo.id), "policy_toml":
                                                     "[gate]\nfail_on = 'low'\n[paths]\nexclude = ['app.py']"})
    assert resp.status_code == 302 and repo.policy_toml.startswith("[gate]")
    c.post(f"/o/{org}/repos/{repo.id}/upload", data={"archive": (io.BytesIO(archive), "src.zip")},
           content_type="multipart/form-data")
    audit = _latest(db)
    assert audit.policy["sources"] == ["repository", "file"] and audit.policy["gate"]["fail_on"] == "never"
    assert not any(f.file_path == "app.py" for f in audit.findings)


def test_disabled_repo_file_is_ignored(alice, db):
    c, org = alice["client"], alice["org"]
    c.post(f"/o/{org}/settings/policy", data={"policy_toml": ""})  # checkbox unticked = files disabled
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp",
                                      mutate=lambda z: z.writestr("myrepo-main/.eval.toml", "[gate]\nfail_on='never'")))
    audit = _latest(db)
    assert audit.policy["gate"]["fail_on"] == "high"
    assert any("disabled for this organization" in n for n in audit.stats["policy_notes"])
    raw = new_token(c, org)
    assert c.get(f"/api/v1/audits/{audit.id}", headers=auth(raw)).get_json()["audit"]["gate"]["passed"] is False


def test_invalid_repo_file_is_ignored_not_fatal(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp",
                                      mutate=lambda z: z.writestr("myrepo-main/.eval.toml", "[gate]\nfail_on=3")))
    audit = _latest(db)
    assert audit.status == "succeeded" and audit.policy["sources"] == []
    assert any("gate.fail_on" in n for n in audit.stats["policy_notes"])


def test_only_admins_edit_policy(app, alice, db):
    viewer = app.test_client()
    register(viewer, "polviewer@example.com", "Viewer Co")
    alice["client"].post(f"/o/{alice['org']}/members", data={"email": "polviewer@example.com", "role": "member"})
    assert viewer.get(f"/o/{alice['org']}/settings/policy").status_code == 200
    assert viewer.post(f"/o/{alice['org']}/settings/policy", data={"policy_toml": ""}).status_code == 403


def test_policy_is_tenant_scoped(alice, bob, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
    repo = db.session.execute(db.select(Repository)).scalar_one()
    resp = bob["client"].post(f"/o/{bob['org']}/settings/policy",
                              data={"repo": str(repo.id), "policy_toml": "[gate]\nfail_on='never'"})
    assert resp.status_code == 404 and repo.policy_toml == ""


def test_pr_that_changes_the_policy_file_cannot_relax_its_gate(alice, db, tmp_path):
    from eval_app.policies import effective_policy

    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
    audit = _latest(db)
    (tmp_path / ".eval.toml").write_text("[gate]\nfail_on = 'never'\n")
    assert effective_policy(audit, tmp_path)[0].fail_on == "never"
    audit.pr_number, audit.changed_files = 3, [".eval.toml", "app.py"]
    policy, notes = effective_policy(audit, tmp_path)
    assert policy.fail_on == "high" and notes == [".eval.toml ignored: this pull request changes it."]


def test_evidence_pack(alice, db):
    import csv
    import hashlib
    import json
    import zipfile

    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    audit = _latest(db)
    sql = next(f for f in audit.findings if f.rule_id == "eval:database.sql-string-formatting")
    from datetime import date, timedelta

    review = (date.today() + timedelta(days=90)).isoformat()
    c.post(f"/o/{org}/findings/{sql.id}/triage", data={"status": "accepted_risk", "reason": "=HYPERLINK(evil)",
                                                       "owner": "Payments team", "expires_on": review})
    resp = c.get(f"/o/{org}/audits/{audit.id}/evidence.zip")
    assert resp.status_code == 200 and resp.mimetype == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(resp.data))
    manifest = json.loads(z.read("manifest.json"))
    assert set(manifest["files"]) == {"report.html", "report.json", "report.sarif", "findings.csv",
                                      "compliance-controls.csv", "risk-register.csv", "decisions.csv",
                                      "policy.json", "coverage.json"}
    for name, digest in manifest["files"].items():
        assert hashlib.sha256(z.read(name)).hexdigest() == digest
    register = list(csv.DictReader(io.StringIO(z.read("risk-register.csv").decode())))
    assert register[0]["owner"] == "Payments team" and register[0]["reason"].startswith("'=")  # formula neutralized
    findings = list(csv.DictReader(io.StringIO(z.read("findings.csv").decode())))
    row = next(r for r in findings if r["rule_id"] == "eval:database.sql-string-formatting")
    assert row["cwe"] == "CWE-89" and row["owasp"] == "A03:2021" and row["triage_status"] == "accepted_risk"
    assert "finding.triaged" in z.read("decisions.csv").decode()
    assert "CC6.1" in z.read("compliance-controls.csv").decode()
    page = c.get(f"/o/{org}/findings/{sql.id}").data.decode()
    assert "Compliance mapping" in page and "CWE-89" in page
