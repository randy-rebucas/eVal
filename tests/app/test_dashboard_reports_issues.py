from __future__ import annotations

import io
import json
import shutil
from datetime import timedelta

import pytest

from eval_app.findings.services import today
from eval_app.models import Audit, Finding, GitHubIssueLink, IntegrationCredential, Repository
from tests.app.helpers import make_project, upload_new, zip_bytes
from tests.conftest import FIXTURES, register


@pytest.fixture
def audited(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    assert audit.status == "succeeded"
    return {**alice, "audit": audit}


def test_audit_dashboard_renders_scores_and_findings(audited):
    c, org, audit = audited["client"], audited["org"], audited["audit"]
    page = c.get(f"/o/{org}/audits/{audit.id}")
    html = page.data.decode()
    assert page.status_code == 200
    for label in ("Security", "Testing", "DevOps &amp; Operations", "Category scores", "Analyzer coverage"):
        assert label in html
    assert "not assessed" in html  # e.g. performance analyzers were not run in this fast test configuration
    assert "Hardcoded aws access key" in html
    critical = c.get(f"/o/{org}/audits/{audit.id}?severity=critical").data.decode()
    no_tests = next(f for f in audit.findings if f.rule_id == "eval:testing.no-tests")
    aws = next(f for f in audit.findings if f.rule_id == "eval:secrets.aws-access-key")
    assert f"/findings/{aws.id}" in critical and f"/findings/{no_tests.id}" not in critical


def test_finding_detail_and_triage(audited, db):
    c, org, audit = audited["client"], audited["org"], audited["audit"]
    f = next(x for x in audit.findings if x.rule_id == "eval:secrets.aws-access-key")
    page = c.get(f"/o/{org}/findings/{f.id}")
    assert page.status_code == 200 and b"Recommended remediation" in page.data
    assert b"AKIAIOSFODNN7EXAMPLE" not in page.data
    c.post(f"/o/{org}/findings/{f.id}/triage", data={"status": "accepted_risk"})  # no reason/owner/date
    db.session.refresh(f)
    assert f.triage_status == "open"
    review = (today() + timedelta(days=30)).isoformat()
    c.post(f"/o/{org}/findings/{f.id}/triage", data={
        "status": "accepted_risk", "reason": "Test fixture key; never deployed.", "owner": "Platform team",
        "expires_on": review})
    db.session.refresh(f)
    assert (f.triage_status, f.triage_owner, f.triage_expires_on.isoformat()) == ("accepted_risk", "Platform team",
                                                                                 review)
    default_view = c.get(f"/o/{org}/audits/{audit.id}").data.decode()
    assert "Hardcoded aws access key" not in default_view and "triaged" in default_view
    md = c.get(f"/o/{org}/audits/{audit.id}/report.md").data.decode()
    assert "Hardcoded aws access key" not in md
    md_all = c.get(f"/o/{org}/audits/{audit.id}/report.md?all=1").data.decode()
    assert "Hardcoded aws access key" in md_all
    assert c.post(f"/o/{org}/findings/{f.id}/triage", data={"status": "bogus"}).status_code == 302
    db.session.refresh(f)
    assert f.triage_status == "accepted_risk"


def test_viewer_cannot_triage(app, audited, db):
    v = app.test_client()
    register(v, "viewer@example.com", "Viewer Org")
    audited["client"].post(f"/o/{audited['org']}/members", data={"email": "viewer@example.com", "role": "viewer"})
    f = audited["audit"].findings[0]
    assert v.get(f"/o/{audited['org']}/findings/{f.id}").status_code == 200
    assert v.post(f"/o/{audited['org']}/findings/{f.id}/triage", data={"status": "fixed"}).status_code == 403


def test_untrusted_content_is_escaped_everywhere(audited, db):
    c, org, audit = audited["client"], audited["org"], audited["audit"]
    payload = '<script>alert("x")</script><img src=x onerror=alert(1)>'
    f = audit.findings[0]
    f.title, f.evidence, f.description, f.file_path = payload, payload, payload, "a|b`<b>.py"
    db.session.commit()
    for url in (f"/o/{org}/audits/{audit.id}?triage=all", f"/o/{org}/findings/{f.id}",
                f"/o/{org}/audits/{audit.id}/report.html?all=1"):
        body = c.get(url).data.decode()
        assert "<script>alert" not in body and "<img src=x" not in body, url
        assert "&lt;script&gt;" in body


def test_report_exports(audited):
    c, org, audit = audited["client"], audited["org"], audited["audit"]
    for fmt, ctype in (("json", "application/json"), ("md", "text/markdown"), ("html", "text/html"),
                       ("sarif", "application/sarif+json")):
        resp = c.get(f"/o/{org}/audits/{audit.id}/report.{fmt}")
        assert resp.status_code == 200 and resp.headers["Content-Type"].startswith(ctype), fmt
        assert "attachment" in resp.headers["Content-Disposition"]
        assert resp.headers["Content-Security-Policy"].startswith("default-src 'none'")
    data = json.loads(c.get(f"/o/{org}/audits/{audit.id}/report.json").data)
    assert data["scores"]["risk"] == "Critical" and data["disclaimer"]
    sarif = json.loads(c.get(f"/o/{org}/audits/{audit.id}/report.sarif").data)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "eVal"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    located = [r for r in run["results"] if "locations" in r]
    assert located and located[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert c.get(f"/o/{org}/audits/{audit.id}/report.exe").status_code == 404


def test_reports_are_tenant_scoped(audited, bob):
    audit = audited["audit"]
    assert bob["client"].get(f"/o/{bob['org']}/audits/{audit.id}/report.json").status_code == 404
    f = audit.findings[0]
    assert bob["client"].get(f"/o/{bob['org']}/findings/{f.id}").status_code == 404
    assert bob["client"].post(f"/o/{bob['org']}/findings/{f.id}/triage", data={"status": "fixed"}).status_code == 404


def test_compare_two_audits(audited, db, app):
    c, org, first = audited["client"], audited["org"], audited["audit"]
    repo = db.session.execute(db.select(Repository)).scalar_one()
    src = app.config["DATA_DIR"] / "v2"
    shutil.copytree(FIXTURES / "vulnapp", src)
    (src / "Dockerfile").unlink()
    (src / "extra.py").write_text(
        "import requests\nr = requests.get('https://x.example')\nDEBUG_TOKEN = 'zq8Xk2pLm9Rt4Vw7'\n")
    c.post(f"/o/{org}/repos/{repo.id}/upload", data={"archive": (io.BytesIO(zip_bytes(src)), "v2.zip")},
           content_type="multipart/form-data")
    second = db.session.execute(db.select(Audit).order_by(Audit.created_at.desc()).limit(1)).scalar_one()
    page = c.get(f"/o/{org}/audits/{second.id}/compare").data.decode()
    assert "Introduced (1)" in page and "Container runs as root" in page and "Hardcoded credential" in page
    assert c.get(f"/o/{org}/audits/{second.id}/compare?base={first.id}").status_code == 200
    dash = c.get(f"/o/{org}").data.decode()
    assert "Repositories by risk" in dash and "vulnapp" in dash and "Revisions" in dash


def test_compare_rejects_audits_from_other_repositories(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"), name="one")
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"), name="two")
    a, b = db.session.execute(db.select(Audit).order_by(Audit.created_at)).scalars().all()
    assert c.get(f"/o/{org}/audits/{b.id}/compare?base={a.id}").status_code == 404


# ----------------------------------------------------------------------------------------- GitHub issues
@pytest.fixture
def github_audit(alice, db, fake_github, monkeypatch):
    c, org = alice["client"], alice["org"]
    c.post(f"/o/{org}/settings/integrations",
           data={"provider": "github", "label": "", "secret": "ghp_validtoken1234567890"})
    pid = make_project(c, org, name="GitHub Shop")
    cred_id = db.session.execute(db.select(IntegrationCredential.id)).scalar_one()
    c.post(f"/o/{org}/projects/{pid}/repos/new",
           data={"kind": "github", "gh-full_name": "octo/shop", "gh-credential_id": str(cred_id)})

    def fake_clone(url, dest, ref, **kw):
        assert kw["token"] == "ghp_validtoken1234567890"  # decrypted only inside the worker
        shutil.copytree(FIXTURES / "vulnapp", dest, dirs_exist_ok=True)
        from eval_engine.workspace import CloneResult

        return CloneResult(commit_sha="c" * 40, ref=ref)

    monkeypatch.setattr("eval_app.audits.workspaces.clone_repo", fake_clone)
    repo = db.session.execute(db.select(Repository)).scalar_one()
    c.post(f"/o/{org}/repos/{repo.id}/audits", data={"ref": "main"})
    audit = db.session.execute(db.select(Audit)).scalar_one()
    assert audit.status == "succeeded", audit.error
    return {**alice, "audit": audit, "gh": fake_github}


def test_create_github_issues_for_selected_findings(github_audit, db):
    c, org, audit, gh = github_audit["client"], github_audit["org"], github_audit["audit"], github_audit["gh"]
    targets = [f for f in audit.findings if f.rule_id in ("eval:secrets.aws-access-key", "eval:testing.no-tests")]
    resp = c.post(f"/o/{org}/audits/{audit.id}/issues", data={"finding_ids": [str(f.id) for f in targets]})
    assert resp.status_code == 302
    links = db.session.execute(db.select(GitHubIssueLink)).scalars().all()
    assert len(links) == 2 and {link.fingerprint for link in links} == {f.fingerprint for f in targets}
    aws_issue = next(i for i in gh["issues"] if "aws" in i["title"].lower())
    assert aws_issue["title"].startswith("[eVal][critical]")
    assert "AKIAIOSFODNN7EXAMPLE" not in aws_issue["body"] and "Recommended remediation" in aws_issue["body"]
    assert "severity:critical" in aws_issue["labels"]
    # Re-submitting does not create duplicates.
    c.post(f"/o/{org}/audits/{audit.id}/issues", data={"finding_ids": [str(f.id) for f in targets]})
    assert len(gh["issues"]) == 2
    page = c.get(f"/o/{org}/audits/{audit.id}?triage=all").data.decode()
    assert "https://github.com/octo/shop/issues/1" in page


def test_issue_creation_requires_member_role(app, github_audit):
    v = app.test_client()
    register(v, "v2@example.com", "Viewer Two")
    github_audit["client"].post(f"/o/{github_audit['org']}/members", data={"email": "v2@example.com", "role": "viewer"})
    f = github_audit["audit"].findings[0]
    assert v.post(f"/o/{github_audit['org']}/audits/{github_audit['audit'].id}/issues",
                  data={"finding_ids": [str(f.id)]}).status_code == 403


def test_issue_creation_rejected_for_upload_repos(audited, db, fake_github):
    c, org, audit = audited["client"], audited["org"], audited["audit"]
    c.post(f"/o/{org}/audits/{audit.id}/issues", data={"finding_ids": [str(audit.findings[0].id)]})
    assert db.session.scalar(db.select(db.func.count(GitHubIssueLink.id))) == 0
    assert fake_github["issues"] == []


def test_issue_creation_ignores_findings_from_other_audits(github_audit, db):
    """Finding IDs from another audit (even same org) are not accepted for this audit's issue batch."""
    c, org = github_audit["client"], github_audit["org"]
    pid = make_project(c, org, name="Other")
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    other = db.session.execute(db.select(Finding).where(Finding.audit_id != github_audit["audit"].id)).scalars().first()
    assert other is not None
    resp = c.post(f"/o/{org}/audits/{github_audit['audit'].id}/issues", data={"finding_ids": [str(other.id)]})
    assert resp.status_code == 302
    assert github_audit["gh"]["issues"] == []
