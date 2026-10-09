"""Organization dashboard: risk with its reason, coverage, accountability, attempt state, ordering."""

from __future__ import annotations

from datetime import timedelta

import pytest

from eval_app.findings.services import today
from eval_app.models import Audit, Organization, Repository, utcnow
from eval_app.orgs import services
from tests.app.helpers import make_project, upload_new, zip_bytes
from tests.conftest import FIXTURES, login, register


@pytest.fixture
def audited(alice, db):
    c, org = alice["client"], alice["org"]
    upload_new(c, org, make_project(c, org), zip_bytes(FIXTURES / "vulnapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    assert audit.status == "succeeded" and audit.risk_level == "Critical"
    return {**alice, "audit": audit, "repo": audit.repository}


def org_of(db, slug):
    return db.session.execute(db.select(Organization).where(Organization.slug == slug)).scalar_one()


def add_audit(db, repo, minutes=1, **fields):
    audit = Audit(organization_id=repo.organization_id, repository_id=repo.id, branch="main",
                  created_at=utcnow() + timedelta(minutes=minutes), **fields)
    db.session.add(audit)
    db.session.commit()
    return audit


def test_dashboard_leads_with_risk_reason_and_coverage(audited):
    dash = audited["client"].get(f"/o/{audited['org']}").data.decode()
    assert "Open <span class=\"directive-mark\">vulnapp</span> first" in dash
    assert "Hardcoded aws access key" in dash  # the finding that capped Security
    assert "not assessed: " in dash and "categories assessed: Security critical" in dash  # fast analyzers skip some
    assert "rmark-critical" in dash and "<polyline" not in dash
    assert "Scores are risk indicators from automated static analysis" in dash


def test_accepted_risk_is_counted_with_owner_and_review_date(audited, db):
    c, org, audit = audited["client"], audited["org"], audited["audit"]
    aws = next(f for f in audit.findings if f.rule_id == "eval:secrets.aws-access-key")
    review = (today() + timedelta(days=7)).isoformat()
    c.post(f"/o/{org}/findings/{aws.id}/triage", data={
        "status": "accepted_risk", "reason": "Rotated; history rewrite scheduled.", "owner": "Platform team",
        "expires_on": review})
    row = services.portfolio(org_of(db, org))[0]
    assert row.risk == "Critical" and row.accepted.get("critical") == 1 and row.accepted_owners == ["Platform team"]
    dash = c.get(f"/o/{org}").data.decode()
    assert "1 accepted" in dash and "Platform team" in dash and review in dash and "tag-alert" in dash


def test_failed_attempt_is_shown_beside_older_results(audited, db):
    add_audit(db, audited["repo"], status="failed", error="clone timed out")
    row = services.portfolio(org_of(db, audited["org"]))[0]
    assert row.latest.id == audited["audit"].id and row.attempt.status == "failed"
    dash = audited["client"].get(f"/o/{audited['org']}").data.decode()
    assert "Last attempt failed" in dash and "Results from" in dash and "clone timed out" in dash
    assert "older results shown" in dash


def test_pull_request_audits_do_not_describe_the_repository(audited, db):
    add_audit(db, audited["repo"], status="succeeded", pr_number=7, risk_level="Low", overall_score=95.0)
    row = services.portfolio(org_of(db, audited["org"]))[0]
    assert row.latest.id == audited["audit"].id and row.risk == "Critical" and row.attempt is None


def test_unaudited_repository_ranks_above_low(audited, db):
    repo = audited["repo"]
    low = Repository(organization_id=repo.organization_id, project_id=repo.project_id, source="upload", name="aaa-low")
    never = Repository(organization_id=repo.organization_id, project_id=repo.project_id, source="upload", name="zzz")
    db.session.add_all([low, never])
    db.session.commit()
    add_audit(db, low, status="succeeded", risk_level="Low", overall_score=92.0)
    rows = services.portfolio(org_of(db, audited["org"]))
    assert [r.repo.name for r in rows] == ["vulnapp", "zzz", "aaa-low"]
    assert rows[1].risk == "Not assessed"
    summary = services.portfolio_summary(rows)
    assert summary["by_risk"]["Not assessed"] == 1 and summary["first"].repo.name == "vulnapp"


def test_project_filter_and_risk_change_since_last_check(audited, db):
    c, org, repo = audited["client"], audited["org"], audited["repo"]
    other = make_project(c, org, "Platform")
    page = c.get(f"/o/{org}?project={other}").data.decode()
    assert ">vulnapp</a>" not in page and "No repositories in Platform" in page
    assert ">vulnapp</a>" in c.get(f"/o/{org}?project={repo.project_id}").data.decode()
    add_audit(db, repo, minutes=-60 * 24, status="succeeded", risk_level="Moderate", overall_score=70.0,
              finished_at=utcnow() - timedelta(days=1))
    rows = services.portfolio(org_of(db, org))
    assert rows[0].previous_risk == "Moderate"
    rev = services.revisions(rows)
    assert [(r["rev"], r["was"], r["now"], r["worse"]) for r in rev] == [("A", "Moderate", "Critical", True)]
    dash = c.get(f"/o/{org}").data.decode()
    assert "was Moderate before this check" in dash and 'class="rev-letter is-worse">A<' in dash


def test_project_scope_drives_directive_and_counts(audited, db):
    c, org = audited["client"], audited["org"]
    platform = make_project(c, org, "Platform")
    upload_new(c, org, platform, zip_bytes(FIXTURES / "cleanapp"), name="billing")
    page = c.get(f"/o/{org}?project={platform}").data.decode()
    directive = page.split('id="directive-h"')[1].split("</section>")[0]
    assert "vulnapp" not in directive  # the critical repository is outside this scope
    assert '<span class="rail-n">1</span> <span class="rail-l">All</span>' in page and "Platform · 1 repository" in page


def test_state_filter_and_named_notes(audited, db):
    c, org = audited["client"], audited["org"]
    failed = add_audit(db, audited["repo"], status="failed", error="clone timed out")
    page = c.get(f"/o/{org}").data.decode()
    assert f'/audits/{failed.id}">vulnapp: last audit failed</a>' in page
    assert ">vulnapp</a>" in c.get(f"/o/{org}?state=failed").data.decode().split("Revisions")[0]
    stale = c.get(f"/o/{org}?state=stale").data.decode().split("Repositories by risk")[1].split("Revisions")[0]
    assert ">vulnapp</a>" not in stale and "No repositories match" in stale
    assert 'data-confirm="Queue a new audit of vulnapp?"' in page


def test_repeated_finding_becomes_a_pattern(audited, db):
    c, org = audited["client"], audited["org"]
    upload_new(c, org, audited["repo"].project_id, zip_bytes(FIXTURES / "vulnapp"), name="vulnapp-copy")
    summary = services.portfolio_summary(services.portfolio(org_of(db, org)))
    assert summary["first_pattern"]["title"] == "Hardcoded aws access key"
    assert len(summary["first_pattern"]["rows"]) == 2
    page = c.get(f"/o/{org}").data.decode()
    assert 'Fix <span class="directive-mark">Hardcoded aws access key</span> in 2 repositories' in page
    assert "typ. ×2" in page
    drill = c.get(f"/o/{org}?pattern=Hardcoded aws access key").data.decode().split("Revisions")[0]
    assert ">vulnapp</a>" in drill and ">vulnapp-copy</a>" in drill
    assert c.get(f"/o/{org}?pattern=nonsense").status_code == 200  # unknown patterns are ignored


def test_risk_filter_and_viewer_has_no_audit_actions(audited, app, db):
    c, org = audited["client"], audited["org"]
    register_section = c.get(f"/o/{org}?risk=Low").data.decode().split("Repositories by risk")[1].split("Revisions")[0]
    assert ">vulnapp</a>" not in register_section and "No repositories match" in register_section
    v = app.test_client()
    register(v, "viewer@example.com", "ViewerOrg")
    c.post(f"/o/{org}/members", data={"email": "viewer@example.com", "role": "viewer"})
    login(v, "viewer@example.com")
    page = v.get(f"/o/{org}").data.decode()
    assert "vulnapp" in page and "Re-audit" not in page and "Open audit" in page
