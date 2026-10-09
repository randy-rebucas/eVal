"""Triage accountability: reasons, owners (teams or vendors), review dates, expiry, carry-over, risk register."""

from __future__ import annotations

import io
import json
import shutil
from datetime import timedelta
from pathlib import Path

import pytest

from eval_app.findings.services import today
from eval_app.models import Audit, AuditEvent, Finding, Repository
from tests.app.helpers import make_project, upload_new, zip_bytes
from tests.app.test_api_pr import auth, new_token
from tests.conftest import FIXTURES

REASON = "Vendor SDK; the vulnerable code path is not reachable from our usage."


def in_days(n: int) -> str:
    return (today() + timedelta(days=n)).isoformat()


@pytest.fixture
def audited(alice, db):
    c, org = alice["client"], alice["org"]
    upload_new(c, org, make_project(c, org), zip_bytes(FIXTURES / "vulnapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    f = next(x for x in audit.findings if x.rule_id == "eval:secrets.aws-access-key")
    return {**alice, "audit": audit, "finding": f}


def triage(ctx, **data):
    return ctx["client"].post(f"/o/{ctx['org']}/findings/{ctx['finding'].id}/triage", data=data)


@pytest.mark.parametrize(("data", "message"), [
    ({"reason": REASON, "owner": "Vendor: Acme"}, b"review date"),
    ({"owner": "Vendor: Acme", "expires_on": in_days(30)}, b"Explain the decision"),
    ({"reason": REASON, "expires_on": in_days(30)}, b"owns the fix"),
    ({"reason": REASON, "owner": "Vendor: Acme", "expires_on": in_days(0)}, b"in the future"),
    ({"reason": REASON, "owner": "Vendor: Acme", "expires_on": in_days(400)}, b"at most 365 days"),
    ({"reason": REASON, "owner": "Vendor: Acme", "expires_on": "next week"}, b"YYYY-MM-DD"),
])
def test_accepted_risk_requires_reason_owner_and_bounded_review_date(audited, db, data, message):
    resp = triage(audited, status="accepted_risk", **data)
    page = audited["client"].get(resp.headers["Location"]).data
    db.session.refresh(audited["finding"])
    assert audited["finding"].triage_status == "open"
    assert message in page


def test_accepted_risk_records_who_what_and_until_when(audited, db):
    triage(audited, status="accepted_risk", reason=REASON, owner="Vendor: Acme", expires_on=in_days(90))
    f = audited["finding"]
    db.session.refresh(f)
    assert (f.triage_status, f.triage_reason, f.triage_owner) == ("accepted_risk", REASON, "Vendor: Acme")
    assert f.triage_expires_on.isoformat() == in_days(90) and f.triaged_by.email == "alice@example.com"
    event = db.session.execute(db.select(AuditEvent).where(AuditEvent.action == "finding.triaged")).scalar_one()
    assert event.details["owner"] == "Vendor: Acme" and event.details["expires_on"] == in_days(90)
    page = audited["client"].get(f"/o/{audited['org']}/findings/{f.id}").data.decode()
    assert "Vendor: Acme" in page and in_days(90) in page and "alice@example.com" in page


def test_false_positive_needs_reason_but_date_is_optional(audited, db):
    f = audited["finding"]
    triage(audited, status="false_positive", reason="short")
    db.session.refresh(f)
    assert f.triage_status == "open"
    triage(audited, status="false_positive", reason="Example key from AWS documentation, not a credential.")
    db.session.refresh(f)
    assert f.triage_status == "false_positive" and f.triage_expires_on is None


def test_reopening_clears_justification(audited, db):
    triage(audited, status="accepted_risk", reason=REASON, owner="Payments team", expires_on=in_days(10))
    triage(audited, status="open")
    f = audited["finding"]
    db.session.refresh(f)
    assert (f.triage_status, f.triage_reason, f.triage_owner, f.triage_expires_on) == ("open", "", "", None)


def test_lapsed_acceptance_reopens_and_shows_what_lapsed(audited, db):
    triage(audited, status="accepted_risk", reason=REASON, owner="Vendor: Acme", expires_on=in_days(10))
    f = audited["finding"]
    db.session.refresh(f)
    f.triage_expires_on = today()  # the review date has arrived
    db.session.commit()
    c, org = audited["client"], audited["org"]
    page = c.get(f"/o/{org}/findings/{f.id}").data.decode()
    db.session.refresh(f)
    assert f.triage_status == "open" and f.triage_owner == "Vendor: Acme"
    assert "Reopened" in page and "lapsed" in page
    assert "Hardcoded aws access key" in c.get(f"/o/{org}/audits/{audited['audit'].id}").data.decode()
    assert db.session.execute(db.select(AuditEvent).where(AuditEvent.action == "finding.triage_expired")).first()


def test_lapsed_acceptance_reopens_for_api_and_ci_gate(audited, db):
    c, org, f = audited["client"], audited["org"], audited["finding"]
    token = new_token(c, org)
    triage(audited, status="accepted_risk", reason=REASON, owner="Vendor: Acme", expires_on=in_days(10))
    db.session.refresh(f)
    f.triage_expires_on = today() - timedelta(days=1)
    db.session.commit()
    data = c.get(f"/api/v1/audits/{audited['audit'].id}/findings?severity=critical", headers=auth(token)).get_json()
    item = next(x for x in data["findings"] if x["id"] == str(f.id))
    assert item["triage"]["expired"] is True and item["triage"]["owner"] == "Vendor: Acme"


def _reupload(audited, db):
    c, org = audited["client"], audited["org"]
    repo = db.session.execute(db.select(Repository)).scalar_one()
    src = Path(c.application.config["DATA_DIR"]) / "v2"
    shutil.copytree(FIXTURES / "vulnapp", src, dirs_exist_ok=True)
    c.post(f"/o/{org}/repos/{repo.id}/upload", data={"archive": (io.BytesIO(zip_bytes(src)), "v2.zip")},
           content_type="multipart/form-data")
    second = db.session.execute(db.select(Audit).order_by(Audit.created_at.desc()).limit(1)).scalar_one()
    assert second.status == "succeeded", second.error
    return next(x for x in second.findings if x.fingerprint == audited["finding"].fingerprint)


def test_decision_carries_to_next_audit_with_reason_owner_and_date(audited, db):
    triage(audited, status="accepted_risk", reason=REASON, owner="Vendor: Acme", expires_on=in_days(60))
    carried = _reupload(audited, db)
    assert (carried.triage_status, carried.triage_reason, carried.triage_owner) == ("accepted_risk", REASON,
                                                                                    "Vendor: Acme")
    assert carried.triage_expires_on.isoformat() == in_days(60) and carried.triaged_by.email == "alice@example.com"


def test_lapsed_decision_is_not_carried(audited, db):
    triage(audited, status="accepted_risk", reason=REASON, owner="Vendor: Acme", expires_on=in_days(60))
    f = audited["finding"]
    db.session.refresh(f)
    f.triage_expires_on = today()
    db.session.commit()
    assert _reupload(audited, db).triage_status == "open"


def test_risk_register_lists_latest_decisions_by_review_date(audited, db):
    c, org, audit = audited["client"], audited["org"], audited["audit"]
    triage(audited, status="accepted_risk", reason=REASON, owner="Vendor: Acme", expires_on=in_days(200))
    other = next(x for x in audit.findings if x.rule_id == "eval:database.sql-string-formatting")
    c.post(f"/o/{org}/findings/{other.id}/triage", data={
        "status": "accepted_risk", "reason": "Legacy report module owned by another team.",
        "owner": "Reporting team", "expires_on": in_days(14)})
    page = c.get(f"/o/{org}/risks").data.decode()
    assert page.index("Reporting team") < page.index("Vendor: Acme")  # soonest review first
    assert "due soon" in page
    token = new_token(c, org)
    risks = c.get("/api/v1/risks", headers=auth(token)).get_json()["risks"]
    assert [r["triage"]["owner"] for r in risks] == ["Reporting team", "Vendor: Acme"]


def test_api_triage_endpoint(audited, db, app):
    c, org, f = audited["client"], audited["org"], audited["finding"]
    token = new_token(c, org)
    url = f"/api/v1/findings/{f.id}/triage"
    bad = c.post(url, json={"status": "accepted_risk", "reason": REASON}, headers=auth(token))
    assert bad.status_code == 422 and "owns the fix" in bad.get_json()["error"]
    ok = c.post(url, json={"status": "accepted_risk", "reason": REASON, "owner": "Vendor: Acme",
                           "expires_on": in_days(30)}, headers=auth(token))
    assert ok.status_code == 200
    assert ok.get_json()["finding"]["triage"] == {
        "status": "accepted_risk", "reason": REASON, "owner": "Vendor: Acme", "expires_on": in_days(30),
        "triaged_by": "alice@example.com", "triaged_at": ok.get_json()["finding"]["triage"]["triaged_at"],
        "expired": False}


def test_reports_show_decisions_and_sarif_marks_them_suppressed(audited, db):
    c, org, audit = audited["client"], audited["org"], audited["audit"]
    triage(audited, status="accepted_risk", reason=REASON, owner="Vendor: Acme", expires_on=in_days(30))
    md = c.get(f"/o/{org}/audits/{audit.id}/report.md?all=1").data.decode()
    assert f"**Triage:** accepted risk until {in_days(30)} · owner: Vendor: Acme" in md
    sarif = json.loads(c.get(f"/o/{org}/audits/{audit.id}/report.sarif").data)
    suppressed = [r for r in sarif["runs"][0]["results"] if r.get("suppressions")]
    assert len(suppressed) == 1 and "Vendor: Acme" in suppressed[0]["suppressions"][0]["justification"]
    assert db.session.scalar(db.select(db.func.count(Finding.id)).where(Finding.triage_status == "open")) > 1
