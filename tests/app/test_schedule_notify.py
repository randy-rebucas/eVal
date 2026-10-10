"""Scheduled re-audits and regression notifications (Slack, Teams, signed webhooks)."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
from datetime import timedelta

import pytest

from eval_app import notifications
from eval_app.audits.schedule import due, run_due
from eval_app.models import Audit, NotificationChannel, Repository, utcnow
from tests.app.helpers import make_project, upload_new, zip_bytes
from tests.conftest import FIXTURES, register


class Posts:
    def __init__(self):
        self.calls = []

    def __call__(self, url, data=None, headers=None, timeout=None, allow_redirects=True):
        assert allow_redirects is False and timeout
        self.calls.append({"url": url, "body": data, "headers": headers})

        class R:
            status_code = 200

        return R()


@pytest.fixture
def posts(monkeypatch):
    p = Posts()
    monkeypatch.setattr("requests.post", p)
    return p


def _audits(db):
    return db.session.execute(db.select(Audit).order_by(Audit.created_at)).scalars().all()


def test_schedule_due_and_run(alice, db):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
    repo = db.session.execute(db.select(Repository)).scalar_one()
    assert not due(repo)  # schedule off
    c.post(f"/o/{org}/repos/{repo.id}/automation", data={"schedule": "daily"})
    assert repo.schedule == "daily"
    assert not due(repo)  # just audited
    assert due(repo, now=utcnow() + timedelta(hours=24))
    started = run_due(now=utcnow() + timedelta(hours=24))
    assert len(started) == 1
    audit = _audits(db)[-1]
    assert audit.trigger == "schedule" and audit.status == "succeeded" and audit.upload_id is not None
    assert run_due(now=utcnow() + timedelta(hours=1)) == []  # not due again yet
    assert c.post(f"/o/{org}/repos/{repo.id}/automation", data={"schedule": "hourly"}).status_code == 400


@pytest.mark.parametrize("kind,url,ok", [
    ("slack", "https://hooks.slack.com/services/T/B/x", True),
    ("slack", "https://evil.example.com/services/T/B/x", False),
    ("slack", "http://hooks.slack.com/services/T/B/x", False),
    ("teams", "https://acme.webhook.office.com/webhookb2/x", True),
    ("teams", "https://webhook.office.com.evil.io/x", False),
    ("webhook", "https://user:pw@hooks.example.com/x", False),
    ("webhook", "https://hooks.example.com:8443/x", False),
])
def test_url_validation(app, kind, url, ok):
    if ok:
        assert notifications.validate_url(kind, url)
    else:
        with pytest.raises(notifications.NotificationError):
            notifications.validate_url(kind, url)


def test_generic_webhook_rejects_private_addresses(app):
    app.config["TESTING"] = False
    try:
        for host in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "localhost"):
            with pytest.raises(notifications.NotificationError, match="public address"):
                notifications.validate_url("webhook", f"https://{host}/hook")
    finally:
        app.config["TESTING"] = True


def test_channels_ui_secret_once_and_admin_only(app, alice, db):
    c, org = alice["client"], alice["org"]
    resp = c.post(f"/o/{org}/settings/notifications", data={"kind": "webhook", "label": "SIEM",
                                                            "url": "https://siem.example.com/eval",
                                                            "events": ["audit.regressed"]})
    assert resp.status_code == 200 and resp.headers["Cache-Control"] == "no-store"
    channel = db.session.execute(db.select(NotificationChannel)).scalar_one()
    assert channel.url_host == "siem.example.com" and channel.events == ["audit.regressed"]
    assert b"siem.example.com/eval" not in channel.encrypted_url
    page = c.get(f"/o/{org}/settings/notifications").data.decode()
    assert "siem.example.com" in page and "/eval" not in page and "Signing secret" not in page
    bad = c.post(f"/o/{org}/settings/notifications", data={"kind": "slack", "url": "https://example.com/x"},
                 follow_redirects=True)
    assert b"hooks.slack.com" in bad.data
    member = app.test_client()
    register(member, "notifmember@example.com", "M Co")
    c.post(f"/o/{org}/members", data={"email": "notifmember@example.com", "role": "member"})
    assert member.post(f"/o/{org}/settings/notifications", data={"kind": "slack"}).status_code == 403
    assert member.post(f"/o/{org}/settings/notifications/{channel.id}/delete").status_code == 403


def _regressing_upload(c, org, pid, db):
    """Audit a clean app, then the vulnerable one as the same repository: a regression."""
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
    repo = db.session.execute(db.select(Repository)).scalar_one()
    c.post(f"/o/{org}/repos/{repo.id}/upload", data={"archive": (io.BytesIO(zip_bytes(FIXTURES / "vulnapp")),
                                                                 "src.zip")}, content_type="multipart/form-data")
    return repo


def test_regression_is_sent_to_slack_and_signed_webhook(alice, db, posts, app):
    c, org = alice["client"], alice["org"]
    app.config["PUBLIC_URL"] = "https://eval.example"
    c.post(f"/o/{org}/settings/notifications", data={"kind": "slack", "url": "https://hooks.slack.com/services/T/B/x",
                                                     "events": ["audit.regressed", "gate.failed"]})
    resp = c.post(f"/o/{org}/settings/notifications", data={"kind": "webhook", "url": "https://siem.example.com/e",
                                                            "events": ["audit.regressed"]})
    secret = resp.data.decode().split('user-select-all">')[1].split("<")[0]
    pid = make_project(c, org)
    _regressing_upload(c, org, pid, db)

    slack = [p for p in posts.calls if "slack" in p["url"]]
    hook = [p for p in posts.calls if "siem" in p["url"]]
    texts = [json.loads(p["body"])["text"] for p in slack]
    assert any("regressed" in t and "new high/critical" in t for t in texts)
    assert any("policy gate failed" in t for t in texts)  # passed on the clean app, fails now
    assert any("https://eval.example/o/" in t for t in texts)
    (delivery,) = hook
    body = delivery["body"]
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert delivery["headers"]["X-Eval-Signature"] == expected
    payload = json.loads(body)
    assert payload["event"] == "audit.regressed" and payload["details"]["new_severe"] >= 1
    assert "AKIA" not in body.decode()  # finding titles only, never evidence
    channels = db.session.execute(db.select(NotificationChannel)).scalars().all()
    assert all(ch.last_status == "HTTP 200" for ch in channels)


def test_no_regression_no_message(alice, db, posts):
    c, org = alice["client"], alice["org"]
    c.post(f"/o/{org}/settings/notifications", data={"kind": "slack", "url": "https://hooks.slack.com/services/T/B/x",
                                                     "events": ["audit.regressed"]})
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
    repo = db.session.execute(db.select(Repository)).scalar_one()
    c.post(f"/o/{org}/repos/{repo.id}/upload", data={"archive": (io.BytesIO(zip_bytes(FIXTURES / "cleanapp")),
                                                                 "src.zip")}, content_type="multipart/form-data")
    assert posts.calls == []


def test_notifications_are_tenant_scoped(alice, bob, db, posts):
    bob["client"].post(f"/o/{bob['org']}/settings/notifications",
                       data={"kind": "slack", "url": "https://hooks.slack.com/services/T/B/bob"})
    channel = db.session.execute(db.select(NotificationChannel)).scalar_one()
    pid = make_project(alice["client"], alice["org"])
    _regressing_upload(alice["client"], alice["org"], pid, db)
    assert posts.calls == []  # alice's regression never reaches bob's channel
    assert alice["client"].post(f"/o/{alice['org']}/settings/notifications/{channel.id}/delete").status_code == 404
