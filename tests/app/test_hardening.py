"""Regression tests for the self-audit fixes in the web app and worker."""

from __future__ import annotations

from datetime import timedelta

from werkzeug.middleware.proxy_fix import ProxyFix

from eval_app import create_app
from eval_app.audits.services import expire_stale_audits
from eval_app.audits.tasks import run_audit
from eval_app.integrations.services import github_clone_url
from eval_app.models import Audit, IntegrationCredential, Membership, Organization, Repository, Upload, User, utcnow
from tests.app.helpers import make_project, upload_new, zip_bytes
from tests.conftest import FIXTURES, login, register


def _add_member(db, org_slug, client, email, role="member"):
    register(client, email, org_name="Own " + email.split("@")[0])
    user = db.session.execute(db.select(User).where(User.email == email)).scalar_one()
    org = db.session.execute(db.select(Organization).where(Organization.slug == org_slug)).scalar_one()
    db.session.add(Membership(user_id=user.id, organization_id=org.id, role=role))
    db.session.commit()


def test_member_cannot_bind_org_credential_to_new_repo(app, alice, db, fake_github):
    c, org = alice["client"], alice["org"]
    c.post(f"/o/{org}/settings/integrations",
           data={"provider": "github", "label": "", "secret": "ghp_validtoken1234567890"})
    cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    pid = make_project(c, org)
    carol = app.test_client()
    _add_member(db, org, carol, "carol@example.com")
    form = carol.get(f"/o/{org}/projects/{pid}/repos/new")
    assert str(cred.id).encode() not in form.data  # credentials are not offered to members
    resp = carol.post(f"/o/{org}/projects/{pid}/repos/new",
                      data={"kind": "github", "gh-full_name": "octo/shop", "gh-credential_id": str(cred.id)})
    assert resp.status_code == 403
    assert db.session.scalar(db.select(db.func.count(Repository.id))) == 0
    # Without a credential, members can still connect public repositories.
    resp = carol.post(f"/o/{org}/projects/{pid}/repos/new", data={"kind": "github", "gh-full_name": "octo/shop"})
    assert resp.status_code == 302


def test_clone_url_follows_github_api_url(app):
    assert github_clone_url("octo/shop") == "https://github.com/octo/shop.git"
    app.config["GITHUB_API_URL"] = "https://ghe.example.com/api/v3"
    assert github_clone_url("octo/shop") == "https://ghe.example.com/octo/shop.git"


def test_redelivered_running_audit_is_failed_not_stuck(alice, db):
    c, org = alice["client"], alice["org"]
    upload_new(c, org, make_project(c, org), zip_bytes(FIXTURES / "cleanapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    audit.status = "running"  # as if the worker died mid-audit and Celery redelivered the task
    db.session.commit()
    assert run_audit.run(str(audit.id)) == "failed"
    db.session.refresh(audit)
    assert audit.status == "failed" and "stopped unexpectedly" in audit.error and audit.finished_at


def test_stale_audits_expire_and_free_the_org_limit(alice, db, app):
    c, org_slug = alice["client"], alice["org"]
    upload_new(c, org_slug, make_project(c, org_slug), zip_bytes(FIXTURES / "cleanapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    audit.status = "running"
    audit.started_at = utcnow() - timedelta(seconds=app.config["ANALYZER_TIMEOUT_SECONDS"] * 6 + 600)
    db.session.commit()
    org = db.session.get(Organization, audit.organization_id)
    assert expire_stale_audits(org) == 1
    db.session.refresh(audit)
    assert audit.status == "failed"
    fresh = Audit(organization_id=org.id, repository_id=audit.repository_id, status="running", stage="x",
                  started_at=utcnow())
    db.session.add(fresh)
    db.session.commit()
    assert expire_stale_audits(org) == 0


def test_deleting_project_removes_uploaded_archives(alice, db, app):
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
    upload = db.session.execute(db.select(Upload)).scalar_one()
    stored = app.config["DATA_DIR"] / upload.stored_path
    assert stored.exists()
    assert c.post(f"/o/{org}/projects/{pid}/delete").status_code == 302
    assert not stored.exists()


def test_org_creation_is_capped_per_user(alice, db, app):
    app.config["MAX_ORGS_PER_USER"] = 2
    c = alice["client"]
    c.post("/orgs", data={"name": "Second"})
    resp = c.post("/orgs", data={"name": "Third"})
    assert resp.status_code == 200 and b"at most 2 organizations" in resp.data
    assert db.session.scalar(db.select(db.func.count(Organization.id))) == 2


def test_csp_pins_cdn_packages(client):
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/" in csp
    assert "https://cdn.jsdelivr.net " not in csp and "https://cdn.jsdelivr.net;" not in csp


def test_login_limited_per_ip_across_emails(app, client):
    app.config["LOGIN_IP_RATE_LIMIT"] = 3
    for i in range(3):
        login(client, f"user{i}@example.com", "Wrong-password-1")
    assert login(client, "other@example.com", "Wrong-password-1").status_code == 429


def test_rate_limiter_does_not_fail_open_without_redis(app, client):
    app.config["RATELIMIT_REDIS_URL"] = "redis://127.0.0.1:1/0"  # nothing listens here
    limit = app.config["LOGIN_RATE_LIMIT"]
    for _ in range(limit):
        login(client, "a@example.com", "Wrong-password-1")
    assert login(client, "a@example.com", "Wrong-password-1").status_code == 429


def test_proxy_fix_is_opt_in(tmp_path):
    assert not isinstance(create_app("testing", {"DATA_DIR": tmp_path}).wsgi_app, ProxyFix)
    app = create_app("testing", {"DATA_DIR": tmp_path, "PROXY_FIX_HOPS": 1})
    assert isinstance(app.wsgi_app, ProxyFix)
