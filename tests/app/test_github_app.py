"""GitHub App: JWT auth, verified installation linking, signed webhooks, PR/push audits and check runs."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from eval_app.integrations.github import GitHubClient, GitHubError
from eval_app.models import Audit, AuditEvent, GitHubInstallation, Repository
from eval_engine.workspace import CloneResult
from tests.app.helpers import make_project
from tests.conftest import FIXTURES, org_slug_from, register

SECRET = "whsec-test-0123456789"
INSTALLATION = 4242


@pytest.fixture
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def gh_app(app, alice, db, fake_github, monkeypatch, rsa_key):
    pem = rsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    app.config.update(GITHUB_APP_ID="123", GITHUB_APP_SLUG="eval-test", GITHUB_APP_PRIVATE_KEY=pem,
                      GITHUB_APP_WEBHOOK_SECRET=SECRET, GITHUB_APP_CLIENT_ID="Iv1.app",
                      GITHUB_APP_CLIENT_SECRET="app-secret", PUBLIC_URL="https://eval.example")
    from eval_app.integrations import github_app

    github_app._TOKEN_CACHE.clear()
    state = {"user_installations": {INSTALLATION}, "check_runs": [], "updates": [], "token_requests": 0,
             "clone_tokens": []}
    inner = GitHubClient._request

    def fake_request(self, method, path, **kwargs):
        auth = self._headers.get("Authorization", "")
        if path.startswith("/app/"):
            assert auth.startswith("Bearer ey"), "App endpoints need the app JWT"
            if path == f"/app/installations/{INSTALLATION}/access_tokens":
                state["token_requests"] += 1
                return {"token": "ghs_installation_token_abcdef", "expires_at": "2099-01-01T00:00:00Z"}
            if path == f"/app/installations/{INSTALLATION}":
                return {"id": INSTALLATION, "account": {"login": "octo", "type": "Organization"}}
            raise GitHubError("Not found on GitHub, or the credential lacks access.", 404)
        if path == "/user/installations":
            return {"installations": [{"id": i} for i in state["user_installations"]]}
        if path == "/repos/octo/shop/check-runs" and method == "POST":
            assert auth == "Bearer ghs_installation_token_abcdef"
            state["check_runs"].append(kwargs["json"])
            return {"id": 900 + len(state["check_runs"]), "html_url": "https://github.com/octo/shop/runs/1"}
        if path.startswith("/repos/octo/shop/check-runs/") and method == "PATCH":
            state["updates"].append((int(path.rsplit("/", 1)[1]), kwargs["json"]))
            return {}
        return inner(self, method, path, **kwargs)

    monkeypatch.setattr(GitHubClient, "_request", fake_request)
    monkeypatch.setattr("eval_app.integrations.github.exchange_oauth_code",
                        lambda web, cid, secret, code, redirect: "ghu_user_token_1234567890")
    trees: dict[str, Path] = {}

    def fake_clone(url, dest, ref, **kw):
        state["clone_tokens"].append(kw.get("token"))
        shutil.copytree(trees.get(ref, FIXTURES / "vulnapp"), dest, dirs_exist_ok=True)
        return CloneResult(commit_sha=ref if len(ref) == 40 else "e" * 40, ref=ref)

    monkeypatch.setattr("eval_app.audits.workspaces.clone_repo", fake_clone)
    c, org = alice["client"], alice["org"]
    pid = make_project(c, org, name="App Shop")
    c.post(f"/o/{org}/projects/{pid}/repos/new", data={"kind": "github", "gh-full_name": "octo/shop"})
    repo = db.session.execute(db.select(Repository)).scalar_one()
    assert repo.credential is None
    return {**alice, "state": state, "repo": repo, "trees": trees, "key": rsa_key, "gh": fake_github}


def install(c, org, installation_id=INSTALLATION, code="oauth-code"):
    resp = c.get(f"/o/{org}/settings/github-app/install")
    assert resp.status_code == 302 and "/apps/eval-test/installations/new?state=" in resp.headers["Location"]
    state = resp.headers["Location"].rsplit("state=", 1)[1]
    qs = f"installation_id={installation_id}&setup_action=install&state={state}" + (f"&code={code}" if code else "")
    return c.get(f"/integrations/github/app/setup?{qs}", follow_redirects=True)


def deliver(c, event, payload, secret=SECRET):
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return c.post("/webhooks/github", data=body, content_type="application/json",
                  headers={"X-GitHub-Event": event, "X-Hub-Signature-256": sig, "X-GitHub-Delivery": "d-1"})


def pr_event(action="opened", sha="d" * 40, installation=INSTALLATION, full_name="octo/shop"):
    return {"action": action, "installation": {"id": installation}, "repository": {"full_name": full_name},
            "pull_request": {"number": 5, "head": {"sha": sha}}}


def test_app_jwt_is_rs256_signed_by_the_app_key(gh_app, app):
    from eval_app.integrations.github_app import app_jwt

    token = app_jwt(now=1_700_000_000)
    head, body, sig = token.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    assert json.loads(base64.urlsafe_b64decode(pad(head))) == {"alg": "RS256", "typ": "JWT"}
    claims = json.loads(base64.urlsafe_b64decode(pad(body)))
    assert claims == {"iat": 1_700_000_000 - 60, "exp": 1_700_000_000 + 540, "iss": "123"}
    gh_app["key"].public_key().verify(base64.urlsafe_b64decode(pad(sig)), f"{head}.{body}".encode(),
                                      padding.PKCS1v15(), hashes.SHA256())


def test_webhook_requires_configuration_and_valid_signature(gh_app, app):
    c = gh_app["client"]
    assert deliver(c, "ping", {"zen": "x"}, secret="wrong").status_code == 401
    resp = c.post("/webhooks/github", data=b"{}", headers={"X-GitHub-Event": "ping"})
    assert resp.status_code == 401
    assert deliver(c, "ping", {"zen": "x"}).status_code == 202
    app.config["GITHUB_APP_WEBHOOK_SECRET"] = ""
    assert deliver(c, "ping", {"zen": "x"}).status_code == 404


def test_installation_linking_is_verified(gh_app, db):
    c, org = gh_app["client"], gh_app["org"]
    # Forged installation id: the GitHub user cannot access it.
    gh_app["state"]["user_installations"] = {1}
    assert b"cannot access that installation" in install(c, org).data
    # No user-authorization code: refuse rather than trust the redirect.
    gh_app["state"]["user_installations"] = {INSTALLATION}
    assert b"Request user authorization" in install(c, org, code="").data
    # A replayed / foreign state is rejected.
    resp = c.get(f"/integrations/github/app/setup?installation_id={INSTALLATION}&state=forged&code=x",
                 follow_redirects=True)
    assert b"could not be matched" in resp.data
    assert db.session.scalar(db.select(db.func.count(GitHubInstallation.id))) == 0

    page = install(c, org).data.decode()
    assert "GitHub App installed for octo" in page
    inst = db.session.execute(db.select(GitHubInstallation)).scalar_one()
    assert (inst.installation_id, inst.account_login, inst.account_type) == (INSTALLATION, "octo", "Organization")
    db.session.refresh(gh_app["repo"])
    assert gh_app["repo"].github_installation_id == inst.id  # existing octo/* repositories now use the App
    assert db.session.execute(db.select(AuditEvent).where(AuditEvent.action == "github_app.linked")).scalar_one()


def test_installation_cannot_be_linked_to_a_second_org(gh_app, app, db):
    install(gh_app["client"], gh_app["org"])
    other = app.test_client()
    other_org = org_slug_from(register(other, "mallory@example.com", "Mallory Co"))
    page = install(other, other_org).data.decode()
    assert "already linked to another organization" in page
    assert db.session.execute(db.select(GitHubInstallation)).scalar_one().organization_id != other_org


def test_pull_request_webhook_audits_and_reports_a_check_run(gh_app, db, app):
    c, org, st = gh_app["client"], gh_app["org"], gh_app["state"]
    install(c, org)
    pr_tree = Path(app.config["DATA_DIR"]) / "pr-tree"
    shutil.copytree(FIXTURES / "vulnapp", pr_tree)
    (pr_tree / "export.py").write_text(
        "def export(db, name):\n    return db.execute(f\"SELECT * FROM orders WHERE name = '{name}'\")\n")
    gh_app["trees"]["d" * 40] = pr_tree

    resp = deliver(c, "pull_request", pr_event())
    assert resp.status_code == 202 and len(resp.get_json()["audits"]) == 1
    audit = db.session.execute(db.select(Audit).where(Audit.pr_number == 5)).scalar_one()
    assert audit.status == "succeeded" and audit.trigger == "pull_request" and audit.requested_by_id is None
    assert st["clone_tokens"] == ["ghs_installation_token_abcdef"]  # the App token, not a PAT
    assert st["token_requests"] == 1  # cached for the clone and the check-run calls

    (run,) = st["check_runs"]
    assert run["name"] == "eVal audit" and run["head_sha"] == "d" * 40 and run["external_id"] == str(audit.id)
    assert audit.check_run_id == 901
    (run_id, update), = st["updates"]
    assert run_id == 901 and update["status"] == "completed" and update["conclusion"] == "failure"
    notes = update["output"]["annotations"]
    assert notes[0]["path"] == "export.py" and notes[0]["annotation_level"] == "failure"
    assert "1 blocking" in update["output"]["title"]

    # Redelivery of the same head commit does not start a second audit; a re-run request does.
    assert deliver(c, "pull_request", pr_event(action="synchronize")).get_json()["audits"] == []
    rerun = {"action": "rerequested", "installation": {"id": INSTALLATION}, "repository": {"full_name": "octo/shop"},
             "check_run": {"head_sha": "d" * 40, "pull_requests": [{"number": 5}]}}
    assert len(deliver(c, "check_run", rerun).get_json()["audits"]) == 1


def test_policy_decides_the_check_run_conclusion(gh_app, db, app):
    c, org, repo, st = gh_app["client"], gh_app["org"], gh_app["repo"], gh_app["state"]
    install(c, org)
    c.post(f"/o/{org}/settings/policy", data={"repo": str(repo.id), "policy_toml": "[gate]\nfail_on = 'never'"})
    deliver(c, "pull_request", pr_event())
    assert st["updates"][-1][1]["conclusion"] == "success"
    assert st["updates"][-1][1]["output"]["title"] == "Gate passed"


def test_push_to_default_branch_refreshes_the_baseline(gh_app, db):
    c, org = gh_app["client"], gh_app["org"]
    install(c, org)
    push = {"ref": "refs/heads/main", "after": "f" * 40, "installation": {"id": INSTALLATION},
            "repository": {"full_name": "octo/shop"}}
    assert len(deliver(c, "push", push).get_json()["audits"]) == 1
    audit = db.session.execute(db.select(Audit)).scalar_one()
    assert (audit.trigger, audit.branch, audit.requested_ref) == ("push", "main", "f" * 40)
    assert deliver(c, "push", {**push, "ref": "refs/heads/feature"}).get_json()["audits"] == []
    assert deliver(c, "push", push).get_json()["audits"] == []  # same commit again


def test_events_for_unlinked_installations_or_other_orgs_are_ignored(gh_app, app, db):
    c, org = gh_app["client"], gh_app["org"]
    assert "ignored" in deliver(c, "pull_request", pr_event()).get_json()
    install(c, org)
    # bob has a repository with the same name, but the installation belongs to alice's organization.
    other = app.test_client()
    bob_org = org_slug_from(register(other, "bob2@example.com", "Bob Two"))
    pid = make_project(other, bob_org, name="Copy")
    other.post(f"/o/{bob_org}/projects/{pid}/repos/new", data={"kind": "github", "gh-full_name": "octo/shop"})
    deliver(c, "pull_request", pr_event())
    audits = db.session.execute(db.select(Audit)).scalars().all()
    assert len(audits) == 1 and audits[0].repository_id == gh_app["repo"].id
    # auto_audit off: nothing is started.
    gh_app["repo"].auto_audit = False
    db.session.commit()
    assert deliver(c, "pull_request", pr_event(sha="1" * 40)).get_json()["audits"] == []


def test_uninstall_and_suspend(gh_app, db):
    c, org = gh_app["client"], gh_app["org"]
    install(c, org)
    base = {"installation": {"id": INSTALLATION}}
    deliver(c, "installation", {**base, "action": "suspend"})
    assert db.session.execute(db.select(GitHubInstallation)).scalar_one().suspended is True
    assert deliver(c, "pull_request", pr_event()).get_json() == {"ignored": "installation suspended"}
    deliver(c, "installation", {**base, "action": "unsuspend"})
    deliver(c, "installation", {**base, "action": "deleted"})
    assert db.session.scalar(db.select(db.func.count(GitHubInstallation.id))) == 0
    db.session.refresh(gh_app["repo"])
    assert gh_app["repo"].github_installation_id is None


def test_install_requires_admin_and_csrf_free_link_is_tenant_bound(gh_app, app, db):
    viewer = app.test_client()
    register(viewer, "appviewer@example.com", "Viewer Co")
    gh_app["client"].post(f"/o/{gh_app['org']}/members", data={"email": "appviewer@example.com", "role": "member"})
    assert viewer.get(f"/o/{gh_app['org']}/settings/github-app/install").status_code == 403
    page = gh_app["client"].get(f"/o/{gh_app['org']}/settings/integrations").data.decode()
    assert "Install GitHub App" in page
