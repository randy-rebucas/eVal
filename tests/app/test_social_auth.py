"""Social sign-in with GitHub, Google and LinkedIn (providers faked; no network)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from eval_app.auth import social
from eval_app.models import Membership, User, UserIdentity
from tests.conftest import login, register

PROFILES = {
    "good": social.Profile(subject="g-1", email="Dana@Example.com", email_verified=True, name="Dana"),
    "unverified": social.Profile(subject="g-2", email="eve@example.com", email_verified=False, name="Eve"),
    "alice": social.Profile(subject="g-3", email="alice@example.com", email_verified=True, name="Alice"),
}


@pytest.fixture
def providers(app, monkeypatch):
    app.config.update(AUTH_GOOGLE_CLIENT_ID="gid", AUTH_GOOGLE_CLIENT_SECRET="gsecret",
                      AUTH_LINKEDIN_CLIENT_ID="lid", AUTH_LINKEDIN_CLIENT_SECRET="lsecret",
                      GITHUB_OAUTH_CLIENT_ID="hid", GITHUB_OAUTH_CLIENT_SECRET="hsecret")
    monkeypatch.setattr(social, "exchange_code", lambda key, code, redirect_uri: f"token-{code}")
    monkeypatch.setattr(social, "fetch_profile", lambda key, token: PROFILES[token.removeprefix("token-")])


def _begin(client, provider, path=None):
    resp = client.get(path or f"/login/{provider}")
    assert resp.status_code == 302, resp.data[:200]
    return parse_qs(urlsplit(resp.headers["Location"]).query)


def _finish(client, provider, code, path=None):
    state = _begin(client, provider, path)["state"][0]
    return client.get(f"/login/{provider}/callback?code={code}&state={state}")


def test_buttons_only_for_configured_providers(app, client):
    assert b"Continue with" not in client.get("/login").data
    app.config.update(AUTH_LINKEDIN_CLIENT_ID="lid", AUTH_LINKEDIN_CLIENT_SECRET="lsecret")
    page = client.get("/login").data
    assert b"Continue with LinkedIn" in page and b"Continue with Google" not in page
    assert client.get("/login/google").status_code == 404


@pytest.mark.parametrize("provider,host", [("google", "accounts.google.com"), ("linkedin", "www.linkedin.com"),
                                           ("github", "github.com")])
def test_authorize_redirect(client, providers, provider, host):
    resp = client.get(f"/login/{provider}")
    loc = urlsplit(resp.headers["Location"])
    q = parse_qs(loc.query)
    assert loc.hostname == host and q["redirect_uri"] == [f"http://localhost/login/{provider}/callback"]
    assert q["scope"] == [social.PROVIDERS[provider].scope] and len(q["state"][0]) > 30


def test_first_sign_in_creates_account_and_workspace(client, db, providers):
    resp = _finish(client, "google", "good")
    assert resp.status_code == 302 and "/o/" in resp.headers["Location"]
    user = db.session.execute(db.select(User)).scalar_one()
    assert user.email == "dana@example.com" and not user.has_password and not user.check_password("!unusable")
    assert db.session.execute(db.select(Membership)).scalar_one().role == "owner"
    assert client.get("/account").status_code == 200

    client.post("/logout")
    resp = _finish(client, "google", "good")  # second sign-in reuses the account
    assert resp.headers["Location"].endswith("/orgs")
    assert db.session.scalar(db.select(db.func.count(User.id))) == 1


def test_state_must_match_and_is_single_use(client, db, providers):
    _begin(client, "google")
    resp = client.get("/login/google/callback?code=good&state=forged")
    assert resp.headers["Location"].endswith("/login")
    state = _begin(client, "google")["state"][0]
    client.get(f"/login/linkedin/callback?code=good&state={state}")  # state is bound to its provider
    assert db.session.scalar(db.select(db.func.count(User.id))) == 0


def test_unverified_email_and_closed_registration_rejected(app, client, db, providers):
    resp = _finish(client, "google", "unverified")
    assert resp.headers["Location"].endswith("/login")
    app.config["ALLOW_REGISTRATION"] = False
    page = client.get(_finish(client, "linkedin", "good").headers["Location"])
    assert b"Registration is closed" in page.data
    assert db.session.scalar(db.select(db.func.count(User.id))) == 0


def test_existing_email_is_not_taken_over(alice, app, db, providers):
    """Someone signing in with a provider account using alice's address must not get into alice's account."""
    other = app.test_client()
    page = other.get(_finish(other, "google", "alice").headers["Location"])
    assert b"already uses alice@example.com" in page.data
    assert db.session.scalar(db.select(db.func.count(UserIdentity.id))) == 0
    assert other.get("/account").status_code == 302  # still logged out


def test_link_then_sign_in_and_unlink(alice, app, db, providers):
    c = alice["client"]
    assert c.get("/account/connect/google").status_code == 302  # CSRF disabled in tests
    resp = _finish(c, "google", "alice", path="/account/connect/google")
    assert resp.headers["Location"].endswith("/account")
    identity = db.session.execute(db.select(UserIdentity)).scalar_one()
    assert (identity.provider, identity.subject) == ("google", "g-3")

    fresh = app.test_client()
    resp = _finish(fresh, "google", "alice")
    assert resp.headers["Location"].endswith("/orgs") and fresh.get("/account").status_code == 200

    c.post("/account/identities/google/delete")
    assert db.session.scalar(db.select(db.func.count(UserIdentity.id))) == 0


def test_cannot_link_an_identity_owned_by_someone_else(app, client, db, providers):
    _finish(client, "google", "good")  # dana owns google g-1
    other = app.test_client()
    register(other, "frank@example.com", "Frankco")
    login(other, "frank@example.com")
    _finish(other, "google", "good", path="/account/connect/google")
    owner = db.session.execute(db.select(UserIdentity)).scalar_one().user
    assert owner.email == "dana@example.com"


def test_social_only_user_cannot_remove_last_sign_in_method(client, db, providers):
    _finish(client, "linkedin", "good")
    page = client.post("/account/identities/linkedin/delete", follow_redirects=True)
    assert b"only way to sign in" in page.data
    assert db.session.scalar(db.select(db.func.count(UserIdentity.id))) == 1


def test_profile_parsing(app, monkeypatch):
    calls = {
        "https://api.github.com/user": {"id": 42, "login": "octocat", "name": None},
        "https://api.github.com/user/emails": [{"email": "x@y.z", "primary": False, "verified": True},
                                               {"email": "oct@y.z", "primary": True, "verified": True}],
        social.LINKEDIN_USERINFO: {"sub": "li-9", "email": "l@y.z", "email_verified": "true", "name": "Li"},
    }
    monkeypatch.setattr(social, "_json", lambda method, url, **kw: calls[url])
    with app.test_request_context():
        gh = social.fetch_profile("github", "t")
        li = social.fetch_profile("linkedin", "t")
    assert (gh.subject, gh.email, gh.email_verified, gh.name) == ("42", "oct@y.z", True, "octocat")
    assert (li.subject, li.email_verified) == ("li-9", True)
