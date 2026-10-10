"""Enterprise identity: TOTP MFA, OIDC SSO, SCIM provisioning, org MFA/SSO enforcement, audit log."""

from __future__ import annotations

import base64
import json
import re
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from eval_app.models import AuditEvent, Membership, ScimToken, SsoConnection, SsoIdentity, User
from eval_app.security import totp
from tests.conftest import PASSWORD, register

# ----------------------------------------------------------------------------------------------- TOTP


def test_totp_rfc6238_vector_and_replay_guard():
    secret = base64.b32encode(b"12345678901234567890").decode()  # RFC 6238 test key (SHA-1)
    assert totp.code_at(secret, 59 // 30) == "287082"  # RFC 6238 T=59 -> 94287082 (last 6 digits)
    assert totp.code_at(secret, 1111111109 // 30) == "081804"
    step = totp.verify(secret, "287082", None, now=59)
    assert step == 1
    assert totp.verify(secret, "287082", step, now=59) is None  # replay rejected
    assert totp.verify(secret, "000000", None, now=59) is None
    codes, hashes_ = totp.new_recovery_codes()
    left = totp.use_recovery_code(hashes_, codes[0].upper())
    assert len(left) == 9 and totp.use_recovery_code(left, codes[0]) is None


def _enable_mfa(c):
    c.post("/account/mfa", data={"action": "start"})
    page = c.get("/account/mfa").data.decode()
    secret = re.search(r'user-select-all mono">([A-Z2-7]+)<', page).group(1)
    resp = c.post("/account/mfa", data={"action": "enable", "code": totp.code_at(secret, int(time.time() // 30))})
    codes = re.search(r'<pre class="mono user-select-all">([^<]+)</pre>', resp.data.decode()).group(1).split()
    assert resp.headers["Cache-Control"] == "no-store" and len(codes) == 10
    return secret, codes


def test_mfa_enrolment_and_login_challenge(app, db):
    c = app.test_client()
    register(c, "mfa@example.com", "MFA Co")
    secret, codes = _enable_mfa(c)
    user = db.session.execute(db.select(User).where(User.email == "mfa@example.com")).scalar_one()
    assert user.mfa_enabled and secret.encode() not in user.mfa_secret_enc  # stored encrypted
    c.post("/logout")
    resp = c.post("/login", data={"email": "mfa@example.com", "password": PASSWORD})
    assert resp.headers["Location"].endswith("/login/mfa")
    assert c.get("/account").status_code == 302  # not logged in yet
    assert b"not valid" in c.post("/login/mfa", data={"code": "123456"}).data
    # The current step was consumed at enrolment, so use the next one (replay guard).
    nxt = totp.code_at(secret, int(time.time() // 30) + 1)
    resp = c.post("/login/mfa", data={"code": nxt})
    assert resp.status_code == 302 and c.get("/account").status_code == 200
    c.post("/logout")
    c.post("/login", data={"email": "mfa@example.com", "password": PASSWORD})
    assert c.post("/login/mfa", data={"code": codes[0]}).status_code == 302  # recovery code
    db.session.refresh(user)
    assert len(user.mfa_recovery) == 9
    actions = {e.action for e in db.session.execute(db.select(AuditEvent)).scalars()}
    assert {"auth.mfa_enabled", "auth.mfa_failed", "auth.mfa_recovery_used", "auth.login"} <= actions


def test_org_can_require_mfa(alice, db):
    c, org = alice["client"], alice["org"]
    page = c.post(f"/o/{org}/settings/security", data={"action": "mfa", "require_mfa": "on"},
                  follow_redirects=True).data
    assert b"Turn on two-factor authentication for your own account first" in page  # no self-lockout
    _enable_mfa(c)
    c.post(f"/o/{org}/settings/security", data={"action": "mfa", "require_mfa": "on"})
    assert c.get(f"/o/{org}").status_code == 200
    other = c.application.test_client()
    register(other, "nomfa@example.com", "Other")
    c.post(f"/o/{org}/members", data={"email": "nomfa@example.com", "role": "member"})
    resp = other.get(f"/o/{org}")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/account/mfa")


# ------------------------------------------------------------------------------------------------ SSO
ISSUER = "https://idp.example.com"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeIdP:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = self.key.public_key().public_numbers()
        self.jwks = {"keys": [{"kty": "RSA", "kid": "k1", "alg": "RS256",
                               "n": _b64(nums.n.to_bytes(256, "big")), "e": _b64(nums.e.to_bytes(3, "big"))}]}
        self.claims = {}
        self.nonce = None

    def id_token(self, **overrides):
        claims = {"iss": ISSUER, "aud": "eval-client", "sub": "idp-user-1", "email": "dev@acme.com",
                  "email_verified": True, "name": "Dev One", "iat": int(time.time()),
                  "exp": int(time.time()) + 300, "nonce": self.nonce, **self.claims, **overrides}
        head = _b64(json.dumps({"alg": "RS256", "kid": "k1"}).encode())
        body = _b64(json.dumps(claims).encode())
        sig = self.key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{head}.{body}.{_b64(sig)}"


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    from eval_app.auth import sso

    sso._cache.clear()

    class Resp:
        def __init__(self, data, status=200):
            self._d, self.status_code = data, status

        def json(self):
            return self._d

        def raise_for_status(self):
            pass

    def get(url, **kw):
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return Resp({"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize",
                         "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/jwks"})
        if url == f"{ISSUER}/jwks":
            return Resp(fake.jwks)
        raise AssertionError(url)

    def post(url, data=None, **kw):
        assert url == f"{ISSUER}/token" and data["code_verifier"] and data["client_secret"] == "idp-secret"
        return Resp({"id_token": fake.id_token()})

    monkeypatch.setattr("eval_app.auth.sso.requests.get", get)
    monkeypatch.setattr("eval_app.auth.sso.requests.post", post)
    return fake


def _configure(c, org, **extra):
    data = {"action": "sso", "issuer": ISSUER, "client_id": "eval-client", "client_secret": "idp-secret",
            "domains": "acme.com", "default_role": "member", "auto_provision": "on", "enabled": "on", **extra}
    return c.post(f"/o/{org}/settings/security", data=data)


def _sso_login(client, idp, org, **query):
    resp = client.get(f"/sso/o/{org}", query_string=query)
    assert resp.status_code == 302, resp.data[:300]
    q = parse_qs(urlsplit(resp.headers["Location"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["client_id"] == ["eval-client"]
    idp.nonce = q["nonce"][0]
    return client.get(f"/sso/callback?code=abc&state={q['state'][0]}")


def test_sso_provisions_and_signs_in(alice, app, db, idp):
    c, org = alice["client"], alice["org"]
    assert _configure(c, org).status_code == 302
    conn = db.session.execute(db.select(SsoConnection)).scalar_one()
    assert conn.domains == ["acme.com"] and b"idp-secret" not in conn.encrypted_client_secret
    browser = app.test_client()
    resp = _sso_login(browser, idp, org)
    assert resp.status_code == 302 and resp.headers["Location"].endswith(f"/o/{org}")
    user = db.session.execute(db.select(User).where(User.email == "dev@acme.com")).scalar_one()
    assert user.managed_by_org_id == conn.organization_id and not user.has_password
    assert db.session.execute(db.select(Membership).where(Membership.user_id == user.id)).scalar_one().role == "member"
    assert browser.get(f"/o/{org}").status_code == 200
    # Second sign-in finds the same identity.
    browser.post("/logout")
    assert _sso_login(browser, idp, org).status_code == 302
    assert db.session.scalar(db.select(db.func.count(SsoIdentity.id))) == 1


def test_sso_never_takes_over_existing_accounts(alice, app, db, idp):
    c, org = alice["client"], alice["org"]
    _configure(c, org)
    victim = app.test_client()
    register(victim, "dev@acme.com", "Victim Org")  # registered independently, not managed by alice's org
    attacker = app.test_client()
    resp = _sso_login(attacker, idp, org)
    assert resp.headers["Location"].endswith("/sso")
    assert attacker.get("/account").status_code == 302  # not signed in
    assert db.session.scalar(db.select(db.func.count(SsoIdentity.id))) == 0


@pytest.mark.parametrize("override,message", [
    ({"aud": "someone-else"}, b"different application"),
    ({"iss": "https://evil.example.com"}, b"different provider"),
    ({"exp": 1000}, b"expired"),
    ({"nonce": "replayed"}, b"does not belong to this sign-in"),
    ({"email": "dev@other.com"}, b"domain is not allowed"),
    ({"email_verified": False}, b"unverified"),
])
def test_sso_rejects_bad_tokens(alice, app, db, idp, override, message):
    _configure(alice["client"], alice["org"])
    idp.claims = override
    browser = app.test_client()
    resp = _sso_login(browser, idp, alice["org"])
    assert resp.headers["Location"].endswith("/sso")
    assert message in browser.get("/sso").data


def test_sso_rejects_forged_signature(alice, app, db, idp):
    _configure(alice["client"], alice["org"])
    idp.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # not the published key
    browser = app.test_client()
    _sso_login(browser, idp, alice["org"])
    assert b"signature could not be verified" in browser.get("/sso").data


def test_sso_enforcement_keeps_owner_break_glass(alice, app, db, idp):
    c, org = alice["client"], alice["org"]
    _configure(c, org, enforce="on")
    assert c.get(f"/o/{org}").status_code == 200  # owner with a password session
    member = app.test_client()
    register(member, "pw-member@example.com", "PW")
    c.post(f"/o/{org}/members", data={"email": "pw-member@example.com", "role": "member"})
    resp = member.get(f"/o/{org}")
    assert resp.status_code == 302 and f"/sso/o/{org}" in resp.headers["Location"]


def test_sso_link_existing_account_while_signed_in(alice, app, db, idp):
    c, org = alice["client"], alice["org"]
    _configure(c, org)
    member = app.test_client()
    register(member, "dev@acme.com", "Own Org")
    c.post(f"/o/{org}/members", data={"email": "dev@acme.com", "role": "member"})
    resp = _sso_login(member, idp, org, link="1")
    assert resp.status_code == 302
    user = db.session.execute(db.select(User).where(User.email == "dev@acme.com")).scalar_one()
    assert db.session.execute(db.select(SsoIdentity)).scalar_one().user_id == user.id
    assert user.has_password and user.managed_by_org_id is None  # still the user's own account


# ----------------------------------------------------------------------------------------------- SCIM
@pytest.fixture
def scim(alice, db):
    c, org = alice["client"], alice["org"]
    resp = c.post(f"/o/{org}/settings/security", data={"action": "scim_token"})
    raw = re.search(r"(scim_[A-Za-z0-9_\-]{40,})", resp.data.decode()).group(1)
    assert db.session.execute(db.select(ScimToken)).scalar_one().token_hash != raw
    return {**alice, "h": {"Authorization": f"Bearer {raw}", "Content-Type": "application/scim+json"}}


def test_scim_lifecycle(scim, app, db):
    c, h = scim["client"], scim["h"]
    assert c.get("/scim/v2/Users").status_code == 401
    created = c.post("/scim/v2/Users", headers=h, json={"userName": "New.Hire@Acme.com", "active": True,
                                                         "name": {"givenName": "New", "familyName": "Hire"}})
    assert created.status_code == 201
    uid = created.get_json()["id"]
    assert created.get_json()["userName"] == "new.hire@acme.com" and created.get_json()["active"] is True
    assert c.post("/scim/v2/Users", headers=h, json={"userName": "new.hire@acme.com"}).status_code == 409
    found = c.get('/scim/v2/Users?filter=userName eq "new.hire@acme.com"', headers=h).get_json()
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == uid
    patched = c.patch(f"/scim/v2/Users/{uid}", headers=h, json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "value": {"active": False}}]})
    assert patched.get_json()["active"] is False
    user = db.session.execute(db.select(User).where(User.email == "new.hire@acme.com")).scalar_one()
    assert not user.is_active  # created by this org, in no other org: deactivated
    c.put(f"/scim/v2/Users/{uid}", headers=h, json={"userName": "new.hire@acme.com", "active": True})
    db.session.refresh(user)
    assert user.is_active
    assert c.delete(f"/scim/v2/Users/{uid}", headers=h).status_code == 204


def test_scim_cannot_remove_owners_or_touch_other_orgs(scim, bob, db):
    c, h = scim["client"], scim["h"]
    owner = db.session.execute(db.select(User).where(User.email == "alice@example.com")).scalar_one()
    assert c.delete(f"/scim/v2/Users/{owner.id}", headers=h).status_code == 409
    bob_user = db.session.execute(db.select(User).where(User.email == "bob@example.com")).scalar_one()
    assert c.get(f"/scim/v2/Users/{bob_user.id}", headers=h).status_code == 404
    assert c.delete(f"/scim/v2/Users/{bob_user.id}", headers=h).status_code == 404
    token = db.session.execute(db.select(ScimToken)).scalar_one()
    c.post(f"/o/{scim['org']}/settings/security/scim-tokens/{token.id}/revoke")
    assert c.get("/scim/v2/Users", headers=h).status_code == 401


# ----------------------------------------------------------------------------------------- audit log
def test_audit_log_page_and_csv_are_admin_only(alice, app, db):
    c, org = alice["client"], alice["org"]
    page = c.get(f"/o/{org}/settings/audit-log").data.decode()
    assert "auth.login" in page or "org.created" in page or "Events" in page
    csv_resp = c.get(f"/o/{org}/settings/audit-log.csv")
    assert csv_resp.mimetype == "text/csv" and csv_resp.data.startswith(b"time,action,actor")
    member = app.test_client()
    register(member, "logmember@example.com", "Log Co")
    c.post(f"/o/{org}/members", data={"email": "logmember@example.com", "role": "member"})
    assert member.get(f"/o/{org}/settings/audit-log").status_code == 403
    assert member.get(f"/o/{org}/settings/security").status_code == 403
