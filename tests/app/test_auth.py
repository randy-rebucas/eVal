from __future__ import annotations

import pytest

from eval_app.auth.services import AuthError, validate_password
from eval_app.models import AuditEvent, Membership, User
from tests.conftest import PASSWORD, login, register


def test_register_creates_user_org_and_owner_membership(client, db):
    resp = register(client, "Alice@Example.com", "Acme Corp")
    assert resp.status_code == 302 and "/o/acme-corp" in resp.headers["Location"]
    user = db.session.execute(db.select(User)).scalar_one()
    assert user.email == "alice@example.com"
    assert user.password_hash.startswith("scrypt:") and PASSWORD not in user.password_hash
    membership = db.session.execute(db.select(Membership)).scalar_one()
    assert membership.role == "owner"


def test_duplicate_email_rejected(client, db):
    register(client, "a@example.com")
    client.post("/logout")
    resp = register(client, "A@example.com")
    assert resp.status_code == 200
    assert db.session.scalar(db.select(db.func.count(User.id))) == 1


@pytest.mark.parametrize("pw", ["short1A", "alllowercaseletters", "ALLUPPERCASELETTERS"])
def test_weak_passwords_rejected(pw):
    with pytest.raises(AuthError):
        validate_password(pw)


def test_login_logout_flow(app, client):
    register(client, "a@example.com")
    client.post("/logout")
    assert client.get("/o/acme").status_code == 302  # redirected to login
    bad = login(client, "a@example.com", "wrong-Password-1")
    assert b"Invalid email or password" in bad.data
    ok = login(client, "a@example.com")
    assert ok.status_code == 302
    assert client.get("/o/acme").status_code == 200


def test_login_does_not_reveal_unknown_email(client):
    resp = login(client, "nobody@example.com")
    assert b"Invalid email or password" in resp.data


def test_login_rate_limited(app, client):
    register(client, "a@example.com")
    client.post("/logout")
    limit = app.config["LOGIN_RATE_LIMIT"]
    for _ in range(limit):
        login(client, "a@example.com", "Wrong-password-1")
    assert login(client, "a@example.com").status_code == 429


def test_open_redirect_blocked(client):
    register(client, "a@example.com")
    client.post("/logout")
    resp = client.post("/login?next=https://evil.example/x", data={"email": "a@example.com", "password": PASSWORD})
    assert resp.headers["Location"].startswith("/")
    resp = client.post("/login?next=//evil.example", data={"email": "a@example.com", "password": PASSWORD})
    assert "evil" not in resp.headers["Location"]


def test_failed_login_audited(client, db):
    login(client, "x@example.com", "nope-Nope-123")
    assert db.session.execute(db.select(AuditEvent).where(AuditEvent.action == "auth.login_failed")).first()


def test_security_headers(client):
    resp = client.get("/login")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_csrf_enforced_when_enabled(tmp_path):
    from eval_app import create_app

    app = create_app("testing", {"WTF_CSRF_ENABLED": True, "DATA_DIR": tmp_path})
    with app.app_context():
        from eval_app.extensions import db

        db.create_all()
        resp = app.test_client().post("/login", data={"email": "a@example.com", "password": "x"})
        assert resp.status_code == 400
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


def test_production_config_requires_secrets(monkeypatch):
    from eval_app import config

    with pytest.raises(RuntimeError, match="EVAL_SECRET_KEY"):
        config.validate({"SECRET_KEY": "short", "SQLALCHEMY_DATABASE_URI": "x", "ENCRYPTION_KEYS": "k"})
