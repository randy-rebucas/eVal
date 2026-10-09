from __future__ import annotations

import re
from pathlib import Path

import pytest

from eval_app import create_app
from eval_app.extensions import db as _db
from eval_app.security import ratelimit

PASSWORD = "Correct-Horse-42"
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """Tests never call OSV.dev; OSV tests inject a fake HTTP session explicitly."""
    monkeypatch.setenv("EVAL_OSV_ENABLED", "0")


@pytest.fixture
def app(tmp_path):
    app = create_app("testing", {"DATA_DIR": tmp_path / "data"})
    app.config["DATA_DIR"].mkdir(parents=True, exist_ok=True)

    # The fixture keeps an app context pushed so tests can query the DB; Flask then reuses it for
    # test-client requests, which would leak Flask-Login's cached user (on ``g``) between clients.
    # In production every request gets a fresh ``g``, so reset per request here only.
    @app.before_request
    def _fresh_request_state():
        from flask import g

        g.pop("_login_user", None)
        g.pop("org", None)
        g.pop("membership", None)
        _db.session.expire_all()

    with app.app_context():
        _db.drop_all()
        _db.create_all()
        ratelimit.reset_memory()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def db(app):
    return _db


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, email, org_name="Acme", password=PASSWORD):
    return client.post(
        "/register",
        data={"email": email, "password": password, "name": "", "org_name": org_name},
        follow_redirects=False,
    )


def login(client, email, password=PASSWORD):
    return client.post("/login", data={"email": email, "password": password})


def org_slug_from(response) -> str:
    match = re.search(r"/o/([a-z0-9-]+)", response.headers["Location"])
    assert match, response.headers.get("Location")
    return match.group(1)


@pytest.fixture
def alice(app):
    """Owner of org 'Acme' with a logged-in client."""
    c = app.test_client()
    resp = register(c, "alice@example.com", "Acme")
    assert resp.status_code == 302
    return {"client": c, "org": org_slug_from(resp), "email": "alice@example.com"}


@pytest.fixture
def bob(app):
    """Owner of a separate org 'Globex' (a different tenant)."""
    c = app.test_client()
    resp = register(c, "bob@example.com", "Globex")
    return {"client": c, "org": org_slug_from(resp), "email": "bob@example.com"}
