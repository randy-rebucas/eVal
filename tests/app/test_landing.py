from __future__ import annotations

from tests.conftest import register


def test_root_shows_landing_to_visitors(client, db):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "eVal verifies it." in html
    assert 'href="/register"' in html and 'href="/login"' in html
    # Sample data is labelled, and the disclaimer survives.
    assert "the revisions are illustrative" in html
    assert "risk indicators, not guarantees of production readiness" in html
    assert "Not assessed" in html


def test_landing_hides_register_when_registration_closed(app, client, db):
    app.config["ALLOW_REGISTRATION"] = False
    html = client.get("/").get_data(as_text=True)
    assert 'href="/register"' not in html
    assert "Log in to run an audit" in html


def test_root_redirects_signed_in_users(client, db):
    register(client, "solo@example.com", "Solo")
    resp = client.get("/")
    assert resp.status_code == 302
