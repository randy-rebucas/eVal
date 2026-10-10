from __future__ import annotations

import pytest

from eval_app.api.cors import origin_allowed
from tests.app.test_api_pr import auth, new_token

VSCODE_WEB = "https://1a2b3c4d.vscode-cdn.net"


@pytest.mark.parametrize("origin,patterns,expected", [
    (VSCODE_WEB, ["https://*.vscode-cdn.net"], True),
    ("https://a.b.vscode-cdn.net", ["https://*.vscode-cdn.net"], True),
    ("https://vscode-cdn.net", ["https://*.vscode-cdn.net"], False),
    ("https://evilvscode-cdn.net", ["https://*.vscode-cdn.net"], False),
    ("https://x.vscode-cdn.net.evil.com", ["https://*.vscode-cdn.net"], False),
    ("http://x.vscode-cdn.net", ["https://*.vscode-cdn.net"], False),
    ("https://x.vscode-cdn.net:8443", ["https://*.vscode-cdn.net"], False),
    ("https://GitHub.dev", ["https://github.dev"], True),
    ("https://anything.example", ["*"], True),
    ("https://anything.example", [], False),
])
def test_origin_matching(origin, patterns, expected):
    assert origin_allowed(origin, patterns) is expected


def test_preflight_and_response_carry_cors_headers_for_allowed_origin(alice):
    c, org = alice["client"], alice["org"]
    pre = c.options("/api/v1/findings/x/triage", headers={
        "Origin": VSCODE_WEB, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization, content-type"})
    assert pre.status_code == 200
    assert pre.headers["Access-Control-Allow-Origin"] == VSCODE_WEB
    assert "POST" in pre.headers["Access-Control-Allow-Methods"]
    assert "Authorization" in pre.headers["Access-Control-Allow-Headers"]
    assert "Access-Control-Allow-Credentials" not in pre.headers

    raw = new_token(c, org)
    resp = c.get("/api/v1/me", headers={**auth(raw), "Origin": VSCODE_WEB})
    assert resp.status_code == 200 and resp.headers["Access-Control-Allow-Origin"] == VSCODE_WEB
    assert "Origin" in resp.headers["Vary"]
    # Errors are readable cross-origin too, so the extension can show "sign in again".
    denied = c.get("/api/v1/me", headers={"Origin": VSCODE_WEB})
    assert denied.status_code == 401 and denied.headers["Access-Control-Allow-Origin"] == VSCODE_WEB


def test_no_cors_for_other_origins_or_web_routes(alice, app):
    c, org = alice["client"], alice["org"]
    assert "Access-Control-Allow-Origin" not in c.get("/api/v1/me", headers={"Origin": "https://evil.example"}).headers
    assert "Access-Control-Allow-Origin" not in c.get(f"/o/{org}", headers={"Origin": VSCODE_WEB}).headers
    app.config["API_CORS_ORIGINS"] = []
    assert "Access-Control-Allow-Origin" not in c.get("/api/v1/me", headers={"Origin": VSCODE_WEB}).headers
