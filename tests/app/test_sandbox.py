"""Sandbox terminals in the app: opt-in, workspace contents, terminal tokens, saving back, ending, isolation."""

from __future__ import annotations

import io
import json
import tarfile

import pytest

from eval_app.config import validate
from eval_app.models import AuditEvent, SandboxSession
from eval_sandbox import tokens
from tests.app.test_autofix import _ready_fix, ai_on  # noqa: F401  (fixture)

SECRET = "x" * 40


class FakeSandbox:
    """Stands in for the sandbox service; checks every request's signature like the real one."""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self.tar: tarfile.TarFile | None = None
        self.headers: dict = {}
        self.files: dict[str, str] = {}
        self.fail: str = ""

    def __call__(self, method, url, data=b"", headers=None, timeout=None):
        path = url.removeprefix("http://sandbox:8100")
        tokens.verify_request(SECRET, headers["Authorization"], method, path, data or b"")
        self.calls.append((method, path))
        if self.fail:
            return Resp(502, {"error": self.fail})
        if method == "POST" and path.endswith("/files"):
            paths = json.loads(data)["paths"]
            return Resp(200, {"files": {p: self.files.get(p) for p in paths}})
        if method == "POST":
            self.tar = tarfile.open(fileobj=io.BytesIO(data))  # noqa: SIM115 - kept open for the assertions
            self.headers = headers
            return Resp(201, {"session": path.rsplit("/", 1)[1], "expires": 4_000_000_000, "runtime": "runsc",
                              "network": "none", "insecure": False})
        return Resp(200, {"ended": True})


class Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


@pytest.fixture
def sandbox(app, monkeypatch):
    app.config.update(SANDBOX_URL="http://sandbox:8100", SANDBOX_PUBLIC_URL="wss://sbx.example.com",
                      SANDBOX_SECRET=SECRET)
    fake = FakeSandbox()
    monkeypatch.setattr("eval_app.sandbox.services.requests.request", fake)
    return fake


def _allow(client, org):
    client.post(f"/o/{org}/settings/security", data={"action": "sandbox", "allow_sandbox": "on"})


def test_terminal_needs_operator_config_and_org_opt_in(ai_on, db, app, monkeypatch):  # noqa: F811
    c, org = ai_on["client"], ai_on["org"]
    fix = _ready_fix(ai_on, db)
    assert "Open a terminal" not in c.get(f"/o/{org}/fixes/{fix.id}").data.decode()
    assert "Sandbox terminals" not in c.get(f"/o/{org}/settings/security").data.decode()
    resp = c.post(f"/o/{org}/fixes/{fix.id}/sandbox", follow_redirects=True)
    assert b"not enabled for this organization" in resp.data

    app.config.update(SANDBOX_URL="http://sandbox:8100", SANDBOX_PUBLIC_URL="wss://sbx.example.com",
                      SANDBOX_SECRET=SECRET)
    assert "Sandbox terminals" in c.get(f"/o/{org}/settings/security").data.decode()
    assert "Open a terminal" not in c.get(f"/o/{org}/fixes/{fix.id}").data.decode()  # org has not opted in
    _allow(c, org)
    assert "Open a terminal on this fix" in c.get(f"/o/{org}/fixes/{fix.id}").data.decode()
    assert db.session.execute(db.select(AuditEvent).where(AuditEvent.action == "org.sandbox_policy")).scalar_one()


def test_open_terminal_ships_the_fixed_tree_without_credentials(ai_on, db, sandbox):  # noqa: F811
    c, org = ai_on["client"], ai_on["org"]
    fix = _ready_fix(ai_on, db)
    _allow(c, org)
    resp = c.post(f"/o/{org}/fixes/{fix.id}/sandbox")
    session = db.session.execute(db.select(SandboxSession)).scalar_one()
    assert resp.headers["Location"].endswith(f"/sandbox/{session.id}")
    assert (session.status, session.runtime, session.network, session.revision) == ("ready", "runsc", "none", 1)
    assert sandbox.headers["X-Eval-Org"] == session.organization_id.hex

    names = sandbox.tar.getnames()
    assert "workspace/app.py" in names and not any(n.startswith("workspace/.git") for n in names)
    assert all(m.uid == 1000 and m.gid == 1000 for m in sandbox.tar.getmembers())
    assert sandbox.tar.extractfile("eval/fix/app.py").read().decode() == fix.files[0]["after"]
    assert sandbox.tar.extractfile("workspace/app.py").read().decode() != fix.files[0]["after"]  # audited version
    assert "fix revision 1" in sandbox.tar.extractfile("eval/motd").read().decode()

    page = c.get(f"/o/{org}/sandbox/{session.id}")
    csp = page.headers["Content-Security-Policy"]
    assert "connect-src 'self' wss://sbx.example.com;" in csp and "@xterm/xterm@5.5.0/" in csp
    assert "integrity=\"sha384-" in page.data.decode() and "data-terminal" in page.data.decode()
    # The rest of the app keeps its strict policy.
    assert "unsafe-inline" not in c.get(f"/o/{org}/fixes/{fix.id}").headers["Content-Security-Policy"]

    got = c.post(f"/o/{org}/sandbox/{session.id}/token").get_json()
    assert got["url"] == f"wss://sbx.example.com/sessions/{session.id.hex}/tty"
    user = tokens.verify_tty_token(SECRET, got["token"], session.id.hex)
    assert user == session.user_id.hex

    # Opening again reuses the open session.
    c.post(f"/o/{org}/fixes/{fix.id}/sandbox")
    assert db.session.scalar(db.select(db.func.count(SandboxSession.id))) == 1
    assert db.session.execute(db.select(AuditEvent).where(AuditEvent.action == "sandbox.opened")).scalar_one()


def test_save_back_creates_a_reaudited_revision_then_end(ai_on, db, sandbox):  # noqa: F811
    c, org = ai_on["client"], ai_on["org"]
    fix = _ready_fix(ai_on, db)
    _allow(c, org)
    c.post(f"/o/{org}/fixes/{fix.id}/sandbox")
    session = db.session.execute(db.select(SandboxSession)).scalar_one()

    sandbox.files = {}
    resp = c.post(f"/o/{org}/sandbox/{session.id}/save", follow_redirects=True)
    assert b"Could not read app.py" in resp.data
    sandbox.files = {"app.py": fix.files[0]["after"] + "# checked in the terminal\n"}
    resp = c.post(f"/o/{org}/sandbox/{session.id}/save", follow_redirects=True)
    assert b"as revision 2" in resp.data
    db.session.refresh(fix)
    db.session.refresh(session)
    assert fix.revisions[-1]["kind"] == "edit" and "# checked in the terminal" in fix.diff
    assert fix.verification["verdict"] == "passed" and session.revision == 2

    c.post(f"/o/{org}/sandbox/{session.id}/end")
    db.session.refresh(session)
    assert session.status == "ended" and ("DELETE", f"/sessions/{session.id.hex}") in sandbox.calls
    assert c.post(f"/o/{org}/sandbox/{session.id}/token").status_code == 410
    assert b"has ended" in c.get(f"/o/{org}/sandbox/{session.id}").data


def test_service_failure_is_reported(ai_on, db, sandbox):  # noqa: F811
    c, org = ai_on["client"], ai_on["org"]
    fix = _ready_fix(ai_on, db)
    _allow(c, org)
    sandbox.fail = "Your organization already has 2 open terminal(s). End one first."
    c.post(f"/o/{org}/fixes/{fix.id}/sandbox")
    session = db.session.execute(db.select(SandboxSession)).scalar_one()
    assert session.status == "failed" and "already has 2" in session.error
    assert b"already has 2" in c.get(f"/o/{org}/sandbox/{session.id}").data


def test_terminals_are_personal_and_tenant_scoped(ai_on, bob, db, app, sandbox):  # noqa: F811
    from tests.conftest import register

    c, org = ai_on["client"], ai_on["org"]
    fix = _ready_fix(ai_on, db)
    _allow(c, org)
    c.post(f"/o/{org}/fixes/{fix.id}/sandbox")
    session = db.session.execute(db.select(SandboxSession)).scalar_one()

    colleague = app.test_client()
    register(colleague, "carol@example.com", "Carol Co")
    c.post(f"/o/{org}/members", data={"email": "carol@example.com", "role": "member"})
    viewer = app.test_client()
    register(viewer, "victor@example.com", "Victor Co")
    c.post(f"/o/{org}/members", data={"email": "victor@example.com", "role": "viewer"})
    for path in (f"/o/{org}/sandbox/{session.id}", f"/o/{org}/sandbox/{session.id}/status"):
        assert colleague.get(path).status_code == 404  # same org, not theirs
    assert colleague.post(f"/o/{org}/sandbox/{session.id}/token").status_code == 404
    assert colleague.post(f"/o/{org}/sandbox/{session.id}/end").status_code == 404
    assert viewer.post(f"/o/{org}/fixes/{fix.id}/sandbox").status_code == 403
    assert bob["client"].get(f"/o/{bob['org']}/sandbox/{session.id}").status_code == 404
    assert bob["client"].post(f"/o/{bob['org']}/fixes/{fix.id}/sandbox").status_code == 404


def test_sandbox_settings_are_validated():
    base = {"SECRET_KEY": "k" * 40, "SQLALCHEMY_DATABASE_URI": "sqlite://", "ENCRYPTION_KEYS": "x"}
    validate({**base})
    with pytest.raises(RuntimeError, match="must be set together"):
        validate({**base, "SANDBOX_URL": "http://sandbox:8100"})
    with pytest.raises(RuntimeError, match="at least 32"):
        validate({**base, "SANDBOX_URL": "http://s", "SANDBOX_PUBLIC_URL": "wss://s", "SANDBOX_SECRET": "short"})
    with pytest.raises(RuntimeError, match="wss://"):
        validate({**base, "SANDBOX_URL": "http://s", "SANDBOX_PUBLIC_URL": "https://s", "SANDBOX_SECRET": SECRET})
