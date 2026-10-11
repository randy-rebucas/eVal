"""The sandbox service against a fake Docker Engine: isolation settings, request signatures, limits, terminals."""

from __future__ import annotations

import asyncio
import json
import time

import pytest

aiohttp = pytest.importorskip("aiohttp")

from aiohttp import WSMsgType  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

from eval_sandbox import tokens  # noqa: E402
from eval_sandbox.config import SandboxConfig, container_config  # noqa: E402
from eval_sandbox.server import create_app, reap_once  # noqa: E402

SECRET = "s" * 40
ORIGIN = "https://eval.example.com"
SID = "a" * 32
ORG = "b" * 32
USER = "c" * 32


def cfg(**kw) -> SandboxConfig:
    return SandboxConfig(secret=SECRET, allowed_origins=[ORIGIN], **kw)


class FakeTTY:
    """The container's terminal: echoes input back as output."""

    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()
        self.received: list[bytes] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def __aiter__(self):
        return self

    async def __anext__(self):
        msg = await self.queue.get()
        if msg is None:
            raise StopAsyncIteration
        return msg

    async def send_bytes(self, data: bytes):
        self.received.append(data)
        await self.queue.put(b"out:" + data)


class FakeDocker:
    def __init__(self):
        self.containers: dict[str, dict] = {}
        self.configs: dict[str, dict] = {}
        self.archives: dict[str, bytes] = {}
        self.killed: list[str] = []
        self.resized: list[tuple] = []
        self.files: dict[str, bytes] = {}
        self.tty = FakeTTY()

    async def list_sessions(self):
        return [dict(c) for c in self.containers.values()]

    async def create(self, name, config):
        labels = config["Labels"]
        self.containers[name] = {"id": name, "session": labels["eval.session"], "org": labels["eval.org"],
                                 "expires": int(labels["eval.expires"]), "state": "created"}
        self.configs[name] = config
        return name

    async def put_archive(self, cid, path, tar):
        self.archives[cid] = tar

    async def start(self, cid):
        self.containers[cid]["state"] = "running"

    async def kill(self, cid):
        self.containers.pop(cid, None)
        self.killed.append(cid)

    async def resize(self, cid, rows, cols):
        self.resized.append((cid, rows, cols))

    async def read_file(self, cid, path, max_bytes):
        return self.files.get(path)

    def attach(self, cid):
        return self.tty


def run(coro_fn, config=None, docker=None):
    """Run ``coro_fn(client, docker, app)`` against the service on a test server."""
    docker = docker or FakeDocker()

    async def main():
        app = create_app(config or cfg(), docker=docker, reaper=False)
        async with TestClient(TestServer(app)) as client:
            return await coro_fn(client, docker, app)

    return asyncio.run(main())


def signed(method, path, body=b""):
    return {"Authorization": tokens.sign_request(SECRET, method, path, body)}


async def open_session(client, sid=SID, org=ORG, body=b"tar-bytes", minutes="10"):
    path = f"/sessions/{sid}"
    return await client.post(path, data=body, headers={**signed("POST", path, body), "X-Eval-Org": org,
                                                       "X-Eval-Minutes": minutes})


# ----------------------------------------------------------------------------------------------- settings
def test_containers_are_locked_down():
    c = container_config(cfg(), SID, ORG, 123)
    host = c["HostConfig"]
    assert host["Runtime"] == "runsc" and host["NetworkMode"] == "none" and c["NetworkDisabled"] is True
    assert host["Privileged"] is False and host["CapDrop"] == ["ALL"]
    assert host["SecurityOpt"] == ["no-new-privileges:true"] and host["AutoRemove"] is True
    assert host["Binds"] == [] and host["Mounts"] == [] and host["Devices"] == []
    assert host["Memory"] == host["MemorySwap"] == 2048 * 1024 * 1024 and host["PidsLimit"] == 256
    assert c["User"] == "1000:1000"
    assert not any("SECRET" in e or "TOKEN" in e for e in c["Env"])  # nothing sensitive in the environment
    assert c["Labels"] == {"eval.sandbox": "1", "eval.session": SID, "eval.org": ORG, "eval.expires": "123"}


def test_unsafe_settings_are_refused():
    with pytest.raises(ValueError, match="shares the host kernel"):
        cfg(runtime="runc")
    assert cfg(runtime="runc", allow_runc=True).insecure
    for network in ("host", "bridge", "container:web"):
        with pytest.raises(ValueError, match="EVAL_SANDBOX_NETWORK"):
            cfg(network=network)
    with pytest.raises(ValueError, match="at least 32"):
        SandboxConfig(secret="short", allowed_origins=[ORIGIN])
    with pytest.raises(ValueError, match="ALLOWED_ORIGINS"):
        SandboxConfig(secret=SECRET)


# ----------------------------------------------------------------------------------------------- tokens
def test_request_signatures():
    header = tokens.sign_request(SECRET, "POST", "/sessions/x", b"body", now=1000)
    tokens.verify_request(SECRET, header, "POST", "/sessions/x", b"body", now=1030)
    tampered = [("POST", "/sessions/x", b"other"), ("DELETE", "/sessions/x", b"body"), ("POST", "/sessions/y", b"body")]
    for args in tampered:
        with pytest.raises(tokens.TokenError, match="bad signature"):
            tokens.verify_request(SECRET, header, *args, now=1030)
    with pytest.raises(tokens.TokenError, match="expired"):
        tokens.verify_request(SECRET, header, "POST", "/sessions/x", b"body", now=1000 + tokens.MAX_SKEW + 1)
    with pytest.raises(tokens.TokenError, match="bad signature"):
        tokens.verify_request("t" * 40, header, "POST", "/sessions/x", b"body", now=1000)


def test_terminal_tokens():
    t = tokens.issue_tty_token(SECRET, SID, USER, now=1000)
    assert tokens.verify_tty_token(SECRET, t, SID, now=1100) == USER
    with pytest.raises(tokens.TokenError, match="expired"):
        tokens.verify_tty_token(SECRET, t, SID, now=1000 + tokens.TTY_TOKEN_SECONDS + 1)
    with pytest.raises(tokens.TokenError, match="another session"):
        tokens.verify_tty_token(SECRET, t, "d" * 32, now=1100)
    forged = t.replace(USER, "e" * 32)
    with pytest.raises(tokens.TokenError, match="bad token"):
        tokens.verify_tty_token(SECRET, forged, SID, now=1100)
    # A request signature is not a terminal token (separate derived keys).
    with pytest.raises(tokens.TokenError):
        tokens.verify_tty_token(SECRET, tokens.sign_request(SECRET, "GET", "/", b""), SID)


# ---------------------------------------------------------------------------------------------- sessions
def test_create_session_needs_a_signature_and_respects_limits():
    async def body(client, docker, app):
        resp = await client.post(f"/sessions/{SID}", data=b"tar", headers={"X-Eval-Org": ORG})
        assert resp.status == 401 and not docker.containers
        resp = await open_session(client)
        assert resp.status == 201, await resp.text()
        data = await resp.json()
        assert data["runtime"] == "runsc" and data["network"] == "none" and data["insecure"] is False
        assert 9 * 60 < data["expires"] - time.time() <= 10 * 60
        name = f"eval-sbx-{SID}"
        assert docker.containers[name]["state"] == "running" and docker.archives[name] == b"tar-bytes"
        assert (await open_session(client)).status == 409  # same session twice
        assert (await open_session(client, sid="1" * 32)).status == 201
        third = await open_session(client, sid="2" * 32)
        assert third.status == 429 and "already has 2" in (await third.json())["error"]
        assert (await open_session(client, sid="3" * 32, org="f" * 32)).status == 201  # another org
        # Minutes are capped by the service's own maximum.
        await (await open_session(client, sid="4" * 32, org="9" * 32, minutes="9999")).json()
        assert docker.containers[f"eval-sbx-{'4' * 32}"]["expires"] - time.time() <= 30 * 60

    run(body)


def test_global_capacity():
    async def body(client, docker, app):
        for i in range(2):
            assert (await open_session(client, sid=str(i) * 32, org=str(i) * 32)).status == 201
        assert (await open_session(client, sid="9" * 32, org="8" * 32)).status == 429

    run(body, config=cfg(max_sessions=2))


def test_end_and_read_files():
    async def body(client, docker, app):
        await open_session(client)
        docker.files["/workspace/app.py"] = b"print('edited')\n"
        path = f"/sessions/{SID}/files"
        payload = json.dumps({"paths": ["app.py", "gone.py"]}).encode()
        resp = await client.post(path, data=payload, headers=signed("POST", path, payload))
        assert (await resp.json())["files"] == {"app.py": "print('edited')\n", "gone.py": None}
        bad = json.dumps({"paths": ["../etc/passwd"]}).encode()
        assert (await client.post(path, data=bad, headers=signed("POST", path, bad))).status == 400
        resp = await client.delete(f"/sessions/{SID}", headers=signed("DELETE", f"/sessions/{SID}"))
        assert (await resp.json()) == {"ended": True} and docker.killed == [f"eval-sbx-{SID}"]
        assert (await client.post(path, data=payload, headers=signed("POST", path, payload))).status == 404

    run(body)


# ---------------------------------------------------------------------------------------------- terminal
def test_terminal_relays_input_and_output():
    async def body(client, docker, app):
        await open_session(client)
        ws = await client.ws_connect(f"/sessions/{SID}/tty", headers={"Origin": ORIGIN})
        await ws.send_json({"t": "auth", "token": tokens.issue_tty_token(SECRET, SID, USER)})
        await ws.send_json({"t": "r", "rows": 40, "cols": 120})
        await ws.send_json({"t": "i", "d": "pytest -q\r"})
        msg = await ws.receive(timeout=5)
        assert msg.type == WSMsgType.BINARY and msg.data == b"out:pytest -q\r"
        assert docker.tty.received == [b"pytest -q\r"]
        assert docker.resized == [(f"eval-sbx-{SID}", 40, 120)]
        await ws.close()

    run(body)


def test_terminal_refuses_other_origins_and_bad_tokens():
    async def body(client, docker, app):
        await open_session(client)
        with pytest.raises(aiohttp.WSServerHandshakeError):
            await client.ws_connect(f"/sessions/{SID}/tty", headers={"Origin": "https://evil.example"})
        ws = await client.ws_connect(f"/sessions/{SID}/tty", headers={"Origin": ORIGIN})
        await ws.send_json({"t": "auth", "token": tokens.issue_tty_token(SECRET, "d" * 32, USER)})
        msg = await ws.receive(timeout=5)
        assert msg.type == WSMsgType.CLOSE and msg.data == 4401
        assert docker.tty.received == []

    run(body)


def test_reaper_ends_expired_and_idle_sessions():
    async def body(client, docker, app):
        await open_session(client, minutes="5")
        await open_session(client, sid="1" * 32, org="2" * 32, minutes="30")
        now = time.time()
        assert await reap_once(app, now=now) == []
        assert await reap_once(app, now=now + 6 * 60) == [SID]  # past its deadline
        assert await reap_once(app, now=now + 11 * 60) == ["1" * 32]  # nobody attached for 10 minutes
        assert docker.containers == {}

    run(body)
