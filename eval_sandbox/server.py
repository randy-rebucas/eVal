"""eVal sandbox service: one short-lived, isolated container per terminal session.

Endpoints (``service`` = signed by the eVal web app or worker, see tokens.py):

* ``POST /sessions/{id}`` (service): body is a tar of the workspace; headers ``X-Eval-Org`` and ``X-Eval-Minutes``.
  Creates the container, copies the tar in, starts the shell.
* ``POST /sessions/{id}/files`` (service): JSON ``{"paths": [...]}`` → ``{"files": {path: text | null}}`` read from
  ``/workspace``, so edits made in the terminal can become a fix revision.
* ``DELETE /sessions/{id}`` (service): end the session.
* ``GET /sessions/{id}/tty`` (websocket): first message ``{"t": "auth", "token"}``; then ``{"t": "i", "d"}`` for
  input and ``{"t": "r", "rows", "cols"}`` to resize. Output arrives as binary frames.
* ``GET /healthz``.

State lives in container labels, so the service can restart without losing sessions.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import posixpath
import time

import aiohttp
from aiohttp import web

from .config import SandboxConfig, container_config
from .docker_api import Docker, DockerError
from .tokens import SESSION_RE, TokenError, verify_request, verify_tty_token

log = logging.getLogger("eval_sandbox")
MAX_TAR_BYTES = 256 * 1024 * 1024
MAX_READ_BYTES = 512 * 1024
AUTH_SECONDS = 10
REAP_SECONDS = 15

CFG = web.AppKey("cfg", SandboxConfig)
DOCKER = web.AppKey("docker", object)
STATE = web.AppKey("state", dict)


def _name(session: str) -> str:
    return f"eval-sbx-{session}"


def _session_id(request: web.Request) -> str:
    sid = request.match_info["sid"]
    if not SESSION_RE.match(sid):
        raise web.HTTPNotFound()
    return sid


async def _authorized_body(request: web.Request, max_bytes: int) -> bytes:
    if request.content_length is not None and request.content_length > max_bytes:
        raise web.HTTPRequestEntityTooLarge(max_size=max_bytes, actual_size=request.content_length)
    body = await request.content.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise web.HTTPRequestEntityTooLarge(max_size=max_bytes, actual_size=len(body))
    try:
        verify_request(request.app[CFG].secret, request.headers.get("Authorization", ""), request.method,
                       request.path_qs, body)
    except TokenError as exc:
        raise web.HTTPUnauthorized(text=str(exc)) from exc
    return body


async def _find(request: web.Request, sid: str) -> dict | None:
    return next((c for c in await request.app[DOCKER].list_sessions() if c["session"] == sid), None)


def _error(status: int, message: str) -> web.Response:
    return web.json_response({"error": message}, status=status)


# ------------------------------------------------------------------------------------------------ sessions
async def create_session(request: web.Request) -> web.Response:
    cfg, docker = request.app[CFG], request.app[DOCKER]
    sid = _session_id(request)
    tar = await _authorized_body(request, MAX_TAR_BYTES)
    org = request.headers.get("X-Eval-Org", "")
    if not SESSION_RE.match(org):
        return _error(400, "X-Eval-Org must be a 32-character hex id")
    try:
        minutes = max(1, min(int(request.headers.get("X-Eval-Minutes", cfg.max_minutes)), cfg.max_minutes))
    except ValueError:
        return _error(400, "X-Eval-Minutes must be an integer")
    async with request.app[STATE]["lock"]:  # count and create atomically, so limits hold under concurrency
        running = [c for c in await docker.list_sessions() if c["state"] in ("created", "running")]
        if any(c["session"] == sid for c in running):
            return _error(409, "session already exists")
        if len(running) >= cfg.max_sessions:
            return _error(429, "The sandbox is at capacity. Try again later.")
        if sum(c["org"] == org for c in running) >= cfg.max_per_org:
            return _error(429, f"Your organization already has {cfg.max_per_org} open terminal(s). End one first.")
        expires = int(time.time()) + minutes * 60
        try:
            cid = await docker.create(_name(sid), container_config(cfg, sid, org, expires))
        except DockerError as exc:
            log.error("create %s failed: %s", sid, exc)
            return _error(502, "The sandbox could not create the container.")
    try:
        await docker.put_archive(cid, "/", tar)
        await docker.start(cid)
    except DockerError as exc:
        log.error("start %s failed: %s", sid, exc)
        await docker.kill(cid)
        return _error(502, "The sandbox could not start the container.")
    request.app[STATE]["idle_since"][sid] = time.time()
    log.info("session %s started for org %s (expires %s, runtime %s)", sid, org, expires, cfg.runtime)
    return web.json_response({"session": sid, "expires": expires, "runtime": cfg.runtime,
                              "network": cfg.network, "insecure": cfg.insecure}, status=201)


async def end_session(request: web.Request) -> web.Response:
    sid = _session_id(request)
    await _authorized_body(request, 0)
    c = await _find(request, sid)
    if c:
        await request.app[DOCKER].kill(c["id"])
        log.info("session %s ended by eVal", sid)
    return web.json_response({"ended": bool(c)})


async def read_files(request: web.Request) -> web.Response:
    sid = _session_id(request)
    body = await _authorized_body(request, 64 * 1024)
    try:
        paths = json.loads(body).get("paths")
    except ValueError:
        paths = None
    if not isinstance(paths, list) or len(paths) > 20 or not all(isinstance(p, str) for p in paths):
        return _error(400, "paths must be a list of at most 20 strings")
    c = await _find(request, sid)
    if not c or c["state"] != "running":
        return _error(404, "The session has ended.")
    files: dict[str, str | None] = {}
    for p in paths:
        norm = posixpath.normpath(p)
        if p.startswith("/") or norm.startswith("..") or norm != p.strip("/"):
            return _error(400, f"not a workspace-relative path: {p}")
        data = await request.app[DOCKER].read_file(c["id"], f"/workspace/{norm}", MAX_READ_BYTES)
        try:
            files[p] = data.decode("utf-8") if data is not None else None
        except UnicodeDecodeError:
            files[p] = None
    return web.json_response({"files": files})


# ------------------------------------------------------------------------------------------------ terminal
async def terminal(request: web.Request) -> web.WebSocketResponse:
    cfg, docker, state = request.app[CFG], request.app[DOCKER], request.app[STATE]
    sid = _session_id(request)
    if request.headers.get("Origin", "").rstrip("/") not in cfg.allowed_origins:
        raise web.HTTPForbidden(text="origin not allowed")  # no cross-site websocket hijacking
    ws = web.WebSocketResponse(heartbeat=30, max_msg_size=64 * 1024)
    await ws.prepare(request)
    try:
        first = await ws.receive_json(timeout=AUTH_SECONDS)
        verify_tty_token(cfg.secret, str(first.get("token", "")) if first.get("t") == "auth" else "", sid)
    except (TimeoutError, TokenError, ValueError, TypeError):
        await ws.close(code=4401, message=b"unauthorized")
        return ws
    c = await _find(request, sid)
    if not c or c["state"] != "running":
        await ws.close(code=4404, message=b"session ended")
        return ws
    previous = state["attached"].get(sid)
    if previous is not None and not previous.closed:  # one viewer at a time; a reconnect takes over
        await previous.close(code=4409, message=b"opened elsewhere")
    state["attached"][sid] = ws
    state["idle_since"].pop(sid, None)
    try:
        async with docker.attach(c["id"]) as tty:
            await _pump(ws, tty, docker, c["id"])
    except (TimeoutError, OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, DockerError) as exc:
        log.warning("attach %s failed: %s", sid, exc)
        if not ws.closed:
            await ws.close(code=1011, message=b"terminal unavailable")
    finally:
        if state["attached"].get(sid) is ws:
            del state["attached"][sid]
            state["idle_since"][sid] = time.time()
    return ws


async def _pump(ws: web.WebSocketResponse, tty, docker, cid: str) -> None:
    async def to_browser():
        async for data in tty:
            await ws.send_bytes(data)
        if not ws.closed:
            await ws.close(code=4000, message=b"shell exited")

    async def to_shell():
        async for msg in ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                continue
            try:
                data = json.loads(msg.data)
            except ValueError:
                continue
            if data.get("t") == "i" and isinstance(data.get("d"), str):
                await tty.send_bytes(data["d"].encode())
            elif data.get("t") == "r":
                rows, cols = data.get("rows"), data.get("cols")
                if isinstance(rows, int) and isinstance(cols, int) and 0 < rows <= 500 and 0 < cols <= 1000:
                    await docker.resize(cid, rows, cols)

    tasks = [asyncio.ensure_future(to_browser()), asyncio.ensure_future(to_shell())]
    _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await t


# ------------------------------------------------------------------------------------------------ reaper
async def reap_once(app: web.Application, now: float | None = None) -> list[str]:
    """Kill sessions past their deadline, and sessions nobody has been attached to for the idle limit."""
    cfg, docker, state = app[CFG], app[DOCKER], app[STATE]
    now = now if now is not None else time.time()
    killed = []
    for c in await docker.list_sessions():
        sid = c["session"]
        idle_since = state["idle_since"].setdefault(sid, now) if sid not in state["attached"] else None
        if c["expires"] <= now or (idle_since is not None and now - idle_since > cfg.idle_minutes * 60):
            await docker.kill(c["id"])
            killed.append(sid)
            state["idle_since"].pop(sid, None)
            ws = state["attached"].pop(sid, None)
            if ws is not None and not ws.closed:
                await ws.close(code=4408, message=b"time limit reached")
    if killed:
        log.info("reaped %s", ", ".join(killed))
    return killed


async def _reaper(app: web.Application):
    async def loop():
        while True:
            with contextlib.suppress(Exception):
                await reap_once(app)
            await asyncio.sleep(REAP_SECONDS)

    task = asyncio.ensure_future(loop())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def healthz(request: web.Request) -> web.Response:
    cfg = request.app[CFG]
    return web.json_response({"ok": True, "runtime": cfg.runtime, "insecure": cfg.insecure, "network": cfg.network})


def create_app(cfg: SandboxConfig, docker=None, reaper: bool = True) -> web.Application:
    app = web.Application(client_max_size=MAX_TAR_BYTES + 1024)
    app[CFG] = cfg
    if docker is not None:
        app[DOCKER] = docker
    app[STATE] = {"attached": {}, "idle_since": {}, "lock": asyncio.Lock()}
    app.router.add_get("/healthz", healthz)
    app.router.add_post("/sessions/{sid}", create_session)
    app.router.add_delete("/sessions/{sid}", end_session)
    app.router.add_post("/sessions/{sid}/files", read_files)
    app.router.add_get("/sessions/{sid}/tty", terminal)
    async def docker_client(app: web.Application):
        """The Docker client needs a running event loop, so it is created at startup (and checked once)."""
        client = Docker(cfg.docker_host)
        app[DOCKER] = client
        try:
            runtimes = await client.runtimes()
            if cfg.runtime not in runtimes:
                raise RuntimeError(f"Docker has no '{cfg.runtime}' runtime (has: {', '.join(sorted(runtimes))}). "
                                   "Install gVisor: https://gvisor.dev/docs/user_guide/install/")
            if cfg.insecure:
                log.warning("EVAL_SANDBOX_RUNTIME=%s: containers share the host kernel. Development only.",
                            cfg.runtime)
            yield
        finally:
            await client.close()

    if docker is None:
        app.cleanup_ctx.append(docker_client)
    if reaper:
        app.cleanup_ctx.append(_reaper)
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = SandboxConfig.from_env()
    web.run_app(create_app(cfg), host=cfg.host, port=cfg.port, access_log=None)


if __name__ == "__main__":
    main()
