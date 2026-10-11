"""Sandbox terminals: eVal's side. The sandbox service (eval_sandbox) runs the containers; eVal decides who may
open one, builds the workspace (the audited commit plus a fix revision) in the worker, and records every session.

Nothing here executes repository code. The workspace leaves eVal as a tar, without .git, so no repository
credentials or remote configuration reach the sandbox.
"""

from __future__ import annotations

import io
import json
import tarfile
import time
from datetime import timedelta
from pathlib import Path

import requests
from flask import current_app

from eval_sandbox.tokens import issue_tty_token, sign_request

from ..extensions import db
from ..fixes import services as fixes
from ..models import FixProposal, Organization, SandboxSession, utcnow
from ..security import events, ratelimit

MAX_WORKSPACE_BYTES = 200 * 1024 * 1024
SANDBOX_UID = 1000


class SandboxError(Exception):
    pass


def configured() -> bool:
    cfg = current_app.config
    return bool(cfg.get("SANDBOX_URL") and cfg.get("SANDBOX_PUBLIC_URL") and cfg.get("SANDBOX_SECRET"))


def available(org: Organization) -> bool:
    return configured() and org.allow_sandbox


# ------------------------------------------------------------------------------------------- service client
def _call(method: str, path: str, body: bytes = b"", headers: dict | None = None, timeout: int = 60):
    cfg = current_app.config
    headers = {**(headers or {}), "Authorization": sign_request(cfg["SANDBOX_SECRET"], method, path, body)}
    try:
        resp = requests.request(method, cfg["SANDBOX_URL"] + path, data=body, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        raise SandboxError("The sandbox service is unreachable.") from exc
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if resp.status_code >= 400:
        raise SandboxError(data.get("error") or f"The sandbox service answered HTTP {resp.status_code}.")
    return data


# ------------------------------------------------------------------------------------------------- open
def open_session(org: Organization, proposal: FixProposal, user) -> SandboxSession:
    if not available(org):
        raise SandboxError("Sandbox terminals are not enabled for this organization.")
    if proposal.status not in ("ready", "pr_opened") or not proposal.files:
        raise SandboxError("Open a terminal on a generated fix that has finished re-auditing.")
    existing = db.session.execute(
        db.select(SandboxSession).where(SandboxSession.organization_id == org.id, SandboxSession.fix_id == proposal.id,
                                        SandboxSession.user_id == user.id,
                                        SandboxSession.status.in_(("preparing", "ready")))
        .order_by(SandboxSession.created_at.desc())
    ).scalars().first()
    if existing is not None and existing.is_open and existing.revision == fixes.current_revision(proposal):
        return existing
    if not ratelimit.hit("sandbox", str(org.id), 20, 3600):
        raise SandboxError("Too many terminals opened this hour; try again later.")
    minutes = current_app.config["SANDBOX_MAX_MINUTES"]
    session = SandboxSession(organization_id=org.id, fix_id=proposal.id, user_id=user.id, status="preparing",
                             revision=fixes.current_revision(proposal),
                             expires_at=utcnow() + timedelta(minutes=minutes))
    db.session.add(session)
    db.session.flush()
    events.record("sandbox.opened", organization_id=org.id, target=session, actor_id=user.id, fix=str(proposal.id),
                  revision=session.revision)
    db.session.commit()
    _enqueue(session)
    return session


def _enqueue(session: SandboxSession) -> None:
    from .tasks import prepare_sandbox

    try:
        prepare_sandbox.apply_async(args=[str(session.id)], queue="audits")
    except Exception as exc:  # broker unavailable
        current_app.logger.error("failed to enqueue sandbox %s: %s", session.id, type(exc).__name__)
        _fail(session, "The work queue is unavailable. Try again shortly.")
        db.session.commit()
        return
    db.session.refresh(session)


def _fail(session: SandboxSession, message: str) -> None:
    session.status = "failed"
    session.error = message[:2000]
    session.ended_at = utcnow()


# ---------------------------------------------------------------------------------------------- prepare
def _owned_by_sandbox(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = SANDBOX_UID
    info.uname = info.gname = ""
    return info


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = _owned_by_sandbox(tarfile.TarInfo(name))
    info.size, info.mode, info.mtime = len(data), 0o644, int(time.time())
    tar.addfile(info, io.BytesIO(data))


def banner(session: SandboxSession) -> str:
    proposal = session.fix
    audit = proposal.audit
    lines = [
        f"eVal sandbox · {audit.repository.name} @ {audit.commit_sha[:12] or 'upload'} · "
        f"fix revision {session.revision}",
        "Your code runs here, in an isolated container: no credentials, no git remote. "
        "`git diff` shows the fix.",
        f"Files in the fix: {', '.join(f['path'] for f in proposal.files)}",
        "Edits to those files can be saved back to the fix from the eVal page. The session ends "
        f"{current_app.config['SANDBOX_MAX_MINUTES']} minutes after it opened.",
    ]
    return "\n".join(f"\x1b[2m# {line}\x1b[0m" for line in lines) + "\n\n"


def build_workspace(session: SandboxSession, src: Path) -> bytes:
    """Tar for the sandbox: ``workspace/`` (the audited tree), ``eval/fix/`` (the revision's files), the banner."""
    buf = io.BytesIO()
    total = 0

    def guard(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        nonlocal total
        if info.isdev() or info.islnk():
            return None  # no device nodes or hard links into the sandbox
        total += info.size
        if total > MAX_WORKSPACE_BYTES:
            raise SandboxError(f"The repository is larger than {MAX_WORKSPACE_BYTES // (1024 * 1024)} MB.")
        return _owned_by_sandbox(info)

    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(src, arcname="workspace", filter=guard)
        for f in session.fix.files:
            _add_bytes(tar, f"eval/fix/{f['path']}", f["after"].encode("utf-8"))
        _add_bytes(tar, "eval/motd", banner(session).encode("utf-8"))
        _add_bytes(tar, "eval/commit", (session.fix.audit.commit_sha or "upload").encode())
    return buf.getvalue()


def prepare(session: SandboxSession) -> None:
    """Fetch the audited commit, package it with the fix, and start the container (called from the worker)."""
    from eval_engine.workspace import WorkspaceError, remove_tree

    from ..audits.workspaces import fetch_source, limits_from_config

    audit = session.fix.audit
    cfg = current_app.config
    workdir = Path(cfg.get("WORK_DIR") or cfg["DATA_DIR"] / "work") / f"sandbox-{session.id.hex}"
    try:
        remove_tree(workdir)
        src = workdir / "src"
        src.mkdir(parents=True)
        sha, _ = fetch_source(audit, src, limits_from_config(),
                              ref=audit.commit_sha if audit.repository.source == "github" else None)
        if audit.commit_sha and sha[:12] != audit.commit_sha[:12]:
            raise SandboxError("The audited commit could not be fetched again.")
        tar = build_workspace(session, src)
    except WorkspaceError as exc:
        raise SandboxError(f"Could not fetch the code: {exc}") from exc
    finally:
        remove_tree(workdir)
    remaining = max(1, int((_aware(session.expires_at) - utcnow()).total_seconds() // 60))
    data = _call("POST", f"/sessions/{session.id.hex}", tar, timeout=300,
                 headers={"X-Eval-Org": session.organization_id.hex, "X-Eval-Minutes": str(remaining),
                          "Content-Type": "application/x-tar"})
    session.status = "ready"
    session.runtime = str(data.get("runtime", ""))[:32]
    session.network = str(data.get("network", ""))[:64]
    session.insecure = bool(data.get("insecure"))
    if isinstance(data.get("expires"), int):
        from datetime import UTC, datetime

        session.expires_at = min(_aware(session.expires_at), datetime.fromtimestamp(data["expires"], UTC))


def _aware(dt):
    from datetime import UTC

    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


# -------------------------------------------------------------------------------------------- terminal
def terminal_token(session: SandboxSession, user) -> dict:
    if session.status != "ready" or not session.is_open:
        raise SandboxError("This terminal session has ended.")
    cfg = current_app.config
    return {"url": f"{cfg['SANDBOX_PUBLIC_URL']}/sessions/{session.id.hex}/tty",
            "token": issue_tty_token(cfg["SANDBOX_SECRET"], session.id.hex, user.id.hex)}


def end_session(session: SandboxSession, user, reason: str = "ended by user") -> None:
    if session.status in ("preparing", "ready"):
        try:
            _call("DELETE", f"/sessions/{session.id.hex}", timeout=30)
        except SandboxError as exc:  # the container also dies at its deadline; record the end either way
            current_app.logger.warning("sandbox %s end: %s", session.id, exc)
    session.status = "ended"
    session.ended_at = utcnow()
    events.record("sandbox.ended", organization_id=session.organization_id, target=session, actor_id=user.id,
                  reason=reason)
    db.session.commit()


def save_back(org: Organization, session: SandboxSession, user) -> int:
    """Copy the fix's files out of the terminal into a new fix revision (re-audited like any hand edit)."""
    proposal = session.fix
    if session.status != "ready" or not session.is_open:
        raise SandboxError("This terminal session has ended, so its files are gone.")
    paths = [f["path"] for f in proposal.files]
    data = _call("POST", f"/sessions/{session.id.hex}/files", json.dumps({"paths": paths}).encode(),
                 headers={"Content-Type": "application/json"})
    files = data.get("files") or {}
    missing = [p for p in paths if not isinstance(files.get(p), str)]
    if missing:
        raise SandboxError(f"Could not read {missing[0]} from the terminal (deleted, binary, or over 512 KB).")
    try:
        fixes.save_edits(org, proposal, {p: files[p] for p in paths}, session.revision, user)
    except fixes.FixError as exc:
        raise SandboxError(str(exc)) from exc
    session.revision = fixes.current_revision(proposal)  # later saves from this terminal build on this one
    db.session.commit()
    return session.revision
