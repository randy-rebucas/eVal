"""Constrained subprocess execution for external analyzers.

Controls applied to every invocation:

* executable must be on a fixed allow-list and is resolved to an absolute path; argv list only, never a shell;
* scrubbed environment (no application secrets, isolated HOME/TMP);
* wall-clock timeout that kills the whole process group;
* stdout/stderr captured to temp files and truncated to a cap (no unbounded memory use);
* on POSIX, ``setrlimit`` for CPU seconds, address space, written file size, open files, and processes.

Container-level isolation (read-only rootfs, dropped capabilities, no-new-privileges, memory/PID limits)
is configured in docker-compose for the worker and complements these process-level controls.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess  # nosec B404
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ALLOWED_TOOLS = frozenset({"ruff", "bandit", "mypy", "semgrep", "trivy", "eslint", "tsc", "pip-audit"})
DEFAULT_MAX_OUTPUT = 32 * 1024 * 1024


class SandboxError(Exception):
    pass


@dataclass
class ToolResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    duration: float


def which(tool: str) -> str | None:
    """Locate an allow-listed tool on PATH or next to the running interpreter (virtualenv bin/Scripts)."""
    if tool not in ALLOWED_TOOLS:
        return None
    # On Windows, try real executables first: node_modules/.bin also holds extensionless POSIX shell shims,
    # which shutil.which may return but CreateProcess cannot run.
    names = [f"{tool}.exe", f"{tool}.cmd", tool] if os.name == "nt" else [tool]
    # Optional operator-controlled search path (e.g. a node_modules/.bin with eslint/tsc).
    search_paths = [p for p in os.environ.get("EVAL_TOOL_PATH", "").split(os.pathsep) if p] + [None]
    for path in search_paths:
        for name in names:
            found = shutil.which(name, path=path)
            if found:
                return found
    bindir = Path(sys.executable).parent
    for candidate in (bindir / tool, bindir / f"{tool}.exe", bindir / f"{tool}.cmd"):
        if candidate.is_file():
            return str(candidate)
    return None


def _scrubbed_env(home: Path, extra: dict[str, str] | None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "TMPDIR": str(home),
        "TEMP": str(home),
        "TMP": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "NO_COLOR": "1",
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "TRIVY_NO_PROGRESS": "true",
    }
    if os.name == "nt":
        for key in ("SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "WINDIR"):
            if key in os.environ:
                env[key] = os.environ[key]
    if extra:
        env.update(extra)
    return env


def _posix_limits(cpu_seconds: int, memory_bytes: int | None, fsize_bytes: int):  # pragma: no cover - POSIX only
    def apply():
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 5))
        if memory_bytes:  # None for tools that mmap large files (Trivy); cgroup mem_limit still applies
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_bytes, fsize_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return apply


def _read_capped(fh, cap: int) -> tuple[str, bool]:
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    fh.seek(0)
    data = fh.read(cap)
    return data.decode("utf-8", errors="replace"), size > cap


def run(
    tool: str,
    args: list[str],
    *,
    cwd: Path,
    timeout: int = 300,
    max_output: int = DEFAULT_MAX_OUTPUT,
    memory_bytes: int | None = 3 * 1024 * 1024 * 1024,
    env_extra: dict[str, str] | None = None,
) -> ToolResult:
    if tool not in ALLOWED_TOOLS:
        raise SandboxError(f"tool {tool!r} is not allow-listed")
    exe = which(tool)
    if exe is None:
        raise SandboxError(f"tool {tool!r} is not installed")
    if any(not isinstance(a, str) or "\x00" in a for a in args):
        raise SandboxError("invalid argument")

    home = Path(tempfile.mkdtemp(prefix=f"eval-{tool}-"))
    kwargs: dict = {
        "cwd": str(cwd),
        "env": _scrubbed_env(home, env_extra),
        "stdin": subprocess.DEVNULL,
        "shell": False,
    }
    if os.name == "posix":  # pragma: no cover - exercised in the Linux container
        kwargs["start_new_session"] = True
        kwargs["preexec_fn"] = _posix_limits(timeout, memory_bytes, 512 * 1024 * 1024)
    else:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    start = time.monotonic()
    timed_out = False
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            # argv list with an allow-listed, absolute executable; never a shell.
            proc = subprocess.Popen([exe, *args], stdout=out, stderr=err, **kwargs)  # nosec B603  # noqa: S603
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_tree(proc)
                proc.wait(timeout=10)
            stdout, t1 = _read_capped(out, max_output)
            stderr, t2 = _read_capped(err, 256 * 1024)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return ToolResult(
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        truncated=t1 or t2,
        duration=time.monotonic() - start,
    )


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":  # pragma: no cover
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            # Fixed argv: Windows system utility that terminates the whole process tree.
            subprocess.run(  # nosec B603 B607  # noqa: S603
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],  # noqa: S607
                capture_output=True, timeout=10, check=False,
            )
    except (OSError, subprocess.SubprocessError):
        proc.kill()
