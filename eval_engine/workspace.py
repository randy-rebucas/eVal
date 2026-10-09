"""Secure repository acquisition and traversal.

Everything here treats repository content as hostile:

* ZIP archives: no absolute paths, drive letters, ``..`` segments, symlinks, device files, or encrypted
  members; file-count, per-file, total-size, and compression-ratio limits are enforced while *streaming*
  (header sizes are not trusted).
* Git: ``https`` only, host allow-list, ``owner/repo`` path validation, shallow fetch of exactly one ref,
  no submodules, no LFS smudge, symlinks checked out as plain files, user/system git config ignored, and
  credentials passed through environment-scoped git config (never in argv, URL, or logs).
* Traversal: symlinks are never followed; vendored/generated directories are skipped.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import stat
import tempfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "env", "__pycache__",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox", "dist", "build", ".next", ".nuxt",
        "coverage", "htmlcov", "vendor", "third_party", ".terraform", ".gradle", "target", ".idea", ".vscode",
    }
)

_REF_RE = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)[A-Za-z0-9._/\-]{1,255}(?<!\.lock)(?<!/)$")
_REPO_PATH_RE = re.compile(r"^/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$")


class WorkspaceError(Exception):
    """Raised for any rejected or unsafe repository input. Messages are safe to show to users."""


@dataclass(frozen=True)
class Limits:
    max_files: int = 20_000
    max_total_bytes: int = 500 * 1024 * 1024
    max_file_bytes: int = 20 * 1024 * 1024
    max_compression_ratio: int = 200
    max_path_length: int = 1024
    max_depth: int = 64


DEFAULT_LIMITS = Limits()


@dataclass
class ExtractStats:
    files: int = 0
    bytes: int = 0
    skipped: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------------- paths


def validate_relative_path(name: str, limits: Limits = DEFAULT_LIMITS) -> PurePosixPath:
    """Normalize an archive member name to a safe relative POSIX path or raise."""
    if not name or "\x00" in name:
        raise WorkspaceError("Archive contains an empty or NUL-containing path.")
    if len(name) > limits.max_path_length:
        raise WorkspaceError("Archive contains an overly long path.")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise WorkspaceError(f"Archive contains an absolute path: {name[:200]!r}")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise WorkspaceError(f"Archive contains a path traversal entry: {name[:200]!r}")
    if len(parts) > limits.max_depth:
        raise WorkspaceError("Archive nesting is too deep.")
    if not parts:
        raise WorkspaceError("Archive contains an invalid path.")
    return PurePosixPath(*parts)


def safe_join(root: Path, relative: str | PurePosixPath) -> Path:
    """Join and verify the result stays inside ``root`` (defence in depth against traversal)."""
    root_resolved = root.resolve()
    candidate = (root_resolved / str(relative)).resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise WorkspaceError("Path escapes the workspace.")
    return candidate


# ----------------------------------------------------------------------------------------------- zip


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _is_special(info: zipfile.ZipInfo) -> bool:
    """Device, FIFO, or socket entries. Many archivers store permission bits without file-type bits;
    those are regular files."""
    mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    return bool(file_type) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode))


def extract_zip(zip_path: Path, dest: Path, limits: Limits = DEFAULT_LIMITS) -> ExtractStats:
    """Safely extract ``zip_path`` into the (empty or new) directory ``dest``."""
    dest.mkdir(parents=True, exist_ok=True)
    stats = ExtractStats()
    try:
        archive = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise WorkspaceError("Upload is not a valid ZIP archive.") from exc

    with archive:
        members = archive.infolist()
        if len(members) > limits.max_files * 2:
            raise WorkspaceError("Archive has too many entries.")
        prefix = _common_top_level_dir(members)
        for info in members:
            rel = validate_relative_path(info.filename, limits)
            if prefix is not None:
                rel = PurePosixPath(*rel.parts[1:]) if len(rel.parts) > 1 else None
                if rel is None:
                    continue
            if info.flag_bits & 0x1:
                raise WorkspaceError("Encrypted archive members are not supported.")
            if _is_symlink(info):
                stats.skipped.append(f"{rel} (symlink)")
                continue
            if _is_special(info):
                stats.skipped.append(f"{rel} (special file)")
                continue
            if info.is_dir():
                safe_join(dest, rel).mkdir(parents=True, exist_ok=True)
                continue
            if info.file_size > limits.max_file_bytes:
                stats.skipped.append(f"{rel} (exceeds per-file size limit)")
                continue
            if info.compress_size and info.file_size / max(info.compress_size, 1) > limits.max_compression_ratio:
                raise WorkspaceError("Archive compression ratio is suspicious (possible zip bomb).")
            stats.files += 1
            if stats.files > limits.max_files:
                raise WorkspaceError(f"Archive exceeds the {limits.max_files} file limit.")
            target = safe_join(dest, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(64 * 1024):
                    written += len(chunk)
                    if written > info.file_size or written > limits.max_file_bytes:
                        raise WorkspaceError("Archive member is larger than declared (possible zip bomb).")
                    if stats.bytes + written > limits.max_total_bytes:
                        raise WorkspaceError("Archive exceeds the total extracted size limit.")
                    out.write(chunk)
            stats.bytes += written
    return stats


def _common_top_level_dir(members: list[zipfile.ZipInfo]) -> str | None:
    """GitHub-style archives wrap everything in ``repo-sha/``; strip it when *all* entries share it."""
    tops = set()
    for info in members:
        name = info.filename.replace("\\", "/")
        while name.startswith(("./", "/")):
            name = name[1:] if name.startswith("/") else name[2:]
        if not name:
            continue
        head, sep, _ = name.partition("/")
        if not sep:
            return None  # a file at the root
        tops.add(head)
        if len(tops) > 1:
            return None
    return next(iter(tops)) if len(tops) == 1 else None


# ----------------------------------------------------------------------------------------------- git


@dataclass
class CloneResult:
    commit_sha: str
    ref: str


def validate_git_url(url: str, allowed_hosts: list[str]) -> tuple[str, str, str]:
    """Return (host, owner, repo) for an allowed ``https://host/owner/repo(.git)`` URL."""
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise WorkspaceError("Only https:// repository URLs are allowed.")
    if parts.username or parts.password:
        raise WorkspaceError("Credentials must not be embedded in the repository URL.")
    host = (parts.hostname or "").lower()
    if host not in {h.lower() for h in allowed_hosts}:
        raise WorkspaceError(f"Repository host {host!r} is not allowed.")
    if parts.port not in (None, 443) or parts.query or parts.fragment:
        raise WorkspaceError("Repository URL must not contain a port, query, or fragment.")
    match = _REPO_PATH_RE.match(parts.path)
    if not match:
        raise WorkspaceError("Repository URL must look like https://host/owner/repo.")
    return host, match.group(1), match.group(2)


def validate_ref(ref: str) -> str:
    ref = ref.strip()
    if not ref or not _REF_RE.match(ref) or "@{" in ref or "\\" in ref:
        raise WorkspaceError("Invalid branch, tag, or commit reference.")
    return ref


def _git_env(token: str | None, home: Path) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ALLOW_PROTOCOL": "https",
    }
    if os.name == "nt":
        for key in ("SYSTEMROOT", "TEMP", "TMP"):
            if key in os.environ:
                env[key] = os.environ[key]
    config = [
        ("protocol.allow", "never"),
        ("protocol.https.allow", "always"),
        ("core.symlinks", "false"),
        ("core.hooksPath", os.devnull),
        ("core.fsmonitor", "false"),
        ("submodule.recurse", "false"),
        ("fetch.recurseSubmodules", "false"),
        ("advice.detachedHead", "false"),
        ("credential.helper", ""),
    ]
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        config.append(("http.extraHeader", f"Authorization: Basic {basic}"))
    env["GIT_CONFIG_COUNT"] = str(len(config))
    for i, (key, value) in enumerate(config):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


def clone_repo(
    url: str,
    dest: Path,
    ref: str,
    *,
    token: str | None = None,
    allowed_hosts: list[str] | None = None,
    timeout: int = 300,
    limits: Limits = DEFAULT_LIMITS,
) -> CloneResult:
    """Shallow-fetch exactly ``ref`` (branch, tag, or commit SHA) into ``dest`` using GitPython."""
    import git  # GitPython; imported lazily so the engine works without it for ZIP-only use

    validate_git_url(url, allowed_hosts or ["github.com"])
    ref = validate_ref(ref)
    dest.mkdir(parents=True, exist_ok=True)
    home = Path(tempfile.mkdtemp(prefix="eval-githome-"))
    env = _git_env(token, home)
    try:
        g = git.Git(str(dest))
        g.update_environment(**env)
        try:
            g.init("--quiet", "--template=")
            g.remote("add", "origin", url)
            _git_with_timeout(g, ["fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "origin", ref],
                              timeout, token)
            _git_with_timeout(g, ["checkout", "--force", "--detach", "FETCH_HEAD"], timeout, token)
            sha = g.rev_parse("HEAD").strip()
        except git.GitCommandError as exc:
            raise WorkspaceError(_sanitize_git_error(exc, token)) from None
    finally:
        shutil.rmtree(home, ignore_errors=True)
    enforce_tree_limits(dest, limits)
    return CloneResult(commit_sha=sha, ref=ref)


def _git_with_timeout(g, args: list[str], timeout: int, token: str | None) -> None:
    """Run a git subcommand via GitPython with a portable wall-clock timeout.

    GitPython's ``kill_after_timeout`` is unsupported on Windows, so the process is driven directly."""
    import subprocess  # nosec B404

    proc = g.execute(["git", *args], as_process=True)
    try:
        _out, err = proc.proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.proc.kill()
        proc.proc.communicate()
        raise WorkspaceError("Fetching the repository timed out.") from None
    if proc.proc.returncode != 0:

        class _Err(Exception):
            stderr = (err or b"").decode("utf-8", "replace")

        raise WorkspaceError(_sanitize_git_error(_Err(), token))


def _sanitize_git_error(exc: Exception, token: str | None) -> str:
    text = str(getattr(exc, "stderr", "") or exc)
    if token:
        text = text.replace(token, "[REDACTED]")
    text = re.sub(r"Authorization: Basic [A-Za-z0-9+/=]+", "Authorization: [REDACTED]", text)
    lowered = text.lower()
    if "timed out" in lowered or "timeout" in lowered:
        return "Fetching the repository timed out."
    if "not found" in lowered or "couldn't find remote ref" in lowered or "could not read" in lowered:
        return "Repository or ref not found, or the credential has no access."
    if "authentication" in lowered or "403" in lowered:
        return "Authentication to the repository failed."
    return "Fetching the repository failed."


def enforce_tree_limits(root: Path, limits: Limits) -> None:
    """Post-checkout size check (git transfer size cannot be bounded up-front)."""
    count = total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            count += 1
            total += st.st_size
            if count > limits.max_files:
                raise WorkspaceError(f"Repository exceeds the {limits.max_files} file limit.")
            if total > limits.max_total_bytes:
                raise WorkspaceError("Repository exceeds the total size limit.")


# --------------------------------------------------------------------------------------------- walk


def iter_files(root: Path, *, max_file_bytes: int = 2 * 1024 * 1024, skip_dirs=SKIP_DIRS) -> Iterator[str]:
    """Yield POSIX relative paths of regular files under ``root``. Never follows symlinks."""
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if d not in skip_dirs and not os.path.islink(os.path.join(dirpath, d))
        )
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size > max_file_bytes:
                continue
            yield Path(full).relative_to(root).as_posix()


def read_text(root: Path, rel: str, max_bytes: int = 2 * 1024 * 1024) -> str | None:
    """Read a repository file as text; returns None for binary/unreadable files."""
    try:
        path = safe_join(root, rel)
        if path.is_symlink() or not path.is_file():
            return None
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except (OSError, WorkspaceError):
        return None
    if len(data) > max_bytes or b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def remove_tree(path: Path) -> None:
    """Remove a workspace, including read-only files (git objects on Windows)."""

    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onexc=_onerror)
