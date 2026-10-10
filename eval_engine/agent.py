"""eVal inside AI coding agents: a Claude Code hook, an MCP server, and changed-file audits.

* ``eval-audit hook``: a Claude Code ``PostToolUse`` hook. After the agent writes or edits a file, eVal audits the
  project with its fast built-in analyzers (offline, nothing executed) and, when the edited file has findings at or
  above the threshold, exits with code 2 and prints them to stderr. Claude Code feeds that back to the agent, which
  then fixes its own output before moving on.
* ``eval-audit mcp``: a Model Context Protocol server on stdio (Claude Code, Cursor, any MCP client) with tools to
  audit a project, audit only changed files, or check single files. Paths are confined to ``--root``.
* ``changed_files``: files changed relative to a git ref (plus untracked files), for ``eval-audit --changed``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - runs git with a fixed argument list, never a shell
import sys
from pathlib import Path

from . import ENGINE_VERSION
from .analyzers import registry
from .findings import SEVERITY_RANK, Severity
from .pipeline import AuditResult, PipelineConfig, run_pipeline
from .policy import POLICY_FILE, PolicyError, layered

MCP_PROTOCOL_VERSION = "2025-06-18"
EDIT_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
MAX_REPORTED = 20


def fast_analyzers() -> list[str]:
    """Built-in analyzers: no external tool, no network. Typically about a second on a mid-sized repository."""
    return [a.name for a in registry.all_analyzers() if a.tool is None and not a.network_use]


def changed_files(root: Path, base: str = "HEAD") -> list[str]:
    """Paths (relative to ``root``) changed since ``base``, staged or not, plus untracked files."""
    exe = shutil.which("git")
    if exe is None:
        raise ValueError("git is not installed")

    def git(*args: str) -> list[str]:
        try:
            out = subprocess.run([exe, "-C", str(root), *args], capture_output=True, text=True,  # nosec B603  # noqa: S603
                                 timeout=30, check=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError(f"git failed: {getattr(exc, 'stderr', '') or exc}".strip()) from None
        return [ln for ln in out.stdout.splitlines() if ln.strip()]

    if base.startswith("-"):
        raise ValueError("invalid git reference")
    prefix = (git("rev-parse", "--show-prefix") or [""])[0]
    paths = set(git("diff", "--name-only", "--relative", base, "--"))
    paths.update(git("ls-files", "--others", "--exclude-standard"))
    return sorted(p[len(prefix):] if prefix and p.startswith(prefix) else p for p in paths)


def load_policy(root: Path):
    path = root / POLICY_FILE
    if path.is_file() and not path.is_symlink():
        return layered([("repository file", path.read_text(encoding="utf-8"))])
    return layered([])


def quick_audit(root: Path, analyzers: list[str] | None = None, offline: bool = True) -> AuditResult:
    return run_pipeline(root, PipelineConfig(analyzers=analyzers or fast_analyzers(), offline=offline,
                                             policy=load_policy(root)))


def at_or_above(findings, threshold: str) -> list:
    rank = SEVERITY_RANK[Severity(threshold)]
    return [f for f in findings if f.scored and SEVERITY_RANK[f.severity] >= rank]


def describe(findings, limit: int = MAX_REPORTED) -> str:
    lines = []
    for f in findings[:limit]:
        loc = f"{f.file_path}:{f.line_start}" if f.line_start else (f.file_path or "(repository)")
        lines.append(f"- [{str(f.severity).upper()}] {f.title} ({loc}, rule {f.rule_id})\n  Fix: {f.remediation}")
    if len(findings) > limit:
        lines.append(f"- … and {len(findings) - limit} more")
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------------- hook
def _project_root(path: Path) -> Path:
    for parent in [path.parent, *path.parents]:
        if (parent / ".git").exists() or (parent / POLICY_FILE).is_file():
            return parent
    return path.parent


def hook_main(stdin=None, stderr=None, fail_on: str | None = None) -> int:
    """Claude Code PostToolUse hook. Exit 0 = nothing to report, 2 = findings for the agent to fix."""
    stdin, stderr = stdin or sys.stdin, stderr or sys.stderr
    fail_on = fail_on or os.environ.get("EVAL_HOOK_FAIL_ON", "high")
    if fail_on not in SEVERITY_RANK:
        print(f"eVal hook: invalid EVAL_HOOK_FAIL_ON {fail_on!r}", file=stderr)
        return 0  # never block the agent because of our own configuration error
    try:
        event = json.load(stdin)
    except ValueError:
        return 0
    if event.get("tool_name") not in EDIT_TOOLS:
        return 0
    raw = (event.get("tool_input") or {}).get("file_path") or (event.get("tool_input") or {}).get("notebook_path")
    if not raw:
        return 0
    cwd = Path(event.get("cwd") or os.getcwd())
    target = (cwd / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
    if not target.is_file():
        return 0
    root = _project_root(target)
    try:
        rel = target.relative_to(root.resolve()).as_posix()
        result = quick_audit(root)
    except (ValueError, PolicyError, OSError) as exc:
        print(f"eVal hook skipped: {exc}", file=stderr)
        return 0
    hits = at_or_above([f for f in result.findings if f.file_path == rel], fail_on)
    if not hits:
        return 0
    print(f"eVal found {len(hits)} issue(s) at or above '{fail_on}' in {rel} that this edit should not leave behind."
          f" Fix them now (or explain why they are false positives):\n{describe(hits)}", file=stderr)
    return 2


# ------------------------------------------------------------------------------------------------- MCP
TOOLS = [
    {"name": "eval_audit",
     "description": "Audit a project directory for production readiness (security, dependencies, tests, AI-generated "
                    "code patterns, …) with eVal's static analyzers. Nothing is executed. Returns findings with "
                    "file, line, severity and a recommended fix.",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string", "description": "directory to audit (default: the server root)"},
         "changed_only": {"type": "boolean", "description": "only report findings in files changed since `base`"},
         "base": {"type": "string", "description": "git ref for changed_only (default HEAD)"},
         "min_severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
         "full": {"type": "boolean", "description": "also run installed external tools (slower)"}}}},
    {"name": "eval_check_files",
     "description": "Check specific files you just wrote or changed. Fast (built-in analyzers only); use after "
                    "every significant edit.",
     "inputSchema": {"type": "object", "required": ["paths"], "properties": {
         "paths": {"type": "array", "items": {"type": "string"}},
         "min_severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]}}}},
]


class MCPServer:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def _inside(self, raw: str) -> Path:
        p = (self.root / raw).resolve() if raw else self.root
        if p != self.root and self.root not in p.parents:
            raise ValueError(f"{raw} is outside the server root {self.root}")
        return p

    def _summary(self, result: AuditResult, findings, scope: str) -> dict:
        card = result.scorecard
        return {"scope": scope, "overall_score": card.overall, "risk": card.risk, "findings": len(findings),
                "results": [{"severity": str(f.severity), "title": f.title, "file": f.file_path, "line": f.line_start,
                             "rule": f.rule_id, "remediation": f.remediation} for f in findings[:100]],
                "skipped_analyzers": {o.name: o.reason for o in result.outcomes if o.status != "ok"}}

    def call(self, name: str, args: dict) -> dict:
        min_sev = args.get("min_severity") or "low"
        if min_sev not in SEVERITY_RANK:
            raise ValueError("min_severity must be critical, high, medium, low or info")
        if name == "eval_audit":
            root = self._inside(args.get("path") or "")
            if not root.is_dir():
                raise ValueError(f"{root} is not a directory")
            result = quick_audit(root, analyzers=None if args.get("full") else fast_analyzers(),
                                 offline=not args.get("full"))
            findings = at_or_above(result.findings, min_sev)
            scope = "all files"
            if args.get("changed_only"):
                changed = set(changed_files(root, args.get("base") or "HEAD"))
                findings = [f for f in findings if f.file_path in changed]
                scope = f"files changed since {args.get('base') or 'HEAD'}"
            return self._summary(result, findings, scope)
        if name == "eval_check_files":
            paths = [self._inside(p) for p in (args.get("paths") or [])[:50]]
            if not paths:
                raise ValueError("paths is required")
            root = _project_root(paths[0])
            if self.root not in [root, *root.parents]:
                root = self.root
            rels = {p.relative_to(root).as_posix() for p in paths if root in p.parents}
            result = quick_audit(root)
            findings = at_or_above([f for f in result.findings if f.file_path in rels], min_sev)
            return self._summary(result, findings, ", ".join(sorted(rels)))
        raise KeyError(name)

    def handle(self, msg: dict) -> dict | None:
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:  # notification (e.g. notifications/initialized)
            return None
        try:
            if method == "initialize":
                result = {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {"tools": {}},
                          "serverInfo": {"name": "eval", "version": ENGINE_VERSION},
                          "instructions": "Call eval_check_files after writing or editing code, and eval_audit "
                                          "with changed_only=true before finishing a task."}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                params = msg.get("params") or {}
                try:
                    data = self.call(params.get("name", ""), params.get("arguments") or {})
                    result = {"content": [{"type": "text", "text": json.dumps(data, indent=1)}], "isError": False}
                except KeyError:
                    return _error(mid, -32602, f"unknown tool {params.get('name')!r}")
                except (ValueError, PolicyError, OSError) as exc:
                    result = {"content": [{"type": "text", "text": f"eVal error: {exc}"}], "isError": True}
            else:
                return _error(mid, -32601, f"method not found: {method}")
        except Exception as exc:  # noqa: BLE001 - a bug must not kill the server session
            return _error(mid, -32603, f"internal error ({type(exc).__name__})")
        return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def mcp_main(root: Path, stdin=None, stdout=None) -> int:
    """Serve MCP over stdio: one JSON-RPC message per line."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    server = MCPServer(root)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            reply = _error(None, -32700, "parse error")
        else:
            reply = server.handle(msg) if isinstance(msg, dict) else _error(None, -32600, "invalid request")
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()
    return 0
