"""Performance and scalability risks found statically (blocking calls, missing timeouts, process-local state,
in-memory session stores, local-disk uploads). Nothing is executed or measured: every finding here is a *static
estimate* (kind=estimate) unless it is a concrete misconfiguration such as a missing timeout.

Database access patterns (N+1 queries, unbounded queries, missing pagination) are reported by the database
analyzer, which resolves queries against the schema."""

from __future__ import annotations

import ast
import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

HTTP_FUNCS = {"get", "post", "put", "patch", "delete", "head", "request", "options"}
BLOCKING_IN_ASYNC = {"time.sleep", "requests.get", "requests.post", "requests.put", "requests.delete",
                     "requests.request", "urllib.request.urlopen", "subprocess.run", "subprocess.call"}
# Names that suggest data, not configuration: module-level containers with these names written by request handlers.
STATE_NAME = re.compile(r"(?i)(cache|session|store|state|users|items|data|db|records|counter|count|queue|jobs|tokens|"
                        r"carts?|orders|visits|memory|registry|buffer|pending|seen|results|messages|rooms|clients)")
MUTABLE_FACTORIES = {"dict", "list", "set", "defaultdict", "OrderedDict", "Counter", "deque"}
MUTATORS = {"append", "add", "update", "setdefault", "extend", "insert", "__setitem__", "appendleft"}
JS_STATE_DECL = re.compile(r"^(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=\s*(?:\{\s*\}|\[\s*\]|new\s+"
                           r"(?:Map|Set)\s*(?:<[^>]*>)?\(\s*\))\s*;?\s*$")


def _call_name(node: ast.Call) -> str:
    parts = []
    f = node.func
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def _is_route(func: ast.AST) -> bool:
    return any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
               and d.func.attr in {"route", "get", "post", "put", "patch", "delete"}
               for d in getattr(func, "decorator_list", []))


@register
class PerformanceAnalyzer(Analyzer):
    name = "performance"
    title = "Performance & scalability (static)"
    categories = (Category.PERFORMANCE,)
    languages = ("python", "javascript", "typescript")

    def run(self, ctx: AnalyzerContext):
        findings = []
        for rel in ctx.python_files():
            if is_test_path(rel):
                continue
            tree = ctx.python_ast(rel)
            if tree is not None:
                findings.extend(self._python(ctx, rel, tree))
        for rel in ctx.files_with_suffix(".js", ".ts", ".mjs", ".cjs"):
            if is_test_path(rel):
                continue
            findings.extend(self._js(ctx, rel))
        return findings

    def _f(self, ctx, rule, title, sev, conf, kind, desc, fix, rel, line):
        return self.finding(ctx, rule=rule, title=title, category=Category.PERFORMANCE, severity=sev,
                            confidence=conf, kind=kind, description=desc, remediation=fix, file_path=rel, line=line)

    def _in_process_state(self, ctx, rel, tree):
        """Module-level mutable containers that request handlers write to: per-process state that is lost on
        restart, diverges between workers/replicas, and grows without bound."""
        containers: dict[str, int] = {}
        for stmt in tree.body:
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target] if isinstance(
                stmt, ast.AnnAssign) else []
            value = getattr(stmt, "value", None)
            mutable = isinstance(value, ast.Dict | ast.List | ast.Set) or (
                isinstance(value, ast.Call) and _call_name(value).rpartition(".")[2] in MUTABLE_FACTORIES)
            for t in targets:
                if mutable and isinstance(t, ast.Name) and STATE_NAME.search(t.id):
                    containers[t.id] = stmt.lineno
        if not containers:
            return []
        out = []
        for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]:
            if not _is_route(func):
                continue
            for node in ast.walk(func):
                written = None
                if isinstance(node, ast.Assign | ast.AugAssign):
                    for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                        if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                            written = t.value.id
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(
                        node.func.value, ast.Name) and node.func.attr in MUTATORS:
                    written = node.func.value.id
                if written in containers:
                    out.append(self._f(ctx, "performance.in-process-state", f"Request handler stores state in "
                                       f"module-level `{written}`", Severity.MEDIUM, Confidence.MEDIUM,
                                       FindingKind.ESTIMATE,
                                       f"`{written}` (line {containers.pop(written)}) is a process-local container "
                                       f"written by `{func.name}()`. It is lost on restart, each worker/replica sees "
                                       "different data, and it grows without bound — the app cannot scale "
                                       "horizontally. (Static estimate.)",
                                       "Move shared state to a database or cache (Redis, Memcached) with expiry, "
                                       "or use a bounded cache (functools.lru_cache, cachetools.TTLCache) if it is "
                                       "only a per-process cache.", rel, node.lineno))
                    if not containers:
                        return out
        return out

    def _local_uploads(self, ctx, rel, tree):
        for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]:
            if not _is_route(func) or "request.files" not in ast.unparse(func):
                continue
            for node in ast.walk(func):
                if isinstance(node, ast.Call) and _call_name(node).endswith(".save"):
                    return [self._f(ctx, "performance.local-file-storage", "Uploaded files saved to the local "
                                    "filesystem", Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                    "Files written to the web server's disk are invisible to other replicas and "
                                    "are lost when the container is replaced, which blocks horizontal scaling. "
                                    "(Fine for a single persistent server.)",
                                    "Store uploads in object storage (S3, GCS, Azure Blob) or a shared volume.",
                                    rel, node.lineno)]
        return []

    def _python(self, ctx, rel, tree):
        out = self._in_process_state(ctx, rel, tree) + self._local_uploads(ctx, rel, tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node)
                root, _, attr = name.rpartition(".")
                if root in ("requests", "httpx") and attr in HTTP_FUNCS and not any(
                        k.arg == "timeout" for k in node.keywords):
                    out.append(self._f(ctx, "performance.http-without-timeout", f"{name}() without a timeout",
                                       Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "Outbound HTTP calls without a timeout can hang a worker indefinitely when "
                                       "the remote end stalls, exhausting the pool under load."
                                       + (" (httpx has a 5s default; set it explicitly.)" if root == "httpx" else ""),
                                       "Pass an explicit timeout (connect, read) and handle timeouts.",
                                       rel, node.lineno))
            if isinstance(node, ast.AsyncFunctionDef):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Call) and _call_name(inner) in BLOCKING_IN_ASYNC:
                        out.append(self._f(ctx, "performance.blocking-call-in-async", f"Blocking call "
                                           f"{_call_name(inner)}() inside async function", Severity.MEDIUM,
                                           Confidence.HIGH, FindingKind.CONFIRMED,
                                           "A synchronous call blocks the event loop, stalling every concurrent "
                                           "request on that worker.",
                                           "Use the async equivalent (asyncio.sleep, httpx.AsyncClient) or run it in "
                                           "a thread executor.", rel, inner.lineno))
        return out

    def _js(self, ctx, rel):
        out = []
        text = ctx.read(rel) or ""
        lines = ctx.lines(rel)
        is_server = bool(re.search(r"\b(app|router)\.(get|post|put|patch|delete)\(", text))
        containers = {m.group(1): i for i, ln in enumerate(lines, start=1) if (m := JS_STATE_DECL.match(ln))
                      and STATE_NAME.search(m.group(1))} if is_server else {}
        for i, line in enumerate(lines, start=1):
            if is_server and re.search(r"\b(readFileSync|writeFileSync|execSync|pbkdf2Sync|scryptSync)\(", line):
                out.append(self._f(ctx, "performance.sync-io-in-server", "Synchronous I/O in a server module",
                                   Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                   "Sync APIs block Node's single event loop; if called per request, all clients "
                                   "wait. (Static estimate — it may only run at startup.)",
                                   "Use the async/promise API inside request paths.", rel, i))
            for name in list(containers):
                if i > containers[name] and re.search(rf"\b{re.escape(name)}(\[[^\]]+\]\s*=[^=]|\.(push|set|add)\()",
                                                      line):
                    out.append(self._f(ctx, "performance.in-process-state", f"Server stores state in module-level "
                                       f"`{name}`", Severity.MEDIUM, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                       f"`{name}` (line {containers[name]}) is process-local. It is lost on restart, "
                                       "differs between cluster workers/replicas, and grows without bound — the app "
                                       "cannot scale horizontally. (Static estimate.)",
                                       "Keep shared state in a database or cache (Redis) with expiry, or use a "
                                       "bounded LRU cache if it is only a per-process cache.", rel, i))
                    del containers[name]
        if re.search(r"""require\(\s*["']express-session["']\s*\)|from\s+["']express-session["']""", text) and \
                re.search(r"\bsession\(\s*\{", text) and not re.search(r"\bstore\s*:", text):
            line = next((i for i, ln in enumerate(lines, 1) if re.search(r"\bsession\(\s*\{", ln)), None)
            out.append(self._f(ctx, "performance.memory-session-store", "express-session uses the default "
                               "in-memory store", Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                               "MemoryStore leaks memory, is not shared between processes, and loses every session "
                               "on restart; express-session documents it as unsuitable for production.",
                               "Configure a shared store (connect-redis, connect-pg-simple, …).", rel, line))
        if re.search(r"\bmulter\(\s*\{\s*dest\s*:|multer\.diskStorage\(", text):
            line = next((i for i, ln in enumerate(lines, 1) if re.search(r"multer\(\s*\{\s*dest|diskStorage", ln)),
                        None)
            out.append(self._f(ctx, "performance.local-file-storage", "Uploaded files saved to the local "
                               "filesystem", Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                               "Uploads written to the server's disk are invisible to other replicas and lost when "
                               "the container is replaced.",
                               "Stream uploads to object storage (S3, GCS, Azure Blob) or a shared volume.", rel, line))
        return out
