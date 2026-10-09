"""Performance and scalability risks found statically. Nothing is executed or measured: every finding here
is a *static estimate* (kind=estimate) unless it is a concrete misconfiguration such as a missing timeout."""

from __future__ import annotations

import ast
import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

HTTP_FUNCS = {"get", "post", "put", "patch", "delete", "head", "request", "options"}
QUERY_ATTRS = {"execute", "scalar", "scalars", "filter", "filter_by", "get", "first", "one", "all",
               "get_or_404", "first_or_404"}
ORM_ROOTS = re.compile(r"(\.query\b|\bsession\b|\.objects\b|\bdb\.)")
BLOCKING_IN_ASYNC = {"time.sleep", "requests.get", "requests.post", "requests.put", "requests.delete",
                     "requests.request", "urllib.request.urlopen", "subprocess.run", "subprocess.call"}


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

    def _python(self, ctx, rel, tree):
        out = []
        reported_loops = set()
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
            if isinstance(node, ast.For | ast.AsyncFor):
                for inner in ast.walk(node):
                    if inner is node or not isinstance(inner, ast.Call):
                        continue
                    name = _call_name(inner)
                    attr = name.rpartition(".")[2]
                    if attr in QUERY_ATTRS and ORM_ROOTS.search("." + name) and node.lineno not in reported_loops:
                        reported_loops.add(node.lineno)
                        out.append(self._f(ctx, "performance.query-in-loop", "Database query inside a loop "
                                           "(possible N+1)", Severity.MEDIUM, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                           f"`{name}()` runs once per iteration of the loop at line {node.lineno}. "
                                           "With N items this issues N queries; latency grows linearly with data "
                                           "size. (Static estimate — not measured.)",
                                           "Fetch in bulk (IN clause, joinedload/selectinload, prefetch_related) "
                                           "before the loop.", rel, inner.lineno))
                        break
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
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _is_route(node):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Call) and _call_name(inner).endswith(".all") and ".query" in _call_name(
                            inner) and not re.search(r"\b(limit|paginate|slice)\b", ast.unparse(inner)):
                        out.append(self._f(ctx, "performance.unbounded-query", "Unbounded query in request handler",
                                           Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                           "`.all()` returns every row; response time and memory grow with table "
                                           "size. (Static estimate.)", "Paginate (limit/offset or keyset).",
                                           rel, inner.lineno))
                        break
        return out

    def _js(self, ctx, rel):
        out = []
        text = ctx.read(rel) or ""
        is_server = bool(re.search(r"\b(app|router)\.(get|post|put|patch|delete)\(", text))
        for i, line in enumerate(ctx.lines(rel), start=1):
            if is_server and re.search(r"\b(readFileSync|writeFileSync|execSync|pbkdf2Sync|scryptSync)\(", line):
                out.append(self._f(ctx, "performance.sync-io-in-server", "Synchronous I/O in a server module",
                                   Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                   "Sync APIs block Node's single event loop; if called per request, all clients "
                                   "wait. (Static estimate — it may only run at startup.)",
                                   "Use the async/promise API inside request paths.", rel, i))
        return out
