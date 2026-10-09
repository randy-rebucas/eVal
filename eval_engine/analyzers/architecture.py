"""Architecture: module import graph (Python + relative JS/TS imports), dependency cycles, excessive coupling,
data access inside request handlers, and scattered configuration access.

The import graph is also exposed via ``build_import_graph`` for future knowledge-graph features.
"""

from __future__ import annotations

import ast
import posixpath
import re
from collections import defaultdict

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

FAN_OUT_LIMIT = 25
CONFIG_SPRAWL_FILES = 12
JS_IMPORT = re.compile(
    r"""(?:import\s[^'"]*?from\s*|import\s*\(\s*|require\s*\(\s*|export\s[^'"]*?from\s*)"""
    r"""["'](\.{1,2}/[^"']+)["']"""
)
JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
SQL_IN_HANDLER = re.compile(
    r"(?is)\b(execute|raw|query)\s*\(\s*[fFrRbB]?[\"'](\s*select|\s*insert|\s*update|\s*delete)"
)


def _python_module_map(files: list[str]) -> dict[str, str]:
    """Map dotted module names to files.

    A file's import name starts at its top-most enclosing *package* (directories with ``__init__.py``), so
    ``src/app/models.py`` with ``src/app/__init__.py`` is ``app.models``. Top-level scripts map to their own
    name. The full path form is also registered for repos that run from the root.
    """
    file_set = set(files)
    mapping: dict[str, str] = {}
    for rel in files:
        if not rel.endswith(".py"):
            continue
        parts = rel[:-3].split("/")
        start = len(parts) - 1
        while start > 0 and "/".join(parts[:start]) + "/__init__.py" in file_set:
            start -= 1
        names = [parts[start:], parts]
        for name_parts in names:
            if name_parts and name_parts[-1] == "__init__":
                name_parts = name_parts[:-1]
            if name_parts:
                mapping.setdefault(".".join(name_parts), rel)
    return mapping


def _resolve_relative(rel: str, module: str | None, level: int) -> str:
    pkg = rel[:-3].split("/")
    pkg = pkg[:-1] if pkg[-1] != "__init__" else pkg[:-1]
    base = pkg[: len(pkg) - (level - 1)] if level > 1 else pkg
    return ".".join([*base, *(module.split(".") if module else [])])


def build_import_graph(ctx: AnalyzerContext) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    py_files = [f for f in ctx.python_files() if not is_test_path(f)]
    modmap = _python_module_map(py_files)
    for rel in py_files:
        tree = ctx.python_ast(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Import):
                targets = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = _resolve_relative(rel, node.module, node.level) if node.level else (node.module or "")
                # `from pkg import mod` imports the submodule when one exists; otherwise a name from pkg.
                targets = [f"{base}.{a.name}" for a in node.names] + [base]
            for t in targets:
                dest = modmap.get(t)
                if dest and dest != rel:
                    graph[rel].add(dest)
                    if isinstance(node, ast.Import):
                        continue
                    if t != base:
                        continue  # each imported submodule is its own edge
                    break
    js_files = [f for f in ctx.files_with_suffix(*JS_EXTS) if not is_test_path(f)]
    js_set = set(js_files)
    for rel in js_files:
        for m in JS_IMPORT.finditer(ctx.read(rel) or ""):
            target = posixpath.normpath(posixpath.join(posixpath.dirname(rel), m.group(1)))
            candidates = [target] + [target + e for e in JS_EXTS] + [f"{target}/index{e}" for e in JS_EXTS]
            for c in candidates:
                if c in js_set and c != rel:
                    graph[rel].add(c)
                    break
    return graph


def strongly_connected(graph: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan's algorithm (iterative). Returns components with more than one node."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0
    nodes = set(graph) | {d for deps in graph.values() for d in deps}
    for root in sorted(nodes):
        if root in index:
            continue
        work = [(root, iter(sorted(graph.get(root, ()))))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for nxt in it:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(sorted(graph.get(nxt, ())))))
                    advanced = True
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                if len(comp) > 1:
                    result.append(sorted(comp))
    return result


@register
class ArchitectureAnalyzer(Analyzer):
    name = "architecture"
    title = "Architecture & module structure"
    categories = (Category.ARCHITECTURE,)

    def applicable(self, ctx: AnalyzerContext):
        if not (ctx.languages.has("python") or any(ctx.languages.has(x) for x in ("javascript", "typescript"))):
            return "import-graph analysis supports Python and JavaScript/TypeScript"
        return None

    def run(self, ctx: AnalyzerContext):
        findings = []
        graph = build_import_graph(ctx)
        for comp in strongly_connected(graph)[:30]:
            findings.append(self.finding(
                ctx, rule="architecture.import-cycle", title=f"Circular dependency between {len(comp)} modules",
                category=Category.ARCHITECTURE, severity=Severity.MEDIUM if len(comp) > 2 else Severity.LOW,
                confidence=Confidence.HIGH, kind=FindingKind.CONFIRMED,
                description="These modules import each other (directly or transitively): " + " → ".join(comp[:12])
                + ". Cycles couple modules so they cannot be understood, tested, or changed independently, and in "
                "Python can cause partially-initialized-module import errors.",
                remediation="Move shared code into a lower-level module, invert the dependency with an interface, "
                "or merge modules that are not truly separate.", file_path=comp[0],
                evidence="cycle: " + ", ".join(comp[:12])))
        for rel, deps in sorted(graph.items()):
            if len(deps) > FAN_OUT_LIMIT:
                findings.append(self.finding(
                    ctx, rule="architecture.high-fan-out", title=f"Module depends on {len(deps)} internal modules",
                    category=Category.ARCHITECTURE, severity=Severity.LOW, confidence=Confidence.HIGH,
                    kind=FindingKind.CONFIRMED,
                    description=f"{rel} imports {len(deps)} other project modules (limit {FAN_OUT_LIMIT}); it is "
                    "likely a 'god module' that changes for many reasons.",
                    remediation="Split responsibilities; depend on narrower interfaces.", file_path=rel))
        findings.extend(self._layering(ctx))
        findings.extend(self._config_sprawl(ctx))
        return findings

    def _layering(self, ctx):
        out = []
        for rel in ctx.python_files():
            if is_test_path(rel):
                continue
            text = ctx.read(rel) or ""
            if not re.search(r"@\w+\.(route|get|post|put|patch|delete)\(", text):
                continue
            m = SQL_IN_HANDLER.search(text)
            if m:
                line = text[: m.start()].count("\n") + 1
                out.append(self.finding(
                    ctx, rule="architecture.sql-in-handlers", title="Raw SQL inside request handler module",
                    category=Category.ARCHITECTURE, severity=Severity.LOW, confidence=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL,
                    description="HTTP route definitions and SQL statements live in the same module, coupling "
                    "transport, business logic, and persistence.",
                    remediation="Move data access into a repository/service layer that handlers call.",
                    file_path=rel, line=line))
        return out

    def _config_sprawl(self, ctx):
        readers = [f for f in ctx.files_with_suffix(".py", ".js", ".ts", ".mjs")
                   if not is_test_path(f) and re.search(r"os\.environ|os\.getenv|process\.env", ctx.read(f) or "")]
        if len(readers) >= CONFIG_SPRAWL_FILES:
            return [self.finding(
                ctx, rule="architecture.config-sprawl", title=f"Environment variables read in {len(readers)} files",
                category=Category.ARCHITECTURE, severity=Severity.LOW, confidence=Confidence.HIGH,
                kind=FindingKind.CONFIRMED,
                description="Configuration is read ad hoc across many modules, so required settings are "
                "undocumented and not validated at startup.",
                remediation="Centralize configuration in one module that validates all settings at boot.",
                file_path=readers[0], evidence=", ".join(readers[:10]))]
        return []
