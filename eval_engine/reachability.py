"""Import reachability for dependency vulnerabilities (``vuln:*`` findings from OSV.dev and Trivy).

For each vulnerable package, eVal checks whether the application's own (non-test) code imports it:

| Label | Meaning | Effect |
|---|---|---|
| ``imported`` | the package is imported; the import sites are added to the evidence | none |
| ``not-imported`` | declared as a direct dependency but never imported | confidence lowered one level |
| ``transitive`` | not declared directly and not imported (comes with another package) | confidence lowered |

This is import-level reachability, not call-graph analysis: an imported package may never call the vulnerable
function, and a transitive package can still be reached through the library that depends on it. That is why
unreachable-looking vulnerabilities are not dropped or downgraded in severity; they only rank lower, and the
finding says why. Ecosystems other than PyPI and npm are left unlabelled.
"""

from __future__ import annotations

import ast
import re

from .analyzers.ai_code import IMPORT_TO_DIST, JS_EXTS, JS_IMPORT, _norm
from .analyzers.base import AnalyzerContext, is_test_path
from .findings import Confidence, Finding
from .languages import js_dependencies, python_dependencies

PACKAGE_RE = re.compile(r"^(?P<name>@?[A-Za-z0-9][A-Za-z0-9._/-]*)==")
LOWER = {Confidence.HIGH: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.LOW, Confidence.LOW: Confidence.LOW}
MAX_SITES = 5


def external_imports(ctx: AnalyzerContext) -> dict[str, list[tuple[str, int]]]:
    """Normalized package name -> import sites, for non-test Python and JavaScript/TypeScript files."""
    dist_of = {k: _norm(v) for k, v in IMPORT_TO_DIST.items()}
    sites: dict[str, list[tuple[str, int]]] = {}
    for rel in ctx.python_files():
        if is_test_path(rel):
            continue
        tree = ctx.python_ast(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots = [node.module.split(".")[0]]
            else:
                continue
            for root in roots:
                for key in {_norm(root), dist_of.get(root, _norm(root))}:
                    sites.setdefault(key, []).append((rel, node.lineno))
    for rel in ctx.files_with_suffix(*JS_EXTS):
        if is_test_path(rel) or "node_modules/" in rel:
            continue
        text = ctx.read(rel) or ""
        for m in JS_IMPORT.finditer(text):
            spec = m.group(1)
            if spec.startswith((".", "/", "node:")):
                continue
            parts = spec.split("/")
            name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
            sites.setdefault(name.lower(), []).append((rel, text.count("\n", 0, m.start(1)) + 1))
    return sites


def package_of(f: Finding) -> str | None:
    m = PACKAGE_RE.match(f.evidence or "")
    return m.group("name") if m else None


def annotate(findings: list[Finding], ctx: AnalyzerContext) -> dict:
    """Label ``vuln:*`` findings in place. Returns counts per label (for audit stats)."""
    vulns = [f for f in findings if f.rule_id.startswith("vuln:") and package_of(f)]
    if not vulns:
        return {}
    imports = external_imports(ctx)
    manifests = ctx.languages.manifests
    direct = {_norm(d) for d in python_dependencies(ctx.root, manifests)}
    direct |= {d.lower() for d in js_dependencies(ctx.root, [m for m in manifests if m.endswith("package.json")])}
    counts: dict[str, int] = {}
    for f in vulns:
        name = package_of(f)
        key = _norm(name) if not name.startswith("@") else name.lower()
        hits = imports.get(key) or imports.get(name.lower()) or []
        if hits:
            f.reachability = "imported"
            where = ", ".join(f"{p}:{n}" for p, n in sorted(set(hits))[:MAX_SITES])
            f.evidence = f"{f.evidence}\nImported at: {where}"[:800]
        else:
            f.reachability = "not-imported" if key in direct else "transitive"
            f.confidence = LOWER[f.confidence]
            why = ("declared directly but not imported by the application code" if f.reachability == "not-imported"
                   else "a transitive dependency the application code does not import directly")
            f.description = (f"{f.description} Reachability: {why}; it may still be used through another package, "
                             "so verify before dismissing.").strip()
        counts[f.reachability] = counts.get(f.reachability, 0) + 1
    return counts
