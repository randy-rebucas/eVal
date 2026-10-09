"""Maintainability: complexity, oversized units, duplicated code, technical-debt markers, documentation."""

from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict

from ..findings import Category, Confidence, FindingKind, Severity
from ..languages import CODE_LANGUAGES, EXTENSIONS
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

COMPLEXITY_MEDIUM = 15
COMPLEXITY_HIGH = 30
FUNCTION_LINES = 120
FILE_LINES = 1000
DUP_WINDOW = 12  # normalized non-blank lines
DEBT_MARKER = re.compile(r"(?:#|//|/\*|\*)\s*(TODO|FIXME|HACK|XXX)\b", re.I)
_BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With, ast.AsyncWith, ast.IfExp,
             ast.comprehension, ast.Assert, ast.match_case)


def cyclomatic_complexity(func: ast.AST) -> int:
    """McCabe-style: 1 + decision points (branches, boolean operators, comprehension conditions)."""
    score = 1
    for node in ast.walk(func):
        if isinstance(node, _BRANCHES):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += len(node.values) - 1
        if isinstance(node, ast.comprehension):
            score += len(node.ifs)
    return score


def _code_files(ctx: AnalyzerContext) -> list[str]:
    return [f for f in ctx.files if EXTENSIONS.get("." + f.rsplit(".", 1)[-1].lower()) in CODE_LANGUAGES]


@register
class MaintainabilityAnalyzer(Analyzer):
    name = "maintainability"
    title = "Maintainability & technical debt"
    categories = (Category.MAINTAINABILITY,)

    def run(self, ctx: AnalyzerContext):
        findings = []
        code_files = _code_files(ctx)
        for rel in ctx.python_files():
            findings.extend(self._python(ctx, rel))
        for rel in code_files:
            n = len(ctx.lines(rel))
            if n > FILE_LINES and not is_test_path(rel):
                findings.append(self._f(ctx, "maintainability.large-file", f"Very large source file ({n} lines)",
                                        Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                        "Large files usually mix responsibilities and are hard to review and test.",
                                        "Split by responsibility into cohesive modules.", rel,
                                        evidence=f"{rel}: {n} lines"))
        findings.extend(self._duplicates(ctx, [f for f in code_files if not is_test_path(f)]))
        findings.extend(self._debt(ctx, code_files))
        findings.extend(self._docs(ctx, code_files))
        return findings

    def _f(self, ctx, rule, title, sev, conf, kind, desc, fix, rel="", line=None, evidence=None):
        return self.finding(ctx, rule=rule, title=title, category=Category.MAINTAINABILITY, severity=sev,
                            confidence=conf, kind=kind, description=desc, remediation=fix, file_path=rel, line=line,
                            evidence=evidence)

    def _python(self, ctx, rel):
        tree = ctx.python_ast(rel)
        if tree is None:
            if ctx.read(rel) is not None:
                return [self._f(ctx, "maintainability.python-syntax-error", "Python file does not parse",
                                Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                "The file is not valid Python 3 syntax, so it cannot run and was not analyzed.",
                                "Fix the syntax error (or remove dead code).", rel)]
            return []
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            cc = cyclomatic_complexity(node)
            length = (node.end_lineno or node.lineno) - node.lineno + 1
            if cc >= COMPLEXITY_MEDIUM:
                out.append(self._f(ctx, "maintainability.high-complexity",
                                   f"High cyclomatic complexity in {node.name}() ({cc})",
                                   Severity.MEDIUM if cc >= COMPLEXITY_HIGH else Severity.LOW, Confidence.HIGH,
                                   FindingKind.CONFIRMED,
                                   f"{node.name}() has {cc} independent paths (threshold {COMPLEXITY_MEDIUM}); each "
                                   "needs a test, and changes are error-prone.",
                                   "Extract cohesive helpers, replace nested conditionals with early returns or "
                                   "dispatch tables.", rel, node.lineno, evidence=f"{node.name}: complexity {cc}, "
                                   f"{length} lines"))
            elif length > FUNCTION_LINES:
                out.append(self._f(ctx, "maintainability.long-function",
                                   f"Long function {node.name}() ({length} lines)", Severity.LOW, Confidence.HIGH,
                                   FindingKind.CONFIRMED, "Long functions tend to mix concerns and hide bugs.",
                                   "Split into smaller functions with descriptive names.", rel, node.lineno,
                                   evidence=f"{node.name}: {length} lines"))
            for handler in ast.walk(node):
                if isinstance(handler, ast.ExceptHandler) and handler.type is None and all(
                        isinstance(s, ast.Pass) for s in handler.body):
                    out.append(self._f(ctx, "maintainability.swallowed-exception", "Bare except that silently "
                                       "swallows errors", Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "`except: pass` hides every error, including KeyboardInterrupt and bugs, "
                                       "making failures invisible.",
                                       "Catch specific exceptions and log or handle them.", rel, handler.lineno))
        return out

    def _duplicates(self, ctx, files):
        windows: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for rel in files[:4000]:
            lines = ctx.lines(rel)
            if len(lines) > 5000:
                continue
            norm = [(i + 1, re.sub(r"\s+", " ", ln).strip()) for i, ln in enumerate(lines)]
            norm = [(i, t) for i, t in norm if t and len(t) > 3 and not t.startswith(("import ", "from ", "#", "//",
                                                                                        "}", ")", "]"))]
            seen_in_file = set()
            for k in range(0, max(len(norm) - DUP_WINDOW + 1, 0)):
                chunk = "\n".join(t for _, t in norm[k:k + DUP_WINDOW])
                h = hashlib.sha1(chunk.encode(), usedforsecurity=False).hexdigest()
                if h in seen_in_file:
                    continue
                seen_in_file.add(h)
                windows[h].append((rel, norm[k][0]))
        reported_pairs = set()
        out = []
        for _h, locs in windows.items():
            if len(locs) < 2:
                continue
            files_involved = tuple(sorted({rel for rel, _ in locs}))
            if files_involved in reported_pairs:
                continue
            reported_pairs.add(files_involved)
            first, others = locs[0], locs[1:]
            out.append(self._f(ctx, "maintainability.duplicated-code",
                               f"Duplicated code block ({DUP_WINDOW}+ lines, {len(locs)} copies)", Severity.LOW,
                               Confidence.HIGH, FindingKind.CONFIRMED,
                               "Identical code appears in multiple places (common in AI-generated code). Fixes "
                               "applied to one copy are easily missed in the others. Other copies: "
                               + ", ".join(f"{r}:{ln}" for r, ln in others[:5]),
                               "Extract the shared logic into one function/module and reuse it.", first[0], first[1]))
            if len(out) >= 40:
                break
        return out

    def _debt(self, ctx, files):
        count, first = 0, None
        for rel in files:
            for i, ln in enumerate(ctx.lines(rel), start=1):
                if DEBT_MARKER.search(ln):
                    count += 1
                    first = first or (rel, i)
        if count >= 10 and first:
            return [self._f(ctx, "maintainability.debt-markers", f"{count} TODO/FIXME/HACK markers",
                            Severity.INFO if count < 50 else Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                            "Unresolved debt markers indicate unfinished or known-fragile code paths.",
                            "Triage markers into tracked issues; remove stale ones.", first[0], first[1],
                            evidence=f"{count} markers; first at {first[0]}:{first[1]}")]
        return []

    def _docs(self, ctx, code_files):
        if not code_files:
            return []
        readmes = [f for f in ctx.files if "/" not in f and f.lower().startswith("readme")]
        if not readmes:
            return [self._f(ctx, "maintainability.no-readme", "No README at the repository root", Severity.LOW,
                            Confidence.HIGH, FindingKind.CONFIRMED,
                            "There is no top-level README describing setup, configuration, and operation.",
                            "Add a README covering purpose, setup, configuration, testing, and deployment.")]
        text = ctx.read(readmes[0]) or ""
        if len([ln for ln in text.splitlines() if ln.strip()]) < 8:
            return [self._f(ctx, "maintainability.thin-readme", "README is minimal", Severity.INFO, Confidence.HIGH,
                            FindingKind.CONFIRMED, "The README has fewer than 8 non-blank lines.",
                            "Document setup, configuration (env vars), testing, and deployment.", readmes[0])]
        return []
