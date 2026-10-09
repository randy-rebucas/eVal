"""Test presence, test-to-code ratio, assertion-free tests, and whether CI actually runs tests."""

from __future__ import annotations

import ast
import json
import re

from ..findings import Category, Confidence, FindingKind, Severity
from ..languages import CODE_LANGUAGES, EXTENSIONS
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

CI_TEST_COMMANDS = re.compile(
    r"\b(pytest|tox|nox|python -m unittest|npm (run )?test|npm t\b|yarn test|pnpm test|jest|vitest|mocha|"
    r"go test|cargo test|mvn (-\S+ )*test|gradle(w)? test|\./gradlew test|bundle exec rspec|rspec|phpunit|"
    r"dotnet test|make test|playwright test|cypress run)\b"
)
DEFAULT_NPM_TEST = "no test specified"


def _code_lines(ctx: AnalyzerContext, files: list[str]) -> int:
    return sum(sum(1 for ln in ctx.lines(f) if ln.strip()) for f in files)


@register
class TestingAnalyzer(Analyzer):
    name = "testing"
    title = "Testing practices"
    categories = (Category.TESTING,)

    def applicable(self, ctx: AnalyzerContext):
        if not any(ctx.languages.has(lang) for lang in CODE_LANGUAGES):
            return "no application source code detected"
        return None

    def run(self, ctx: AnalyzerContext):
        findings = []
        code_files = [f for f in ctx.files
                      if EXTENSIONS.get("." + f.rsplit(".", 1)[-1].lower()) in CODE_LANGUAGES]
        tests = [f for f in code_files if is_test_path(f)]
        source = [f for f in code_files if not is_test_path(f)]
        src_loc, test_loc = _code_lines(ctx, source), _code_lines(ctx, tests)

        def add(rule, title, sev, conf, kind, desc, fix, path="", line=None, evidence=None):
            findings.append(self.finding(ctx, rule=rule, title=title, category=Category.TESTING, severity=sev,
                                         confidence=conf, kind=kind, description=desc, remediation=fix,
                                         file_path=path, line=line, evidence=evidence))

        if not tests:
            add("testing.no-tests", "No automated tests found", Severity.HIGH, Confidence.HIGH, FindingKind.CONFIRMED,
                f"No test files were found for {src_loc} lines of source code. Regressions, including security "
                "regressions, will reach production undetected.",
                "Add unit tests for business logic and integration tests for API endpoints and data access; run "
                "them in CI.", evidence=f"0 test files; {len(source)} source files ({src_loc} non-blank lines)")
        elif src_loc >= 200:
            ratio = test_loc / max(src_loc, 1)
            evidence = f"{test_loc} test lines / {src_loc} source lines = {ratio:.2f}"
            if ratio < 0.1:
                add("testing.low-test-ratio", "Very low test-to-code ratio", Severity.MEDIUM, Confidence.MEDIUM,
                    FindingKind.POTENTIAL, "Test code is under 10% of source code size. This is a coarse proxy, "
                    "not coverage — measure line/branch coverage in CI for a real figure.",
                    "Prioritize tests for authentication, authorization, data writes, and payment flows.",
                    evidence=evidence)
            elif ratio < 0.3:
                add("testing.modest-test-ratio", "Modest test-to-code ratio", Severity.LOW, Confidence.MEDIUM,
                    FindingKind.POTENTIAL, "Test code is under 30% of source code size (a coarse proxy, not "
                    "coverage).", "Measure coverage in CI and grow tests around critical paths.", evidence=evidence)

        for pkg in ctx.files_named("package.json"):
            try:
                data = json.loads(ctx.read(pkg) or "{}")
            except json.JSONDecodeError:
                continue
            script = (data.get("scripts") or {}).get("test", "") if isinstance(data, dict) else ""
            if isinstance(script, str) and DEFAULT_NPM_TEST in script:
                add("testing.npm-default-test-script", "npm test script is the default placeholder", Severity.MEDIUM,
                    Confidence.HIGH, FindingKind.CONFIRMED,
                    "`npm test` exits with an error stub, so no JavaScript tests run.",
                    "Configure a real test runner (Vitest, Jest, node:test) in the test script.", pkg,
                    evidence=f'"test": "{script[:120]}"')

        findings.extend(self._assertionless_python_tests(ctx, [t for t in tests if t.endswith(".py")]))

        ci_files = [f for f in ctx.files if f.startswith(".github/workflows/") or f in (
            ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml")]
        if tests and ci_files and not any(CI_TEST_COMMANDS.search(ctx.read(f) or "") for f in ci_files):
            add("testing.ci-does-not-run-tests", "CI does not appear to run the test suite", Severity.MEDIUM,
                Confidence.MEDIUM, FindingKind.POTENTIAL,
                "CI configuration exists but no recognizable test command (pytest, npm test, go test, …) was found.",
                "Run the test suite on every pull request and block merges on failure.", ci_files[0])
        return findings

    def _assertionless_python_tests(self, ctx: AnalyzerContext, test_files: list[str]):
        out = []
        for rel in test_files:
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            empty = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith("test")
                and not _has_assertion(node)
            ]
            if empty:
                out.append(self.finding(
                    ctx, rule="testing.tests-without-assertions",
                    title=f"{len(empty)} test function(s) without assertions",
                    category=Category.TESTING, severity=Severity.LOW, confidence=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL,
                    description="These tests contain no assert statement, pytest.raises, or assert* call, so they "
                    "only check that code does not crash: " + ", ".join(n.name for n in empty[:10]),
                    remediation="Assert on return values, side effects, and error cases.",
                    file_path=rel, line=empty[0].lineno))
        return out


def _has_assertion(func: ast.AST) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            if name.startswith(("assert", "expect")) or name in ("raises", "fail", "approx", "verify", "check"):
                return True
        if isinstance(node, ast.With):
            for item in node.items:
                c = item.context_expr
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr in (
                        "raises", "warns", "assertRaises", "assertLogs"):
                    return True
    return False
