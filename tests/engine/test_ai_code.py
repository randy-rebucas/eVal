"""AI-generated code patterns: undeclared/lookalike/non-existent packages, stubs, placeholders, hollow tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from eval_engine.analyzers.ai_code import RegistryAnalyzer, edit_distance, lookalike_of
from eval_engine.analyzers.base import AnalyzerContext, AnalyzerError
from eval_engine.languages import detect
from eval_engine.pipeline import PipelineConfig, run_pipeline
from eval_engine.workspace import iter_files
from tests.conftest import FIXTURES


@pytest.fixture(scope="module")
def ai_findings():
    result = run_pipeline(FIXTURES / "aiapp", PipelineConfig(analyzers=["ai_code"]))
    assert result.outcomes[0].status == "ok", result.outcomes[0].reason
    return result.findings


def _by_rule(findings, rule):
    return [f for f in findings if f.rule_id == f"eval:ai-code.{rule}"]


def test_undeclared_imports_python_and_js(ai_findings):
    names = {f.title.split("'")[1]: f.file_path for f in _by_rule(ai_findings, "undeclared-import")}
    # yaml -> pyyaml mapping, local package `app`, stdlib os/json, optional ujson, node builtins and relative
    # imports are all accepted; only the undeclared packages remain.
    assert names == {"fastjsonx": "app/service.py", "express-magic-router": "web/server.js"}


def test_lookalike_packages(ai_findings):
    titles = sorted(f.title for f in _by_rule(ai_findings, "lookalike-package"))
    assert titles == ["'lodahs' looks like a misspelling of 'lodash'",
                      "'reqeusts' looks like a misspelling of 'requests'"]
    f = next(f for f in _by_rule(ai_findings, "lookalike-package") if "reqeusts" in f.title)
    assert (f.file_path, f.line_start, f.severity) == ("requirements.txt", 2, "high")


def test_stubs_and_placeholders(ai_findings):
    (stubs,) = _by_rule(ai_findings, "stub-function")
    assert stubs.title == "3 unimplemented function(s)"
    assert "refund, send_receipt, save" in stubs.description  # on_saved hook and BaseStore.get are exempt
    (comment,) = _by_rule(ai_findings, "placeholder-logic")
    assert "In a real application" in comment.description and comment.line_start == 17
    values = {f.file_path: f.line_start for f in _by_rule(ai_findings, "placeholder-value")}
    assert values == {"app/service.py": 13, "web/server.js": 8}


def test_hollow_tests(ai_findings):
    taut = {f.file_path: f.title for f in _by_rule(ai_findings, "tautological-assertion")}
    assert taut == {"tests/test_service.py": "2 assertion(s) that can never fail",
                    "web/math.test.js": "1 assertion(s) that can never fail"}
    assert [f.file_path for f in _by_rule(ai_findings, "tests-without-expect")] == ["web/server.test.js"]


@pytest.mark.parametrize("fixture", ["cleanapp", "vulnapp", "jsapp"])
def test_no_false_positives_on_other_fixtures(fixture):
    result = run_pipeline(FIXTURES / fixture, PipelineConfig(analyzers=["ai_code"]))
    assert [f.rule_id for f in result.findings if f.rule_id != "eval:ai-code.placeholder-value"] == []


@pytest.mark.parametrize("a,b,d", [("requests", "reqeusts", 1), ("lodash", "lodahs", 1), ("flask", "flask", 0),
                                   ("django", "djagno", 1), ("numpy", "pandas", 3)])
def test_edit_distance(a, b, d):
    assert edit_distance(a, b) == min(d, 3)


def test_lookalike_ignores_popular_and_short_names():
    popular = {"requests", "react", "attrs"}
    assert lookalike_of("requests", popular) is None
    assert lookalike_of("request", popular) == "requests"
    assert lookalike_of("ract", popular) is None  # too short to judge
    assert lookalike_of("Requests_", popular) is None  # normalisation: same package


# ------------------------------------------------------------------------------------------- registry
class FakeResponse:
    def __init__(self, status, data=None):
        self.status_code, self._data = status, data or {}

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, table):
        self.table, self.urls = table, []

    def get(self, url, **kw):
        self.urls.append(url)
        return self.table.get(url, FakeResponse(404))


def _ctx(root):
    files = list(iter_files(root))
    return AnalyzerContext(root=root, files=files, languages=detect(root, files))


def test_registry_flags_missing_and_brand_new_packages():
    ctx = _ctx(FIXTURES / "aiapp")
    now = datetime(2026, 10, 10, tzinfo=UTC)
    session = FakeSession({
        "https://pypi.org/pypi/flask/json": FakeResponse(200, {"releases": {"0.1": [
            {"upload_time_iso_8601": "2010-04-06T00:00:00Z"}]}}),
        "https://pypi.org/pypi/pyyaml/json": FakeResponse(200, {"releases": {}}),
        "https://registry.npmjs.org/express": FakeResponse(200, {"time": {"created": "2010-12-29T19:38:25Z"}}),
        "https://registry.npmjs.org/lodahs": FakeResponse(200, {"time": {"created": "2026-10-01T00:00:00Z"}}),
    })
    packages = [("PyPI", "flask"), ("PyPI", "reqeusts"), ("PyPI", "pyyaml"), ("npm", "express"), ("npm", "lodahs")]
    findings = RegistryAnalyzer().check(ctx, packages, session=session, now=now)
    got = {f.rule_id: f.title for f in findings}
    assert got == {"eval:ai-code.package-not-found": "Dependency 'reqeusts' does not exist on PyPI",
                   "eval:ai-code.package-very-new": "Dependency 'lodahs' was first published 9 day(s) ago"}
    assert all("source" not in u for u in session.urls)  # only names are sent


def test_registry_unreachable_is_reported_not_silent():
    import requests

    class Down:
        def get(self, *a, **kw):
            raise requests.ConnectionError("offline")

    with pytest.raises(AnalyzerError, match="could not be reached"):
        RegistryAnalyzer().check(_ctx(FIXTURES / "aiapp"), [("PyPI", "flask")], session=Down())


def test_registry_skips_private_indexes_and_offline(tmp_path, monkeypatch):
    assert "EVAL_REGISTRY_CHECK_ENABLED=0" in RegistryAnalyzer().applicable(_ctx(FIXTURES / "aiapp"))
    monkeypatch.setenv("EVAL_REGISTRY_CHECK_ENABLED", "1")
    (tmp_path / "requirements.txt").write_text("--index-url https://pypi.internal/simple\ninternal-lib==1.0\n")
    (tmp_path / "app.py").write_text("import internal_lib\n")
    assert "private package index" in RegistryAnalyzer().applicable(_ctx(tmp_path))
    result = run_pipeline(FIXTURES / "aiapp", PipelineConfig(analyzers=["registry"], offline=True))
    assert result.outcomes[0].status == "skipped" and "offline" in result.outcomes[0].reason
