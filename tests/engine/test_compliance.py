"""Compliance mapping: explicit rules, tool-reported CWEs, category fallback, report integration."""

from __future__ import annotations

import json

from eval_engine.compliance import map_finding, summarize
from eval_engine.pipeline import PipelineConfig, run_pipeline
from eval_engine.reports import render
from tests.conftest import FIXTURES


def test_explicit_rule_mapping():
    m = map_finding("eval:database.sql-string-formatting", "database")
    assert m == {"cwe": ["CWE-89"], "owasp": ["A03:2021"], "asvs": ["V5.3.4"], "soc2": ["CC6.1"],
                 "iso27001": ["A.8.28"]}
    assert map_finding("eval:secrets.aws-access-key", "security")["owasp"] == ["A07:2021"]
    assert map_finding("vuln:CVE-2024-1", "dependencies")["owasp"] == ["A06:2021"]
    assert map_finding("eval:api.flask-debug-enabled", "api")["cwe"] == ["CWE-489"]


def test_tool_reported_cwe_is_used():
    m = map_finding("semgrep:python.lang.security.audit.foo", "security",
                    "Untrusted input reaches eval() (CWE-95)", ["https://cwe.mitre.org/data/definitions/94.html"])
    assert m["cwe"] == ["CWE-95", "CWE-94"] and m["owasp"] == ["A03:2021"]
    assert m["soc2"] == ["CC6.1", "CC7.1"]  # category fallback


def test_category_fallback_and_unknown():
    m = map_finding("ruff:E501", "maintainability")
    assert m["cwe"] == [] and m["soc2"] == ["CC8.1"] and m["iso27001"] == ["A.8.25"]
    assert map_finding("x:y", "nonsense") == {"cwe": [], "owasp": [], "asvs": [], "soc2": [], "iso27001": []}


def test_summary_counts_by_control():
    rows = [{"rule_id": "eval:database.sql-string-formatting", "category": "database", "severity": "high"},
            {"rule_id": "eval:secrets.x", "category": "security", "severity": "critical"}]
    s = summarize(rows)
    cc61 = next(c for c in s["soc2"] if c["control"] == "CC6.1")
    assert cc61["findings"] == 2 and cc61["by_severity"] == {"high": 1, "critical": 1}
    assert cc61["title"] == "Logical access security"


def test_reports_carry_the_mapping():
    model = run_pipeline(FIXTURES / "vulnapp", PipelineConfig(analyzers=["database", "secrets"])).to_dict()
    model["meta"] = {"title": "t"}
    data = json.loads(render(model, "json"))
    assert data["compliance"]["controls"]["owasp"][0]["control"] in ("A03:2021", "A07:2021")
    assert all("compliance" in f for f in data["findings"])
    md = render(model, "md")
    assert "## Compliance mapping" in md and "**Maps to:** CWE-89 · A03:2021" in md
    assert "Compliance mapping</h2>" in render(model, "html")
    sarif = json.loads(render(model, "sarif"))
    rule = next(r for r in sarif["runs"][0]["tool"]["driver"]["rules"]
                if r["id"] == "eval:database.sql-string-formatting")
    assert {"security", "external/cwe/cwe-89", "owasp-top10-2021/a03"} <= set(rule["properties"]["tags"])
