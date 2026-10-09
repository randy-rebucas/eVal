from __future__ import annotations

import json
import zipfile

import pytest

from eval_engine import cli
from eval_engine.pipeline import PipelineConfig, run_pipeline
from eval_engine.reports import render
from tests.conftest import FIXTURES


@pytest.fixture(scope="module")
def model():
    result = run_pipeline(FIXTURES / "vulnapp", PipelineConfig(analyzers=["secrets", "devops", "database"]))
    m = result.to_dict()
    m["meta"] = {"title": "t", "repository": "vulnapp"}
    return m


def test_markdown_report(model):
    md = render(model, "md")
    assert md.startswith("# t") and "| Category | Score | Risk | Findings |" in md
    assert "risk indicators" in md and "[CRITICAL]" in md
    assert "AKIAIOSFODNN7EXAMPLE" not in md


def test_markdown_escapes_table_breaking_content(model):
    m = json.loads(json.dumps(model))
    m["tools"][0]["reason"] = "a|b<script>"
    md = render(m, "md")
    assert "a\\|b&lt;script>" in md


def test_html_report_escapes(model):
    m = json.loads(json.dumps(model))
    m["findings"][0]["title"] = "<script>alert(1)</script>"
    out = render(m, "html")
    assert "<script>alert" not in out and "&lt;script&gt;" in out and "<script" not in out


def test_sarif_report(model):
    sarif = json.loads(render(model, "sarif"))
    results = sarif["runs"][0]["results"]
    assert sarif["version"] == "2.1.0" and results
    levels = {r["level"] for r in results}
    assert levels <= {"error", "warning", "note"}
    assert all(r["partialFingerprints"]["evalFingerprint/v1"] for r in results)


def test_unknown_format(model):
    with pytest.raises(ValueError):
        render(model, "pdf")


def test_cli_fail_on_threshold_and_zip_input(tmp_path, capsys):
    out = tmp_path / "r.json"
    code = cli.main([str(FIXTURES / "vulnapp"), "--format", "json", "-o", str(out), "--analyzers", "secrets",
                     "--fail-on", "high"])
    assert code == 1 and json.loads(out.read_text())["scores"]["risk"] == "Critical"
    assert cli.main([str(FIXTURES / "cleanapp"), "--analyzers", "secrets", "--fail-on", "high", "-o",
                     str(tmp_path / "c.md")]) == 0
    archive = tmp_path / "src.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.write(FIXTURES / "vulnapp" / "app.py", "proj/app.py")
    assert cli.main([str(archive), "--analyzers", "secrets", "--format", "sarif", "-o", str(tmp_path / "s.sarif"),
                     "--fail-on", "critical"]) == 1
    assert cli.main([str(tmp_path / "missing"), "--analyzers", "secrets"]) == 2
    with pytest.raises(SystemExit):
        cli.main(["x", "--format", "pdf"])
