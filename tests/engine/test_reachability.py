"""Import reachability for dependency vulnerabilities."""

from __future__ import annotations

from eval_engine.analyzers.base import AnalyzerContext
from eval_engine.findings import Finding
from eval_engine.languages import detect
from eval_engine.reachability import annotate
from eval_engine.workspace import iter_files


def _vuln(name, ver="1.0.0", src="requirements.txt"):
    return Finding(rule_id=f"vuln:CVE-{name}", title=f"{name} {ver}", category="dependencies", severity="high",
                   confidence="high", kind="confirmed", description="Advisory.", remediation="Upgrade.",
                   file_path=src, evidence=f"{name}=={ver} pinned in {src}", fingerprint=name)


def _ctx(root):
    files = list(iter_files(root))
    return AnalyzerContext(root=root, files=files, languages=detect(root, files))


def test_labels_and_confidence(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\npyyaml==5.1\nunused-lib==1.0\n")
    (tmp_path / "app.py").write_text("import requests\nimport yaml\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("import unused_lib\n")  # test imports do not count
    (tmp_path / "package.json").write_text('{"dependencies": {"@scope/ui": "1.0.0"}}')
    (tmp_path / "web.js").write_text("import Button from '@scope/ui/button';\n")
    findings = [_vuln("requests"), _vuln("PyYAML"), _vuln("unused-lib"), _vuln("urllib3"),
                _vuln("@scope/ui", src="package-lock.json"), _vuln("left-pad", src="package-lock.json")]
    counts = annotate(findings, _ctx(tmp_path))
    by = {f.fingerprint: f for f in findings}
    assert by["requests"].reachability == "imported" and "Imported at: app.py:1" in by["requests"].evidence
    assert by["requests"].confidence == "high"
    assert by["PyYAML"].reachability == "imported"  # import yaml -> pyyaml
    assert by["unused-lib"].reachability == "not-imported" and by["unused-lib"].confidence == "medium"
    assert by["urllib3"].reachability == "transitive" and "transitive dependency" in by["urllib3"].description
    assert by["@scope/ui"].reachability == "imported" and by["left-pad"].reachability == "transitive"
    assert all(f.severity == "high" for f in findings)  # severity is never changed
    assert counts == {"imported": 3, "not-imported": 1, "transitive": 2}


def test_non_vulnerability_findings_are_untouched(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    f = Finding(rule_id="eval:secrets.x", title="t", category="security", severity="high", confidence="high",
                kind="confirmed", description="d", remediation="r", file_path="app.py", evidence="requests==1")
    assert annotate([f], _ctx(tmp_path)) == {} and f.reachability == ""
