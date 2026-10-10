"""Audit policies: parsing, layering, applying to findings, gates, and the CLI."""

from __future__ import annotations

import shutil

import pytest

from eval_engine.cli import main
from eval_engine.findings import Finding
from eval_engine.pipeline import PipelineConfig, run_pipeline
from eval_engine.policy import Policy, PolicyError, apply, evaluate_gate, layered, parse_toml, path_match
from tests.conftest import FIXTURES


def _f(rule="eval:x", sev="high", path="app.py"):
    return Finding(rule_id=rule, title=rule, category="security", severity=sev, confidence="high", kind="confirmed",
                   description="", remediation="", file_path=path, line_start=1)


def test_defaults_gate_on_high():
    p = Policy()
    assert p.is_default and p.fail_on == "high"
    assert not evaluate_gate(p, [_f(sev="high")], []).passed
    assert evaluate_gate(p, [_f(sev="medium")], []).passed


@pytest.mark.parametrize("text,msg", [
    ("[gate]\nfail_on = 'severe'", "gate.fail_on"),
    ("[gaet]\nfail_on = 'high'", "Unknown policy section"),
    ("[gate]\nfailon = 'high'", r"Unknown key in \[gate\]: failon"),
    ("[rules.severity]\n'bandit:B101' = 'tiny'", "rules.severity"),
    ("[gate]\nmax_findings = -1", "max_findings"),
    ("[[gate.paths]]\nfail_on = 'low'", "needs a pattern"),
    ("not toml = = ", "Invalid TOML"),
])
def test_invalid_policies_are_rejected(text, msg):
    with pytest.raises(PolicyError, match=msg):
        parse_toml(text)


def test_layering_scalars_override_lists_extend():
    org = "[gate]\nfail_on = 'critical'\n[paths]\nexclude = ['vendor/**']"
    repo = "[paths]\nexclude = ['migrations/**']\n[rules]\ndisable = ['eval:maintainability.*']"
    file = "[gate]\nfail_on = 'medium'\n[[gate.paths]]\npattern = 'src/pay/**'\nfail_on = 'low'"
    p = layered([("organization", org), ("repository", repo), ("file", file)])
    assert p.sources == ["organization", "repository", "file"]
    assert p.fail_on == "medium" and p.exclude_paths == ["vendor/**", "migrations/**"]
    # A layer that does not mention fail_on keeps the lower layer's value.
    assert layered([("organization", org), ("repository", repo)]).fail_on == "critical"
    assert p.threshold_for("src/pay/card.py") == "low" and p.threshold_for("src/other.py") == "medium"
    assert p.rule_disabled("eval:maintainability.long-function") and not p.rule_disabled("eval:secrets.aws")
    with pytest.raises(PolicyError, match="repository policy"):
        layered([("repository", "[gate]\nfail_on = 1")])


def test_policy_roundtrip_and_digest():
    p = layered([("organization", "[gate]\nfail_on = 'low'\n[rules.severity]\n'bandit:*' = 'info'")])
    again = Policy.from_dict(p.to_dict())
    assert again.digest == p.digest and again.sources == ["organization"] and not again.is_default
    assert again.severity_for("bandit:B101") == "info"


@pytest.mark.parametrize("pattern,path,ok", [
    ("vendor/**", "vendor/a/b.py", True),
    ("vendor/**", "src/vendor/a.py", False),
    ("**/migrations/*.py", "app/migrations/0001.py", True),
    ("**/migrations/*.py", "migrations/0001.py", True),
    ("*.min.js", "static/app.min.js", True),
    ("src/*.py", "src/a/b.py", True),  # fnmatch's * crosses "/" (documented: prefer dir/** for subtrees)
])
def test_path_match(pattern, path, ok):
    assert path_match(pattern, path) is ok


def test_apply_excludes_disables_and_overrides():
    p = layered([("x", "[paths]\nexclude=['vendor/**']\n[rules]\ndisable=['eval:a']\n"
                       "[rules.severity]\n'eval:b' = 'low'")])
    kept, effect = apply(p, [_f("eval:a"), _f("eval:b"), _f("eval:c", path="vendor/x.py"), _f("eval:d")])
    assert [f.rule_id for f in kept] == ["eval:b", "eval:d"]
    assert kept[0].severity == "low" and "policy: severity high → low" in kept[0].evidence
    assert effect.to_dict() == {"excluded": 1, "disabled": 1, "overridden": 1}


def test_gate_max_findings_and_required_analyzers():
    p = layered([("x", "[gate]\nfail_on='never'\nmax_findings=1\nrequire_analyzers=['semgrep']")])
    g = evaluate_gate(p, [_f(sev="low"), _f(sev="low")], [{"name": "semgrep", "status": "skipped"}])
    assert not g.passed and len(g.reasons) == 2 and "semgrep" in g.reasons[1]
    assert evaluate_gate(p, [_f(sev="critical")], [{"name": "semgrep", "status": "ok"}]).passed


def test_pipeline_applies_policy(tmp_path):
    root = tmp_path / "src"
    shutil.copytree(FIXTURES / "vulnapp", root)
    p = layered([("x", "[rules]\ndisable=['eval:secrets.*']\n[analyzers]\ndisable=['performance']")])
    result = run_pipeline(root, PipelineConfig(analyzers=["secrets", "database", "performance"], policy=p))
    assert not any(f.rule_id.startswith("eval:secrets") for f in result.findings)
    assert [o.name for o in result.outcomes] == ["database", "secrets"]
    assert result.stats["policy"]["disabled"] > 0 and result.stats["policy"]["digest"] == p.digest


def test_cli_reads_repo_policy_and_gates_with_it(tmp_path, capsys):
    root = tmp_path / "src"
    shutil.copytree(FIXTURES / "vulnapp", root)
    args = [str(root), "--analyzers", "secrets,database", "--format", "json", "-o", str(tmp_path / "r.json")]
    assert main([*args, "--fail-on", "policy"]) == 1
    (root / ".eval.toml").write_text("[gate]\nfail_on = 'never'\n")
    assert main([*args, "--fail-on", "policy"]) == 0
    assert main([*args, "--fail-on", "policy", "--no-policy"]) == 1
    (root / ".eval.toml").write_text("[gate]\nfail_on = 'sometimes'\n")
    assert main([*args, "--fail-on", "policy"]) == 2
    assert "gate.fail_on" in capsys.readouterr().err
