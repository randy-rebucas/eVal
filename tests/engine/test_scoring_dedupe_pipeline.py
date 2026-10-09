from __future__ import annotations

import shutil

import pytest

from eval_engine import fingerprint
from eval_engine.analyzers.base import Analyzer
from eval_engine.dedupe import classify, family_of, merge_duplicates, validate
from eval_engine.findings import Category, Confidence, Finding, FindingKind, Severity
from eval_engine.pipeline import PipelineConfig, PreviousState, run_pipeline
from eval_engine.scoring import score
from tests.conftest import FIXTURES

ALL = {c.value for c in Category}


def mk(rule="eval:x", sev=Severity.HIGH, conf=Confidence.HIGH, kind=FindingKind.CONFIRMED, cat=Category.SECURITY,
       path="a.py", line=1, title="t", sources=("x",)):
    return Finding(rule_id=rule, title=title, category=cat, severity=sev, confidence=conf, kind=kind,
                   description="", remediation="", file_path=path, line_start=line, line_end=line,
                   sources=list(sources))


# --------------------------------------------------------------------------------------------- scoring
def test_clean_repo_scores_100_low_risk():
    card = score([], ALL)
    assert card.overall == 100.0 and card.risk == "Low"


def test_unassessed_categories_are_not_scored_as_perfect():
    card = score([], {"security"})
    assert card.categories["testing"].assessed is False and card.categories["testing"].score is None
    assert card.categories["testing"].risk == "Not assessed"
    assert score([], set()).overall is None


def test_confirmed_critical_forces_critical_risk():
    card = score([mk(sev=Severity.CRITICAL)], ALL)
    assert card.categories["security"].score == 35.0
    assert card.categories["security"].risk == "Critical" and card.risk == "Critical"
    assert "capped at 35" in card.categories["security"].ceiling_reason


def test_low_confidence_findings_never_cap():
    card = score([mk(sev=Severity.CRITICAL, conf=Confidence.LOW, kind=FindingKind.POTENTIAL)], ALL)
    assert card.categories["security"].score == pytest.approx(100 - 40 * 0.4 * 0.75)


def test_per_rule_penalty_cap_limits_noisy_rules():
    noisy = [mk(rule="ruff:F401", sev=Severity.LOW, cat=Category.MAINTAINABILITY, line=i) for i in range(1, 200)]
    card = score(noisy, ALL)
    assert card.categories["maintainability"].score == 100 - 2.0 * 3


def test_ai_observations_are_never_scored():
    card = score([mk(sev=Severity.CRITICAL, kind=FindingKind.AI_OBSERVATION)], ALL)
    assert card.overall == 100.0 and card.severity_counts["critical"] == 0


def test_overall_risk_not_hidden_by_average():
    # Security is Critical; every other category is perfect. Average would be ~84 ("Low").
    card = score([mk(sev=Severity.CRITICAL)], ALL)
    assert card.overall > 80 and card.risk == "Critical"
    # A non-critical category at High lifts the overall risk to at most one level below.
    card = score([mk(cat=Category.MAINTAINABILITY, sev=Severity.CRITICAL, conf=Confidence.MEDIUM,
                     kind=FindingKind.POTENTIAL)], ALL)
    assert card.categories["maintainability"].risk == "High" and card.risk == "Moderate"


def test_scoring_is_deterministic():
    findings = [mk(sev=s, line=i) for i, s in enumerate(Severity, start=1)]
    assert score(findings, ALL).to_dict() == score(list(reversed(findings)), ALL).to_dict()


# --------------------------------------------------------------------------------- fingerprint & dedupe
def _fp(findings, lines):
    fingerprint.compute(findings, lambda p, n: lines[p][n - 1], family_of)
    return [f.fingerprint for f in findings]


def test_fingerprint_stable_when_lines_shift():
    a = _fp([mk(line=2)], {"a.py": ["x = 1", "eval(data)"]})
    b = _fp([mk(line=5)], {"a.py": ["# new", "", "", "x = 1", "eval(data)"]})
    assert a == b


def test_fingerprint_differs_for_identical_lines_at_different_places():
    lines = {"a.py": ["eval(data)", "y", "eval(data)"]}
    fps = _fp([mk(line=1), mk(line=3)], lines)
    assert fps[0] != fps[1]


def test_cross_tool_duplicates_merge_into_one_finding():
    lines = {"a.py": ["SECRET_KEY = 'abc123def456'"]}
    a = mk(rule="bandit:B105", sev=Severity.LOW, conf=Confidence.MEDIUM, sources=("bandit",))
    b = mk(rule="eval:api.hardcoded-session-secret", sev=Severity.HIGH, conf=Confidence.HIGH, sources=("api",))
    _fp([a, b], lines)
    merged = merge_duplicates([a, b])
    assert len(merged) == 1
    assert merged[0].severity == "high" and set(merged[0].sources) == {"bandit", "api"}


def test_validation_drops_paths_outside_workspace_and_clamps_lines():
    findings = [mk(path="../../etc/passwd"), mk(path="a.py", line=999), mk(path="a.py", line=1)]
    valid, dropped = validate(findings, {"a.py"}, lambda p: 10)
    assert dropped == 1 and len(valid) == 2
    assert valid[0].line_start is None


def test_lifecycle_classification():
    cur = [mk(), mk(line=2), mk(line=3)]
    cur[0].fingerprint, cur[1].fingerprint, cur[2].fingerprint = "A", "B", "C"
    diff = classify(cur, previous={"A": {"title": "a"}, "D": {"title": "d"}}, ever_seen={"A", "B", "D"})
    assert [f.lifecycle for f in cur] == ["existing", "recurring", "new"]
    assert (diff.new, diff.existing, diff.recurring) == (1, 1, 1)
    assert [r["fingerprint"] for r in diff.resolved] == ["D"]


# ----------------------------------------------------------------------------------------------- pipeline
def test_pipeline_end_to_end_on_fixture():
    stages = []
    result = run_pipeline(FIXTURES / "vulnapp",
                          PipelineConfig(progress=lambda s, p, m: stages.append((s, p))))
    assert result.scorecard.risk == "Critical"
    assert stages[0][0] == "inspecting repository" and any(s.startswith("analyzing") for s, _ in stages)
    assert [p for _, p in stages] == sorted(p for _, p in stages)
    assert all(f.fingerprint and f.evidence is not None for f in result.findings)
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    ranks = [sev_rank[f.severity] for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)
    names = {o.name: o.status for o in result.outcomes}
    assert names["osv"] == "skipped" and names["secrets"] == "ok"
    assert result.to_dict()["scores"]["risk"] == "Critical"


def test_second_audit_marks_existing_and_resolved(tmp_path):
    repo = tmp_path / "r"
    shutil.copytree(FIXTURES / "vulnapp", repo)
    first = run_pipeline(repo, PipelineConfig(analyzers=["secrets", "devops"]))
    prev = PreviousState(previous={f.fingerprint: {"title": f.title} for f in first.findings},
                         ever_seen={f.fingerprint for f in first.findings})
    (repo / "Dockerfile").unlink()
    (repo / "app.py").write_text("\n\n" + (repo / "app.py").read_text())  # shift every line
    second = run_pipeline(repo, PipelineConfig(analyzers=["secrets", "devops"], previous_fingerprints=prev))
    lifecycles = {f.rule_id: f.lifecycle for f in second.findings}
    assert lifecycles["eval:secrets.aws-access-key"] == "existing"
    resolved_titles = {r["title"] for r in second.lifecycle.resolved}
    assert "Container runs as root" in resolved_titles


def test_crashing_analyzer_is_contained(monkeypatch):
    from eval_engine.analyzers import registry

    class Boom(Analyzer):
        name, title, categories = "boom", "Boom", (Category.TESTING,)

        def run(self, ctx):
            raise RuntimeError("secret=ghp_" + "x" * 36)

    monkeypatch.setattr(registry, "get", lambda names: [Boom()])
    result = run_pipeline(FIXTURES / "cleanapp")
    assert result.outcomes[0].status == "failed"
    assert "ghp_" not in result.outcomes[0].reason
    assert result.scorecard.categories["testing"].assessed is False  # failed analyzers don't count as coverage


def test_ai_enricher_cannot_change_scores():
    class EvilAI:
        def enrich(self, findings, languages, scorecard, ctx):
            for f in findings:
                f.severity = Severity.INFO  # attempt to tamper after scoring
            obs = mk(sev=Severity.CRITICAL, kind=FindingKind.AI_OBSERVATION, path="app.py", line=1)
            return {"summary": "x", "_observations": [obs]}

    baseline = run_pipeline(FIXTURES / "vulnapp", PipelineConfig(analyzers=["secrets"]))
    result = run_pipeline(FIXTURES / "vulnapp", PipelineConfig(analyzers=["secrets"], ai=EvilAI()))
    assert result.scorecard.to_dict() == baseline.scorecard.to_dict()
    scored = [f for f in result.findings if f.kind != "ai_observation"]
    assert [f.severity for f in scored] == [f.severity for f in baseline.findings]  # tampering discarded
    obs = [f for f in result.findings if f.kind == "ai_observation"]
    assert len(obs) == 1 and obs[0].confidence == "low"
