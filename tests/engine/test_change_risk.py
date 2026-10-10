"""Pull-request change risk: deterministic, explained factors; optional policy gate."""

from __future__ import annotations

from types import SimpleNamespace

from eval_engine.change_risk import assess, exceeds, level_for
from eval_engine.policy import evaluate_gate, layered


def _f(sev, rule="eval:x"):
    return SimpleNamespace(severity=sev, rule_id=rule, file_path="a.py")


def test_small_tested_change_is_low_risk():
    risk = assess([("app/util.py", 20, 3), ("tests/test_util.py", 15, 0)], [])
    assert (risk.score, risk.level, risk.factors) == (0, "low", [])


def test_factors_add_up_and_are_explained():
    files = [("src/auth/login.py", 300, 20), ("src/billing/stripe.py", 200, 10), ("migrations/0042_add.py", 40, 0),
             ("requirements.txt", 2, 1), (".github/workflows/ci.yml", 5, 5), ("src/crypto/keys.py", 30, 0)]
    risk = assess(files, [_f("high"), _f("medium", "eval:ai-code.stub-function")])
    by = {}
    for f in risk.factors:
        by.setdefault(f["factor"], []).append(f)
    assert [f["points"] for f in by["size"]] == [15]  # 613 lines, 6 files
    assert sum(f["points"] for f in by["sensitive area"]) == 35  # capped
    assert by["sensitive area"][0]["detail"] == "authentication & authorization: src/auth/login.py"
    assert by["tests"][0]["points"] == 15
    assert by["introduced findings"][0] == {"factor": "introduced findings", "points": 14, "detail": "1 high, 1 medium"}
    assert by["AI-generated code patterns"][0]["points"] == 5
    assert risk.score == 15 + 35 + 15 + 14 + 5 and risk.level == "high"


def test_test_files_do_not_count_as_sensitive_or_untested():
    risk = assess([("tests/test_auth.py", 50, 0)], [])
    assert risk.factors == []


def test_levels_and_gate():
    assert [level_for(s) for s in (0, 29, 30, 59, 60, 100)] == ["low", "low", "medium", "medium", "high", "high"]
    assert exceeds("high", "medium") and not exceeds("medium", "medium") and not exceeds("high", "never")
    policy = layered([("x", "[gate]\nfail_on = 'never'\nmax_change_risk = 'medium'")])
    assert evaluate_gate(policy, [], [], change_risk={"level": "medium", "score": 40}).passed
    gate = evaluate_gate(policy, [], [], change_risk={"level": "high", "score": 70})
    assert not gate.passed and gate.reasons == ["change risk high (70) is above the maximum medium"]
    assert evaluate_gate(layered([]), [], [], change_risk={"level": "high", "score": 99}).passed  # off by default
