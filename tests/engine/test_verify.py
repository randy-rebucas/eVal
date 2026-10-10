"""Patch verification: re-audit the patched tree and compare findings in the changed files."""

from __future__ import annotations

import shutil

import pytest

from eval_engine.findings import Finding
from eval_engine.verify import BaselineFinding, apply_files, compare, select_analyzers, verdict_for, verify_patch
from tests.conftest import FIXTURES


def _after(rule, path, fp, line=1):
    return Finding(rule_id=rule, title=rule, category="security", severity="high", confidence="high",
                   kind="confirmed", description="", remediation="", file_path=path, line_start=line,
                   fingerprint=fp)


def test_compare_resolved_still_present_and_introduced():
    a = BaselineFinding(fingerprint="fa", rule_id="r1", file_path="app.py", id="A")
    b = BaselineFinding(fingerprint="fb", rule_id="r2", file_path="app.py", id="B")
    other = BaselineFinding(fingerprint="fo", rule_id="r9", file_path="untouched.py", id="O")
    after = [
        _after("r2", "app.py", "fb-rewritten"),  # B's line changed but the rule still fires: not resolved
        _after("r3", "app.py", "new"),  # introduced
        _after("r9", "untouched.py", "fo2"),  # outside the changed files: ignored
    ]
    diff = compare([a, b], [a, b, other], after, {"app.py"})
    assert diff["resolved"] == ["A"] and diff["still_present"] == ["B"]
    assert [i["rule_id"] for i in diff["introduced"]] == ["r3"]


def test_compare_counts_duplicates_of_one_rule():
    base = [BaselineFinding(fingerprint=f"f{i}", rule_id="r", file_path="x.py", id=str(i)) for i in range(2)]
    # Two before, two after with new fingerprints (lines shifted and rewritten): nothing resolved, nothing new.
    diff = compare(base[:1], base, [_after("r", "x.py", "g0"), _after("r", "x.py", "g1")], {"x.py"})
    assert diff == {"resolved": [], "still_present": ["0"], "introduced": []}


@pytest.mark.parametrize("args,expected", [
    (([1], [], [], []), "passed"),
    (([1], [2], [], []), "partial"),
    (([1], [], [{"x": 1}], []), "regressed"),
    (([1], [], [], [{"name": "ruff"}]), "incomplete"),
])
def test_verdicts(args, expected):
    assert verdict_for(*args) == expected


def test_select_analyzers_uses_only_ok_tools_and_skips_network_unless_relevant():
    status = [{"name": "ruff", "status": "ok"}, {"name": "osv", "status": "ok"},
              {"name": "semgrep", "status": "skipped"}, {"name": "trivy", "status": "ok"}]
    base = [BaselineFinding(fingerprint="f", rule_id="r", file_path="requirements.txt", sources=["osv"])]
    assert select_analyzers(status, base, {"app.py"}, skip={"osv", "trivy"}) == ["ruff"]
    assert select_analyzers(status, base, {"requirements.txt"}, skip={"osv", "trivy"}) == ["osv", "ruff"]


def test_apply_files_refuses_paths_outside_the_tree(tmp_path):
    with pytest.raises(Exception):
        apply_files(tmp_path, {"../escape.py": "x"})
    apply_files(tmp_path, {"pkg/new.py": "print(1)\n"})
    assert (tmp_path / "pkg" / "new.py").read_text() == "print(1)\n"


def test_verify_patch_end_to_end(tmp_path):
    from eval_engine.pipeline import PipelineConfig, run_pipeline

    root = tmp_path / "src"
    shutil.copytree(FIXTURES / "vulnapp", root)
    original = run_pipeline(root, PipelineConfig(analyzers=["database", "secrets"]))
    base = [BaselineFinding(fingerprint=f.fingerprint, rule_id=f.rule_id, file_path=f.file_path, id=f.fingerprint,
                            sources=f.sources) for f in original.findings]
    sql = next(b for b in base if b.rule_id == "eval:database.sql-string-formatting")
    text = (root / sql.file_path).read_text()
    patched = text.replace("conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
                           "conn.execute(\"SELECT * FROM users WHERE name = ?\", (name,))")
    assert patched != text
    v = verify_patch(root, {sql.file_path: patched}, [sql], base, ["database", "secrets"])
    assert v.verdict == "passed" and v.resolved == [sql.id]
