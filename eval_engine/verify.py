"""Verify a proposed patch by re-auditing the patched tree.

A fix is only as good as the evidence that it works. Given the audited source tree, the new content of the files a
patch changes, and the findings of the original audit, this re-runs the analyzers on the patched tree and compares
the findings *in the changed files*:

* a **target** finding is *resolved* when its fingerprint is gone and the number of findings of the same rule in the
  same file went down (a rule that still fires on a rewritten line keeps the count up, so it is *still present*);
* a finding is *introduced* when its (file, rule) count went up and its fingerprint was not in the original audit.

Only analyzers that ran successfully in the original audit are used, so a tool missing on this worker cannot make a
patch look clean; analyzers that fail during verification are reported and make the verdict ``incomplete``.
Repository code is never executed: verification is the same static pipeline as an audit.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .pipeline import PipelineConfig, run_pipeline
from .workspace import Limits, safe_join, validate_relative_path

VERDICTS = ("passed", "partial", "regressed", "incomplete")


@dataclass
class BaselineFinding:
    fingerprint: str
    rule_id: str
    file_path: str
    title: str = ""
    severity: str = ""
    line_start: int | None = None
    id: str = ""  # opaque caller id (e.g. database id); targets carry it back in the result
    sources: list[str] = field(default_factory=list)  # analyzers that reported it


@dataclass
class Verification:
    verdict: str
    resolved: list[str] = field(default_factory=list)  # target ids
    still_present: list[str] = field(default_factory=list)  # target ids
    introduced: list[dict] = field(default_factory=list)  # {rule_id, title, severity, file_path, line_start}
    analyzers: list[str] = field(default_factory=list)
    incomplete: list[dict] = field(default_factory=list)  # {name, reason}
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "resolved": self.resolved,
            "still_present": self.still_present,
            "introduced": self.introduced,
            "analyzers": self.analyzers,
            "incomplete": self.incomplete,
            "duration_seconds": self.duration_seconds,
        }


def apply_files(root: Path, files: dict[str, str]) -> None:
    """Overwrite repository-relative ``files`` under ``root`` (paths validated, never outside the tree)."""
    for rel, content in files.items():
        validate_relative_path(rel)
        target = safe_join(root, rel)
        if target.is_symlink():
            raise ValueError(f"{rel} is a symbolic link")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="")


def select_analyzers(tool_status: list[dict], baseline: list[BaselineFinding], changed: set[str],
                     skip: set[str] | None = None) -> list[str]:
    """Analyzers worth re-running: those that ran ``ok`` in the original audit, minus ``skip`` (e.g. network-bound
    dependency lookups a code patch cannot affect) unless they reported a finding in a changed file."""
    ok = {t["name"] for t in tool_status if t.get("status") == "ok"}
    relevant = {s for f in baseline if f.file_path in changed for s in f.sources}
    skip = (skip or set()) - relevant
    return sorted(ok - skip)


def compare(targets: list[BaselineFinding], baseline: list[BaselineFinding], after: list, changed: set[str]) -> dict:
    """Compare original findings with re-audit findings (``eval_engine.findings.Finding``) in ``changed`` files."""
    before_counts = Counter((f.file_path, f.rule_id) for f in baseline if f.file_path in changed)
    after_in_scope = [f for f in after if f.file_path in changed]
    after_counts = Counter((f.file_path, f.rule_id) for f in after_in_scope)
    after_fps = {f.fingerprint for f in after}
    baseline_fps = {f.fingerprint for f in baseline}

    resolved, still = [], []
    for t in targets:
        key = (t.file_path, t.rule_id)
        if t.fingerprint not in after_fps and after_counts[key] < before_counts[key]:
            resolved.append(t.id)
        else:
            still.append(t.id)

    introduced, budget = [], {k: after_counts[k] - before_counts[k] for k in after_counts}
    for f in sorted(after_in_scope, key=lambda f: (f.file_path, f.line_start or 0)):
        key = (f.file_path, f.rule_id)
        if f.fingerprint in baseline_fps or budget.get(key, 0) <= 0:
            continue
        budget[key] -= 1
        introduced.append({"rule_id": f.rule_id, "title": f.title, "severity": str(f.severity),
                           "file_path": f.file_path, "line_start": f.line_start})
    return {"resolved": resolved, "still_present": still, "introduced": introduced}


def verdict_for(resolved: list, still: list, introduced: list, incomplete: list) -> str:
    if introduced:
        return "regressed"
    if incomplete:
        return "incomplete"
    return "passed" if not still else "partial"


def verify_patch(root: Path, files: dict[str, str], targets: list[BaselineFinding], baseline: list[BaselineFinding],
                 analyzers: list[str], *, limits: Limits | None = None, tool_timeout: int = 300,
                 offline: bool = False, policy=None) -> Verification:
    """Apply ``files`` to the source tree at ``root`` and re-audit it. ``root`` is modified in place."""
    apply_files(root, files)
    if not analyzers:
        return Verification(verdict="incomplete", incomplete=[{"name": "*", "reason": "no analyzer to re-run"}],
                            still_present=[t.id for t in targets])
    result = run_pipeline(root, PipelineConfig(analyzers=analyzers, limits=limits or Limits(),
                                               tool_timeout=tool_timeout, offline=offline, policy=policy))
    incomplete = [{"name": o.name, "reason": o.reason or o.status} for o in result.outcomes if o.status != "ok"]
    diff = compare(targets, baseline, result.findings, set(files))
    return Verification(
        verdict=verdict_for(diff["resolved"], diff["still_present"], diff["introduced"], incomplete),
        analyzers=analyzers,
        incomplete=incomplete,
        duration_seconds=result.stats.get("duration_seconds", 0.0),
        **diff,
    )
