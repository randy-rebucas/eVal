"""Finding validation, cross-tool deduplication, and audit-to-audit lifecycle classification."""

from __future__ import annotations

from dataclasses import dataclass, field

from .findings import SEVERITY_RANK, Confidence, Finding

# Equivalent rules from different tools collapse into one finding (and share a fingerprint key).
RULE_FAMILIES: dict[str, str] = {
    "bandit:B105": "hardcoded-secret",
    "bandit:B106": "hardcoded-secret",
    "bandit:B107": "hardcoded-secret",
    "eval:secrets.hardcoded-credential": "hardcoded-secret",
    "eval:api.hardcoded-session-secret": "hardcoded-secret",
    "eval:api.tls-verify-disabled": "tls-verify-disabled",
    "ruff:S105": "hardcoded-secret",
    "ruff:S106": "hardcoded-secret",
    "ruff:S107": "hardcoded-secret",
    "bandit:B602": "shell-injection",
    "bandit:B605": "shell-injection",
    "ruff:S602": "shell-injection",
    "ruff:S605": "shell-injection",
    "bandit:B608": "sql-injection",
    "ruff:S608": "sql-injection",
    "eval:database.sql-string-formatting": "sql-injection",
    "eval:taint.sql-injection": "sql-injection",
    "eval:taint.command-injection": "shell-injection",
    "eval:taint.code-injection": "eval-use",
    "bandit:B201": "flask-debug",
    "ruff:S201": "flask-debug",
    "eval:api.flask-debug-enabled": "flask-debug",
    "bandit:B301": "pickle",
    "ruff:S301": "pickle",
    "bandit:B506": "yaml-load",
    "ruff:S506": "yaml-load",
    "bandit:B501": "tls-verify-disabled",
    "ruff:S501": "tls-verify-disabled",
    "bandit:B307": "eval-use",
    "ruff:S307": "eval-use",
    "ruff:E722": "bare-except",
    "eval:maintainability.swallowed-exception": "bare-except",
    "bandit:B110": "bare-except",
    "bandit:B113": "request-without-timeout",
    "ruff:S113": "request-without-timeout",
    "eval:performance.http-without-timeout": "request-without-timeout",
}
_CONF_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def family_of(rule_id: str) -> str | None:
    if rule_id in RULE_FAMILIES:
        return RULE_FAMILIES[rule_id]
    if rule_id.startswith("semgrep:"):
        lowered = rule_id.lower()
        for needle, fam in (("sql", "sql-injection"), ("subprocess-shell", "shell-injection"),
                            ("hardcoded", "hardcoded-secret"), ("debug", "flask-debug")):
            if needle in lowered:
                return fam
    return None


def normalize_path(path: str) -> str:
    """Strip leading ``./`` segments only. (``lstrip("./")`` would also eat the dot of ``.github/`` or ``.env``.)"""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def validate(findings: list[Finding], existing_files: set[str], line_counts) -> tuple[list[Finding], int]:
    """Drop findings that point outside the workspace; clamp invalid line numbers. Returns (valid, dropped)."""
    valid: list[Finding] = []
    dropped = 0
    for f in findings:
        if f.file_path:
            path = normalize_path(f.file_path)
            if path not in existing_files:
                dropped += 1
                continue
            f.file_path = path
            n = line_counts(path)
            if f.line_start is not None and not (1 <= f.line_start <= max(n, 1)):
                f.line_start = f.line_end = None
            if f.line_end is not None and f.line_start is not None and f.line_end < f.line_start:
                f.line_end = f.line_start
        if not f.title.strip():
            dropped += 1
            continue
        valid.append(f)
    return valid, dropped


def merge_duplicates(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same fingerprint (same family/rule, location, code line)."""
    merged: dict[str, Finding] = {}
    for f in findings:
        current = merged.get(f.fingerprint)
        if current is None:
            merged[f.fingerprint] = f
            continue
        if SEVERITY_RANK[f.severity] > SEVERITY_RANK[current.severity]:
            current.severity = f.severity
        if _CONF_RANK[f.confidence] > _CONF_RANK[current.confidence]:
            current.confidence = f.confidence
            current.kind = f.kind
        if f.rule_id.startswith("eval:taint.") and not current.rule_id.startswith("eval:taint."):
            # A traced data flow is stronger evidence than a pattern match on the same line: keep its trace.
            current.description, current.evidence, current.kind = f.description, f.evidence, f.kind
            current.confidence = f.confidence
        for src in f.sources:
            if src not in current.sources:
                current.sources.append(src)
        for ref in f.references:
            if ref not in current.references:
                current.references.append(ref)
        if not current.evidence and f.evidence:
            current.evidence = f.evidence
    return list(merged.values())


@dataclass
class LifecycleDiff:
    new: int = 0
    existing: int = 0
    recurring: int = 0
    resolved: list[dict] = field(default_factory=list)


def classify(findings: list[Finding], previous: dict[str, dict] | None, ever_seen: set[str] | None) -> LifecycleDiff:
    """Label each finding new/existing/recurring and list fingerprints resolved since the previous audit.

    * existing  – present in the previous successful audit
    * recurring – absent from the previous audit but seen in an earlier one (a regression)
    * new       – never seen before for this repository
    * resolved  – present in the previous audit, absent now
    """
    diff = LifecycleDiff()
    previous = previous or {}
    ever_seen = ever_seen or set()
    current = set()
    for f in findings:
        current.add(f.fingerprint)
        if f.fingerprint in previous:
            f.lifecycle = "existing"
            diff.existing += 1
        elif f.fingerprint in ever_seen:
            f.lifecycle = "recurring"
            diff.recurring += 1
        else:
            f.lifecycle = "new"
            diff.new += 1
    for fp, meta in previous.items():
        if fp not in current:
            diff.resolved.append({"fingerprint": fp, **meta})
    return diff
