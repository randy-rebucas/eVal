"""Audit policies: which findings count, how severe they are, and when a gate fails.

A policy is written in TOML (``.eval.toml`` in a repository, or edited in the app for an organization or a
repository)::

    [gate]
    fail_on = "high"              # critical | high | medium | low | info | never
    max_findings = 0              # optional: also fail when more than this many gated findings remain
    max_change_risk = "medium"    # optional, pull requests: fail when the change risk is above this (low|medium|high)
    require_analyzers = ["semgrep"]   # gate fails if these did not run successfully

    [[gate.paths]]                # stricter (or looser) thresholds for some paths; the first match wins
    pattern = "src/payments/**"
    fail_on = "medium"

    [rules]
    disable = ["eval:maintainability.long-function"]   # exact rule ids or prefixes ending in "*"
    [rules.severity]
    "bandit:B101" = "low"

    [analyzers]
    disable = ["mypy"]

    [paths]
    exclude = ["vendor/**", "migrations/**"]

Policies layer: organization default ← repository override ← repository file. Later layers replace scalar
values and *extend* lists. Applying a policy is deterministic and recorded on the audit (``Policy.digest``), so a
score can always be traced back to the policy that produced it.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import tomllib
from dataclasses import dataclass, field

from .findings import SEVERITY_ORDER, SEVERITY_RANK, Finding, Severity

GATE_LEVELS = (*SEVERITY_ORDER, "never")
POLICY_FILE = ".eval.toml"
MAX_POLICY_BYTES = 64 * 1024
MAX_ENTRIES = 500


class PolicyError(ValueError):
    """The policy text is invalid; the message is safe to show to users."""


@dataclass
class PathGate:
    pattern: str
    fail_on: str


@dataclass
class Policy:
    fail_on: str = "high"
    max_findings: int | None = None
    max_change_risk: str = "never"
    require_analyzers: list[str] = field(default_factory=list)
    path_gates: list[PathGate] = field(default_factory=list)
    disable_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    disable_analyzers: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)  # which layers contributed, e.g. ["organization", "file"]

    # ------------------------------------------------------------------ serialization
    def to_dict(self) -> dict:
        return {
            "gate": {"fail_on": self.fail_on, "max_findings": self.max_findings,
                     "max_change_risk": self.max_change_risk,
                     "require_analyzers": self.require_analyzers,
                     "paths": [{"pattern": p.pattern, "fail_on": p.fail_on} for p in self.path_gates]},
            "rules": {"disable": self.disable_rules, "severity": self.severity_overrides},
            "analyzers": {"disable": self.disable_analyzers},
            "paths": {"exclude": self.exclude_paths},
            "sources": self.sources,
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> Policy:
        """Rebuild a stored effective policy (the output of ``to_dict``)."""
        policy = cls()
        if data:
            policy = merge(policy, parse_dict(data))
            policy.sources = list(data.get("sources") or [])
        return policy

    @property
    def digest(self) -> str:
        body = {k: v for k, v in self.to_dict().items() if k != "sources"}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]

    @property
    def is_default(self) -> bool:
        return self.digest == Policy().digest

    # ------------------------------------------------------------------ matching
    def rule_disabled(self, rule_id: str) -> bool:
        return any(_rule_match(p, rule_id) for p in self.disable_rules)

    def severity_for(self, rule_id: str) -> str | None:
        exact = self.severity_overrides.get(rule_id)
        if exact:
            return exact
        best = None
        for pattern, sev in self.severity_overrides.items():
            if pattern.endswith("*") and rule_id.startswith(pattern[:-1]) and (best is None or len(pattern) > best[0]):
                best = (len(pattern), sev)
        return best[1] if best else None

    def path_excluded(self, path: str) -> bool:
        return bool(path) and any(path_match(p, path) for p in self.exclude_paths)

    def threshold_for(self, path: str) -> str:
        for gate in self.path_gates:
            if path and path_match(gate.pattern, path):
                return gate.fail_on
        return self.fail_on


def _rule_match(pattern: str, rule_id: str) -> bool:
    return rule_id.startswith(pattern[:-1]) if pattern.endswith("*") else rule_id == pattern


def path_match(pattern: str, path: str) -> bool:
    """Glob match where ``**`` spans directories and a trailing ``/**`` also matches the directory's files."""
    pattern = pattern.strip().lstrip("./")
    if pattern.endswith("/**") and path.startswith(pattern[:-3] + "/"):
        return True
    if fnmatch.fnmatchcase(path, pattern):
        return True
    if "**/" in pattern:
        return fnmatch.fnmatchcase(path, pattern.replace("**/", "")) or fnmatch.fnmatchcase(path, pattern)
    return False


# ---------------------------------------------------------------------------------------------- parsing
def _level(value, where: str) -> str:
    if not isinstance(value, str) or value.lower() not in GATE_LEVELS:
        raise PolicyError(f"{where} must be one of: {', '.join(GATE_LEVELS)}.")
    return value.lower()


def _str_list(value, where: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise PolicyError(f"{where} must be a list of non-empty strings.")
    if len(value) > MAX_ENTRIES:
        raise PolicyError(f"{where} has more than {MAX_ENTRIES} entries.")
    return [v.strip()[:300] for v in value]


def _table(data: dict, key: str) -> dict:
    value = data.get(key) or {}
    if not isinstance(value, dict):
        raise PolicyError(f"[{key}] must be a table.")
    return value


KNOWN = {"gate": {"fail_on", "max_findings", "max_change_risk", "require_analyzers", "paths"},
         "rules": {"disable", "severity"}, "analyzers": {"disable"}, "paths": {"exclude"}, "sources": None}


def parse_dict(data: dict) -> Policy:
    """Validate a policy given as a dict. Unknown keys are rejected so typos do not silently weaken a gate."""
    if not isinstance(data, dict):
        raise PolicyError("A policy must be a table.")
    for key, sub in data.items():
        if key not in KNOWN:
            raise PolicyError(f"Unknown policy section [{key}].")
        if KNOWN[key] is not None and isinstance(sub, dict):
            unknown = set(sub) - KNOWN[key]
            if unknown:
                raise PolicyError(f"Unknown key in [{key}]: {', '.join(sorted(unknown))}.")
    gate, rules = _table(data, "gate"), _table(data, "rules")
    policy = Policy(sources=[])
    if "fail_on" in gate:
        policy.fail_on = _level(gate["fail_on"], "gate.fail_on")
    if gate.get("max_findings") is not None:
        mf = gate["max_findings"]
        if not isinstance(mf, int) or isinstance(mf, bool) or mf < 0:
            raise PolicyError("gate.max_findings must be a non-negative integer.")
        policy.max_findings = mf
    if "max_change_risk" in gate:
        mcr = gate["max_change_risk"]
        if not isinstance(mcr, str) or mcr.lower() not in ("low", "medium", "high", "never"):
            raise PolicyError("gate.max_change_risk must be one of: low, medium, high, never.")
        policy.max_change_risk = mcr.lower()
    policy.require_analyzers = _str_list(gate.get("require_analyzers"), "gate.require_analyzers")
    paths = gate.get("paths") or []
    if not isinstance(paths, list) or len(paths) > MAX_ENTRIES:
        raise PolicyError("[[gate.paths]] must be a list of tables.")
    for i, item in enumerate(paths):
        if not isinstance(item, dict) or not isinstance(item.get("pattern"), str) or not item["pattern"].strip():
            raise PolicyError(f"gate.paths[{i}] needs a pattern.")
        if set(item) - {"pattern", "fail_on"}:
            raise PolicyError(f"gate.paths[{i}] accepts only pattern and fail_on.")
        policy.path_gates.append(PathGate(item["pattern"].strip()[:300],
                                          _level(item.get("fail_on", "high"), f"gate.paths[{i}].fail_on")))
    policy.disable_rules = _str_list(rules.get("disable"), "rules.disable")
    overrides = rules.get("severity") or {}
    if not isinstance(overrides, dict) or len(overrides) > MAX_ENTRIES:
        raise PolicyError("[rules.severity] must map rule ids to severities.")
    for rule, sev in overrides.items():
        if not isinstance(sev, str) or sev.lower() not in SEVERITY_ORDER:
            raise PolicyError(f"rules.severity.{rule} must be one of: {', '.join(SEVERITY_ORDER)}.")
        policy.severity_overrides[str(rule)[:300]] = sev.lower()
    policy.disable_analyzers = _str_list(_table(data, "analyzers").get("disable"), "analyzers.disable")
    policy.exclude_paths = _str_list(_table(data, "paths").get("exclude"), "paths.exclude")
    return policy


def parse_toml(text: str) -> Policy:
    if len(text.encode("utf-8", "replace")) > MAX_POLICY_BYTES:
        raise PolicyError("The policy is larger than 64 KB.")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"Invalid TOML: {exc}") from None
    return parse_dict(data)


def _explicit(text_or_dict) -> dict:
    """The keys a layer sets explicitly (so defaults of one layer don't override the layer below)."""
    data = tomllib.loads(text_or_dict) if isinstance(text_or_dict, str) else text_or_dict
    return data or {}


def merge(base: Policy, top: Policy, top_raw: dict | None = None) -> Policy:
    """``top`` over ``base``. Scalars from ``top`` win only when ``top_raw`` sets them (or no raw is given);
    lists extend; severity overrides merge."""
    raw_gate = (top_raw or {}).get("gate", {}) if top_raw is not None else None
    return Policy(
        fail_on=top.fail_on if raw_gate is None or "fail_on" in raw_gate else base.fail_on,
        max_findings=top.max_findings if top.max_findings is not None else base.max_findings,
        max_change_risk=top.max_change_risk if raw_gate is None or "max_change_risk" in raw_gate
        else base.max_change_risk,
        require_analyzers=_union(base.require_analyzers, top.require_analyzers),
        path_gates=[*top.path_gates, *base.path_gates],  # the more specific layer is matched first
        disable_rules=_union(base.disable_rules, top.disable_rules),
        severity_overrides={**base.severity_overrides, **top.severity_overrides},
        disable_analyzers=_union(base.disable_analyzers, top.disable_analyzers),
        exclude_paths=_union(base.exclude_paths, top.exclude_paths),
        sources=list(base.sources),
    )


def _union(a: list[str], b: list[str]) -> list[str]:
    return list(dict.fromkeys([*a, *b]))


def layered(layers: list[tuple[str, str]]) -> Policy:
    """Build the effective policy from ``[(source name, toml text), ...]``, lowest precedence first.
    Empty texts are skipped. Raises PolicyError naming the layer that is invalid."""
    policy = Policy()
    for name, text in layers:
        if not (text or "").strip():
            continue
        try:
            top = parse_toml(text)
            policy = merge(policy, top, _explicit(text))
        except PolicyError as exc:
            raise PolicyError(f"{name} policy: {exc}") from None
        policy.sources.append(name)
    return policy


# --------------------------------------------------------------------------------------------- applying
@dataclass
class PolicyEffect:
    excluded: int = 0
    disabled: int = 0
    overridden: int = 0

    def to_dict(self) -> dict:
        return {"excluded": self.excluded, "disabled": self.disabled, "overridden": self.overridden}


def apply(policy: Policy, findings: list[Finding]) -> tuple[list[Finding], PolicyEffect]:
    """Drop excluded/disabled findings and apply severity overrides (before scoring)."""
    effect = PolicyEffect()
    kept = []
    for f in findings:
        if policy.path_excluded(f.file_path):
            effect.excluded += 1
            continue
        if policy.rule_disabled(f.rule_id):
            effect.disabled += 1
            continue
        sev = policy.severity_for(f.rule_id)
        if sev and sev != str(f.severity):
            f.evidence = (f.evidence + f"\n[policy: severity {f.severity} → {sev}]").strip()
            f.severity = Severity(sev)
            effect.overridden += 1
        kept.append(f)
    return kept, effect


# ------------------------------------------------------------------------------------------------ gate
@dataclass
class GateResult:
    passed: bool
    blocking: list = field(default_factory=list)  # the gated findings at/above their path's threshold
    reasons: list[str] = field(default_factory=list)
    fail_on: str = "high"

    def to_dict(self) -> dict:
        return {"passed": self.passed, "reasons": self.reasons, "fail_on": self.fail_on,
                "blocking": len(self.blocking)}


def _at_or_above(severity: str, threshold: str) -> bool:
    return threshold != "never" and SEVERITY_RANK[Severity(severity)] >= SEVERITY_RANK[Severity(threshold)]


def evaluate_gate(policy: Policy, findings: list, tool_status: list[dict],
                  change_risk: dict | None = None) -> GateResult:
    """``findings`` are the candidates (e.g. findings a PR introduced); each needs ``severity`` and ``file_path``.
    ``tool_status`` is the audit's analyzer outcomes (``{"name", "status"}``); ``change_risk`` a pull request's
    ``eval_engine.change_risk.ChangeRisk.to_dict()``."""
    blocking = [f for f in findings if _at_or_above(str(f.severity), policy.threshold_for(f.file_path))]
    reasons = []
    if blocking:
        reasons.append(f"{len(blocking)} finding(s) at or above the gate threshold")
    if policy.max_findings is not None and len(findings) > policy.max_findings:
        reasons.append(f"{len(findings)} finding(s) exceed the maximum of {policy.max_findings}")
    ok = {t["name"] for t in tool_status if t.get("status") == "ok"}
    missing = [a for a in policy.require_analyzers if a not in ok]
    if missing:
        reasons.append(f"required analyzer(s) did not run: {', '.join(missing)}")
    if change_risk and policy.max_change_risk != "never":
        from .change_risk import exceeds

        if exceeds(change_risk.get("level", "low"), policy.max_change_risk):
            reasons.append(f"change risk {change_risk['level']} ({change_risk.get('score')}) is above the maximum "
                           f"{policy.max_change_risk}")
    return GateResult(passed=not reasons, blocking=blocking, reasons=reasons, fail_on=policy.fail_on)
