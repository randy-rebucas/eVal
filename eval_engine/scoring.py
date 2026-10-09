"""Deterministic, documented scoring. See docs/SCORING.md — keep the two in sync.

Scores are *risk indicators*, not guarantees of production readiness.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .findings import Category, Confidence, Finding, FindingKind, Severity

SCORING_VERSION = "1"

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 6.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}
CONFIDENCE_FACTOR = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.7, Confidence.LOW: 0.4}
KIND_FACTOR = {
    FindingKind.CONFIRMED: 1.0,
    FindingKind.POTENTIAL: 0.75,
    FindingKind.ESTIMATE: 0.5,
    FindingKind.AI_OBSERVATION: 0.0,  # never scored
}
# One noisy rule cannot dominate: a rule's total penalty is capped at this multiple of its single weight.
PER_RULE_CAP_MULTIPLIER = 3.0
# A single serious finding bounds its category's score, however clean the rest is.
#   (severity, strong) -> ceiling, where strong = confirmed with high confidence.
# Low-confidence findings never set a ceiling.
SEVERITY_CEILING = {
    (Severity.CRITICAL, True): 35.0,   # -> Critical risk
    (Severity.CRITICAL, False): 55.0,  # -> High risk
    (Severity.HIGH, True): 65.0,       # -> Moderate risk
    (Severity.HIGH, False): 75.0,      # -> Moderate risk
}
# The overall risk is at least the risk of these categories, and at most one level better than any other.
CRITICAL_CATEGORIES = {Category.SECURITY, Category.API, Category.DEPENDENCIES, Category.DATABASE}

CATEGORY_WEIGHT = {
    Category.SECURITY: 3.0,
    Category.DEPENDENCIES: 2.0,
    Category.API: 2.0,
    Category.DATABASE: 1.5,
    Category.TESTING: 1.5,
    Category.DEVOPS: 1.5,
    Category.ARCHITECTURE: 1.0,
    Category.PERFORMANCE: 1.0,
    Category.MAINTAINABILITY: 1.0,
}

# Risk thresholds on a 0–100 score.
RISK_THRESHOLDS = [(80.0, "Low"), (60.0, "Moderate"), (40.0, "High"), (0.0, "Critical")]


def risk_for(score: float) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "Critical"


@dataclass
class CategoryScore:
    category: str
    assessed: bool
    score: float | None
    risk: str
    penalty: float
    findings: int
    ceiling_reason: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ScoreCard:
    overall: float | None
    risk: str
    categories: dict[str, CategoryScore] = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)
    version: str = SCORING_VERSION

    def to_dict(self) -> dict:
        return {
            "overall": self.overall,
            "risk": self.risk,
            "categories": {k: v.to_dict() for k, v in self.categories.items()},
            "severity_counts": self.severity_counts,
            "version": self.version,
        }


def finding_penalty(f: Finding) -> float:
    return SEVERITY_WEIGHT[f.severity] * CONFIDENCE_FACTOR[f.confidence] * KIND_FACTOR[f.kind]


def score(findings: list[Finding], assessed_categories: set[str]) -> ScoreCard:
    """Compute category and overall scores.

    A category is only scored if at least one analyzer covering it ran successfully; otherwise it is
    reported as *not assessed* (never as a perfect 100).
    """
    by_cat_rule: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    rule_cap: dict[tuple[str, str], float] = {}
    counts_by_cat: dict[str, int] = defaultdict(int)
    ceiling: dict[str, tuple[float, str]] = {}
    severity_counts = {s.value: 0 for s in Severity}

    for f in findings:
        if not f.scored:
            continue
        cat = str(f.category)
        severity_counts[str(f.severity)] += 1
        counts_by_cat[cat] += 1
        by_cat_rule[cat][f.rule_id] += finding_penalty(f)
        key = (cat, f.rule_id)
        rule_cap[key] = max(rule_cap.get(key, 0.0), SEVERITY_WEIGHT[f.severity] * PER_RULE_CAP_MULTIPLIER)
        if f.confidence != Confidence.LOW:
            strong = f.kind == FindingKind.CONFIRMED and f.confidence == Confidence.HIGH
            limit = SEVERITY_CEILING.get((f.severity, strong))
            if limit is not None and (cat not in ceiling or limit < ceiling[cat][0]):
                label = "confirmed" if strong else str(f.kind)
                ceiling[cat] = (limit, f"capped at {limit:.0f} by {label} {f.severity} finding: {f.title}")

    categories: dict[str, CategoryScore] = {}
    weighted_sum = weight_total = 0.0
    for cat in Category:
        name = cat.value
        if name not in assessed_categories:
            categories[name] = CategoryScore(name, False, None, "Not assessed", 0.0, counts_by_cat.get(name, 0))
            continue
        penalty = sum(min(p, rule_cap[(name, rule)]) for rule, p in by_cat_rule[name].items())
        value = max(0.0, 100.0 - penalty)
        reason = ""
        if name in ceiling and value > ceiling[name][0]:
            value, reason = ceiling[name]
        value = round(value, 1)
        categories[name] = CategoryScore(name, True, value, risk_for(value), round(penalty, 2),
                                         counts_by_cat.get(name, 0), reason)
        weighted_sum += value * CATEGORY_WEIGHT[cat]
        weight_total += CATEGORY_WEIGHT[cat]

    if weight_total == 0:
        return ScoreCard(None, "Not assessed", categories, severity_counts)
    overall = round(weighted_sum / weight_total, 1)
    risk = escalate_overall_risk(risk_for(overall), categories)
    return ScoreCard(overall, risk, categories, severity_counts)


RISK_ORDER = ["Low", "Moderate", "High", "Critical"]


def escalate_overall_risk(risk: str, categories: dict[str, CategoryScore]) -> str:
    """An average must not hide a severe category: the overall risk is at least the risk of any critical
    category (security, API, dependencies, database) and at most one level better than any other category."""
    level = RISK_ORDER.index(risk)
    for name, cs in categories.items():
        if not cs.assessed:
            continue
        cat_level = RISK_ORDER.index(cs.risk)
        floor = cat_level if Category(name) in CRITICAL_CATEGORIES else cat_level - 1
        level = max(level, floor)
    return RISK_ORDER[level]
