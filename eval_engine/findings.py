"""Normalized finding model shared by every analyzer, the scorer, reports, and the web app."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITY_ORDER))}  # info=0 … critical=4


class Category(StrEnum):
    SECURITY = "security"
    ARCHITECTURE = "architecture"
    TESTING = "testing"
    DATABASE = "database"
    API = "api"
    DEPENDENCIES = "dependencies"
    PERFORMANCE = "performance"
    DEVOPS = "devops"
    MAINTAINABILITY = "maintainability"


CATEGORY_LABELS = {
    Category.SECURITY: "Security",
    Category.ARCHITECTURE: "Architecture",
    Category.TESTING: "Testing",
    Category.DATABASE: "Database",
    Category.API: "API",
    Category.DEPENDENCIES: "Dependencies",
    Category.PERFORMANCE: "Performance",
    Category.DEVOPS: "DevOps & Operations",
    Category.MAINTAINABILITY: "Maintainability",
}


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingKind(StrEnum):
    """How much the finding should be trusted.

    * ``confirmed`` – a tool matched a concrete, verifiable pattern (e.g. Bandit B602, a hardcoded key).
    * ``potential`` – a heuristic risk that needs human review (e.g. route without visible auth decorator).
    * ``estimate`` – a static performance/scale estimate; nothing was measured.
    * ``ai_observation`` – produced by an AI model; never scored.
    """

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    ESTIMATE = "estimate"
    AI_OBSERVATION = "ai_observation"


@dataclass
class Finding:
    rule_id: str  # namespaced: "<tool>:<code>", e.g. "bandit:B602", "eval:devops.dockerfile-root"
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    kind: FindingKind
    description: str
    remediation: str
    file_path: str = ""  # POSIX path relative to repo root; "" = repository-level finding
    line_start: int | None = None
    line_end: int | None = None
    evidence: str = ""  # short redacted snippet or factual statement
    references: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)  # analyzer names that reported it
    fingerprint: str = ""
    lifecycle: str = "new"
    ai_explanation: dict = field(default_factory=dict)

    @property
    def scored(self) -> bool:
        return self.kind != FindingKind.AI_OBSERVATION

    def to_dict(self) -> dict:
        data = asdict(self)
        for key in ("category", "severity", "confidence", "kind"):
            data[key] = str(data[key])
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        return cls(
            rule_id=data["rule_id"],
            title=data["title"],
            category=Category(data["category"]),
            severity=Severity(data["severity"]),
            confidence=Confidence(data["confidence"]),
            kind=FindingKind(data["kind"]),
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            file_path=data.get("file_path", ""),
            line_start=data.get("line_start"),
            line_end=data.get("line_end"),
            evidence=data.get("evidence", ""),
            references=list(data.get("references", [])),
            sources=list(data.get("sources", [])),
            fingerprint=data.get("fingerprint", ""),
            lifecycle=data.get("lifecycle", "new"),
            ai_explanation=dict(data.get("ai_explanation", {})),
        )
