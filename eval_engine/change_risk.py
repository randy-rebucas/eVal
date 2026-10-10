"""Change risk of a pull request: how much scrutiny a change deserves, independent of the audit score.

AI assistants make large changes cheap to produce and expensive to review. This score helps reviewers decide where
to look first. It is deterministic and additive; every point comes from a named factor shown to the user:

| Factor | Points |
|---|---|
| Size: changed lines > 1000 / > 400 / > 150 | 25 / 15 / 8 |
| Size: changed files > 30 / > 10 | 10 / 5 |
| Sensitive area touched (each kind once): authentication/authorization, payments | 15 each |
| Sensitive area: cryptography & secrets, database schema, CI/infrastructure | 10 each |
| Sensitive area: dependency manifests | 8 |
| (all sensitive areas together are capped at 35) | |
| Source code changed but no test file changed | 15 |
| Findings the change introduced: critical 15, high 10, medium 4, low 1 each (cap 30) | |
| AI-generated-code patterns among them (``ai-code.*`` rules): 5 each (cap 15) | |

Levels: **high** ≥ 60, **medium** ≥ 30, otherwise **low**. The score never changes audit scores or severities; a
policy may gate on it (``gate.max_change_risk``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .analyzers.base import is_test_path
from .languages import CODE_LANGUAGES, EXTENSIONS

LEVELS = ("low", "medium", "high")
SENSITIVE = [
    ("authentication & authorization", 15, re.compile(
        r"(?:^|[/_.-])(?:auth|login|logout|session|password|passwd|oauth|sso|saml|jwt|token|permission|rbac|acl|"
        r"role|signup|register)", re.I)),
    ("payments & billing", 15, re.compile(r"(?:pay|billing|invoice|checkout|stripe|subscription|refund|wallet)",
                                          re.I)),
    ("cryptography & secrets", 10, re.compile(r"(?:crypt|cipher|secret|hmac|signing|keys?[/_.]|vault|kms)", re.I)),
    ("database schema", 10, re.compile(r"(?:^|/)(?:migrations?|alembic|schema\.(?:sql|prisma|rb)|db/schema)", re.I)),
    ("CI & infrastructure", 10, re.compile(
        r"(?:^\.github/workflows/|(?:^|/)Dockerfile|docker-compose|\.tf$|(?:^|/)(?:k8s|helm|terraform|deploy)/|"
        r"render\.ya?ml$|\.gitlab-ci\.yml$|Jenkinsfile$|nginx\.conf$)", re.I)),
    ("dependencies", 8, re.compile(
        r"(?:^|/)(?:requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile(?:\.lock)?|package\.json|"
        r"package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.mod|Cargo\.toml|Gemfile(?:\.lock)?)$", re.I)),
]
SENSITIVE_CAP = 35
SEVERITY_POINTS = {"critical": 15, "high": 10, "medium": 4, "low": 1, "info": 0}


@dataclass
class ChangeRisk:
    score: int
    level: str
    factors: list[dict] = field(default_factory=list)  # {"factor", "points", "detail"}

    def to_dict(self) -> dict:
        return {"score": self.score, "level": self.level, "factors": self.factors}


def level_for(score: int) -> str:
    return "high" if score >= 60 else "medium" if score >= 30 else "low"


def _is_code(path: str) -> bool:
    ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    return EXTENSIONS.get(ext) in CODE_LANGUAGES


def assess(files: list[tuple[str, int, int]], introduced: list) -> ChangeRisk:
    """``files``: (path, additions, deletions) for every file the change touches. ``introduced``: findings the
    change introduced (objects with ``severity`` and ``rule_id``)."""
    factors: list[dict] = []

    def add(factor: str, points: int, detail: str) -> None:
        if points:
            factors.append({"factor": factor, "points": points, "detail": detail})

    lines = sum(a + d for _, a, d in files)
    add("size", 25 if lines > 1000 else 15 if lines > 400 else 8 if lines > 150 else 0,
        f"{lines} changed lines")
    add("size", 10 if len(files) > 30 else 5 if len(files) > 10 else 0, f"{len(files)} changed files")

    sensitive_points = 0
    for name, points, pattern in SENSITIVE:
        hits = [p for p, _, _ in files if pattern.search(p) and not is_test_path(p)]
        if hits and sensitive_points < SENSITIVE_CAP:
            pts = min(points, SENSITIVE_CAP - sensitive_points)
            sensitive_points += pts
            more = f" and {len(hits) - 3} more" if len(hits) > 3 else ""
            add("sensitive area", pts, f"{name}: {', '.join(hits[:3])}{more}")

    code = [p for p, _, _ in files if _is_code(p) and not is_test_path(p)]
    tests = [p for p, _, _ in files if is_test_path(p)]
    if code and not tests:
        add("tests", 15, f"{len(code)} source file(s) changed, no test file changed")

    finding_points = min(30, sum(SEVERITY_POINTS.get(str(f.severity), 0) for f in introduced))
    if finding_points:
        counts: dict[str, int] = {}
        for f in introduced:
            counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
        add("introduced findings", finding_points, ", ".join(f"{n} {s}" for s, n in counts.items()))
    ai = [f for f in introduced if ":ai-code." in f.rule_id]
    add("AI-generated code patterns", min(15, 5 * len(ai)), f"{len(ai)} finding(s) typical of generated code")

    score = min(100, sum(f["points"] for f in factors))
    return ChangeRisk(score=score, level=level_for(score), factors=factors)


def exceeds(level: str, maximum: str) -> bool:
    """Whether ``level`` is above the allowed ``maximum`` (``never`` disables the check)."""
    return maximum in LEVELS and LEVELS.index(level) > LEVELS.index(maximum)
