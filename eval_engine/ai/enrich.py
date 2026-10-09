"""AI-assisted explanations, remediation suggestions, and architectural summary.

Safety properties (see docs/SECURITY.md § AI):
* Only already-detected findings and short, *redacted* evidence snippets are sent; never whole files.
* Repository-derived text is wrapped in ``<untrusted_repository_content>`` delimiters (closing tags inside the
  data are neutralised) and the system prompt forbids following instructions found there.
* Output must be JSON; it is validated against the expected shape, unknown IDs and keys are dropped, strings
  are length-capped and redacted again. Invalid output is discarded, never partially trusted.
* The pipeline hands this module copies of findings and keeps only ``ai_explanation`` plus unscored
  ``ai_observation`` findings, so AI output can never change severities or scores.
"""

from __future__ import annotations

import json
from importlib import resources

from ..findings import SEVERITY_RANK, Category, Confidence, Finding, FindingKind, Severity
from ..redaction import redact
from .base import AIError, AIOutputError, AIProvider

PROMPT_VERSION = "v1"
DELIM = "untrusted_repository_content"
MAX_STR = 2000
FP_LEVELS = ("low", "medium", "high")

EXPLAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "explanations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "explanation": {"type": "string"},
                    "remediation_steps": {"type": "array", "items": {"type": "string"}},
                    "suggested_patch": {"type": "string"},
                    "false_positive_likelihood": {"type": "string", "enum": list(FP_LEVELS)},
                },
                "required": ["id", "explanation", "remediation_steps", "suggested_patch",
                             "false_positive_likelihood"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["explanations"],
    "additionalProperties": False,
}
SUMMARY_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "top_risks": {"type": "array", "items": {"type": "string"}},
        "observations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "file_path": {"type": "string"},
                    "category": {"type": "string", "enum": [c.value for c in Category]},
                },
                "required": ["title", "description", "file_path", "category"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "top_risks", "observations"],
    "additionalProperties": False,
}


def load_prompt(name: str) -> str:
    return resources.files("eval_engine.ai").joinpath(f"prompts/{name}_{PROMPT_VERSION}.txt").read_text("utf-8")


def neutralize(text: str) -> str:
    """Redact secrets and stop data from closing (or opening) the untrusted-content delimiter."""
    return redact(text or "").replace(f"</{DELIM}", f"</{DELIM}_").replace(f"<{DELIM}", f"<{DELIM}_")


def _clean_str(value, limit: int = MAX_STR) -> str:
    return redact(value)[:limit].strip() if isinstance(value, str) else ""


def validate_explanations(data: dict, allowed: set[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    items = data.get("explanations") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise AIOutputError("AI response did not match the expected schema.")
    for item in items[: len(allowed) * 2]:
        if not isinstance(item, dict) or item.get("id") not in allowed or item["id"] in out:
            continue
        explanation = _clean_str(item.get("explanation"))
        if not explanation:
            continue
        steps = item.get("remediation_steps")
        fp = item.get("false_positive_likelihood")
        out[item["id"]] = {
            "explanation": explanation,
            "remediation_steps": [_clean_str(s, 500) for s in steps[:5] if _clean_str(s, 500)]
            if isinstance(steps, list) else [],
            "suggested_patch": _clean_str(item.get("suggested_patch"), 4000),
            "false_positive_likelihood": fp if fp in FP_LEVELS else "",
        }
    return out


def validate_summary(data: dict, known_files: set[str]) -> tuple[dict, list[Finding]]:
    if not isinstance(data, dict) or not isinstance(data.get("summary"), str):
        raise AIOutputError("AI response did not match the expected schema.")
    risks = data.get("top_risks") if isinstance(data.get("top_risks"), list) else []
    summary = {"summary": _clean_str(data["summary"], 3000),
               "top_risks": [r for r in (_clean_str(x, 300) for x in risks[:5]) if r]}
    observations = []
    raw_obs = data.get("observations") if isinstance(data.get("observations"), list) else []
    for obs in raw_obs[:5]:
        if not isinstance(obs, dict):
            continue
        title, desc = _clean_str(obs.get("title"), 200), _clean_str(obs.get("description"), 1500)
        try:
            category = Category(obs.get("category"))
        except ValueError:
            continue
        path = obs.get("file_path") if obs.get("file_path") in known_files else ""
        if not title or not desc:
            continue
        observations.append(Finding(
            rule_id="ai:observation", title=title, category=category, severity=Severity.INFO,
            confidence=Confidence.LOW, kind=FindingKind.AI_OBSERVATION, description=desc,
            remediation="Review manually; this observation was generated by an AI model and is not scored.",
            file_path=path, sources=["ai"],
        ))
    return summary, observations


class Enricher:
    def __init__(self, provider: AIProvider, max_findings: int = 15, max_tokens: int = 16000,
                 batch_size: int | None = None, output_retries: int = 1):
        self.provider = provider
        self.max_findings = max(1, min(max_findings, 50))
        self.max_tokens = max_tokens
        # Findings explained per request (default: all in one). Small local models do better with short batches.
        self.batch_size = max(1, batch_size or self.max_findings)
        self.output_retries = max(0, output_retries)
        self.retries = 0

    def _ask(self, user: str, schema: dict, validate):
        """One request, validated; retried only when the model answered with unusable output."""
        for attempt in range(self.output_retries + 1):
            try:
                data = self.provider.complete_json(system=load_prompt("system"), user=user, schema=schema,
                                                   max_tokens=self.max_tokens)
                return validate(data)
            except AIOutputError:
                if attempt == self.output_retries:
                    raise
                self.retries += 1
        raise AssertionError("unreachable")  # pragma: no cover

    def _select(self, findings: list[Finding]) -> list[Finding]:
        conf = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}
        candidates = [f for f in findings if f.scored and f.severity != Severity.INFO]
        candidates.sort(key=lambda f: (-SEVERITY_RANK[f.severity], -conf[f.confidence], f.file_path))
        return candidates[: self.max_findings]

    @staticmethod
    def _profile(languages, scorecard) -> str:
        return json.dumps({"languages": languages.files_by_language, "frameworks": languages.frameworks,
                           "overall_risk": scorecard.risk}, sort_keys=True)

    @staticmethod
    def _finding_payload(fid: str, f: Finding) -> dict:
        return {"id": fid, "rule": f.rule_id, "title": neutralize(f.title), "severity": str(f.severity),
                "kind": str(f.kind), "category": str(f.category), "location": neutralize(
                    f"{f.file_path}:{f.line_start}" if f.line_start else f.file_path or "(repository)"),
                "description": neutralize(f.description)[:800], "evidence": neutralize(f.evidence)[:600]}

    def enrich(self, *, findings: list[Finding], languages, scorecard, ctx) -> dict:
        chosen = self._select(findings)
        self.retries = 0
        result: dict = {"provider": self.provider.info.name, "model": self.provider.info.model,
                        "prompt_version": PROMPT_VERSION, "explained": 0}
        if not chosen:
            result["summary"] = ""
            return result
        ids = {f"F{i}": f for i, f in enumerate(chosen, start=1)}
        payloads = [self._finding_payload(fid, f) for fid, f in ids.items()]
        profile = self._profile(languages, scorecard)
        errors = []
        for start in range(0, len(payloads), self.batch_size):
            batch = payloads[start:start + self.batch_size]
            allowed = {p["id"] for p in batch}
            try:
                explained = self._ask(
                    load_prompt("explain").format(profile=profile, findings=json.dumps(batch, indent=1)),
                    EXPLAIN_SCHEMA, lambda data, allowed=allowed: validate_explanations(data, allowed))
            except AIError as exc:
                errors.append(str(exc))
                continue
            for fid, expl in explained.items():
                ids[fid].ai_explanation = {**expl, "provider": self.provider.info.name,
                                           "model": self.provider.info.model, "prompt_version": PROMPT_VERSION}
            result["explained"] += len(explained)
        try:
            scores = json.dumps({k: v.score for k, v in scorecard.categories.items()}, sort_keys=True)
            summary, observations = self._ask(
                load_prompt("summary").format(profile=profile, scores=scores,
                                              findings=json.dumps(payloads, indent=1)),
                SUMMARY_SCHEMA, lambda data: validate_summary(data, set(ctx.files)))
            result.update(summary)
            result["_observations"] = observations
        except AIError as exc:
            errors.append(str(exc))
        if self.retries:
            result["retries"] = self.retries
        if errors:
            result["error"] = "; ".join(dict.fromkeys(errors))
        return result
