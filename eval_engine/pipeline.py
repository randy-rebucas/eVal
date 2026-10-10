"""Audit pipeline:

Repository Input → Secure Inspection → Language Detection → Static Analysis → Finding Validation &
Deduplication → Deterministic Scoring → (optional) AI-Assisted Analysis → Report.

AI enrichment runs *after* scoring and can only attach explanations or add unscored ``ai_observation``
findings, so AI output can never change a score.
"""

from __future__ import annotations

import copy
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import ENGINE_VERSION, fingerprint
from .analyzers import registry
from .analyzers.base import Analyzer, AnalyzerContext, AnalyzerError, AnalyzerOutcome, ToolTimeout
from .dedupe import LifecycleDiff, classify, family_of, merge_duplicates, validate
from .findings import SEVERITY_RANK, Confidence, Finding, FindingKind
from .languages import LanguageReport, detect
from .redaction import redact
from .scoring import ScoreCard, score
from .workspace import Limits, WorkspaceError, iter_files

Progress = Callable[[str, int, str], None]


def _noop(stage: str, percent: int, message: str = "") -> None:
    return None


@dataclass
class PreviousState:
    """Fingerprints from the previous successful audit (with display metadata) and all earlier audits."""

    previous: dict[str, dict] = field(default_factory=dict)
    ever_seen: set[str] = field(default_factory=set)


@dataclass
class PipelineConfig:
    analyzers: list[str] | None = None
    limits: Limits = field(default_factory=Limits)
    tool_timeout: int = 300
    progress: Progress | None = None
    previous_fingerprints: PreviousState | None = None
    ai: Any = None  # eval_engine.ai.enrich.Enricher
    offline: bool = False  # skip analyzers that need network access (CLI --offline)
    policy: Any = None  # eval_engine.policy.Policy: excluded paths, disabled rules/analyzers, severity overrides


@dataclass
class AuditResult:
    findings: list[Finding]
    scorecard: ScoreCard
    languages: LanguageReport
    outcomes: list[AnalyzerOutcome]
    lifecycle: LifecycleDiff
    stats: dict
    engine_version: str = ENGINE_VERSION
    ai_summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "engine_version": self.engine_version,
            "scores": self.scorecard.to_dict(),
            "languages": self.languages.to_dict(),
            "tools": [o.to_dict() for o in self.outcomes],
            "lifecycle": {
                "new": self.lifecycle.new,
                "existing": self.lifecycle.existing,
                "recurring": self.lifecycle.recurring,
                "resolved": self.lifecycle.resolved,
            },
            "stats": self.stats,
            "ai_summary": self.ai_summary,
            "findings": [f.to_dict() for f in self.findings],
        }


def run_analyzer(analyzer: Analyzer, ctx: AnalyzerContext) -> AnalyzerOutcome:
    from . import sandbox

    outcome = AnalyzerOutcome(
        name=analyzer.name,
        title=analyzer.title,
        status="ok",
        categories=[str(c) for c in analyzer.categories],
        tool=analyzer.tool,
    )
    reason = analyzer.applicable(ctx)
    if reason:
        outcome.status, outcome.reason = "skipped", reason
        return outcome
    if analyzer.tool and sandbox.which(analyzer.tool) is None:
        outcome.status, outcome.reason = "skipped", f"{analyzer.tool} is not installed on the worker"
        return outcome
    if ctx.offline:
        needs = analyzer.network_required(ctx)
        if needs:
            outcome.status, outcome.reason = "skipped", f"offline mode: {needs}"
            return outcome
    start = time.monotonic()
    try:
        outcome.findings = analyzer.run(ctx)
    except ToolTimeout as exc:
        outcome.status, outcome.reason = "timeout", str(exc)
    except AnalyzerError as exc:
        outcome.status, outcome.reason = "failed", redact(str(exc))[:300]
    except Exception as exc:  # noqa: BLE001 - one broken analyzer must not fail the audit
        outcome.status, outcome.reason = "failed", f"internal analyzer error ({type(exc).__name__})"
    outcome.duration = time.monotonic() - start
    if outcome.status != "ok":
        outcome.findings = []
    return outcome


def _run_ai(enricher, findings: list[Finding], languages, card, ctx) -> tuple[dict, list[Finding]]:
    """Give the enricher deep copies; accept back only ``ai_explanation`` and unscored AI observations.
    Deterministic fields (severity, kind, location, evidence …) cannot be altered by AI output."""
    copies = copy.deepcopy(findings)
    summary = enricher.enrich(findings=copies, languages=languages, scorecard=card, ctx=ctx) or {}
    by_fp = {f.fingerprint: f for f in findings}
    for c in copies:
        if c.fingerprint in by_fp and isinstance(c.ai_explanation, dict):
            by_fp[c.fingerprint].ai_explanation = c.ai_explanation
    observations = []
    for obs in summary.pop("_observations", []) or []:
        if isinstance(obs, Finding):
            obs.kind = FindingKind.AI_OBSERVATION
            obs.confidence = Confidence.LOW
            observations.append(obs)
    valid_obs, _ = validate(observations, set(ctx.files), lambda p: len(ctx.lines(p)))
    return summary, valid_obs


def run_pipeline(root: Path, config: PipelineConfig | None = None) -> AuditResult:
    config = config or PipelineConfig()
    progress = config.progress or _noop
    started = time.monotonic()

    progress("inspecting repository", 5, "")
    files = []
    for rel in iter_files(root, max_file_bytes=config.limits.max_file_bytes):
        files.append(rel)
        if len(files) > config.limits.max_files:
            raise WorkspaceError(f"Repository exceeds the {config.limits.max_files} file limit.")

    progress("detecting languages", 10, "")
    languages = detect(root, files)
    ctx = AnalyzerContext(root=root, files=files, languages=languages, timeout=config.tool_timeout,
                          offline=config.offline)

    analyzers = registry.get(config.analyzers)
    if config.policy is not None and config.policy.disable_analyzers:
        analyzers = [a for a in analyzers if a.name not in config.policy.disable_analyzers]
    outcomes: list[AnalyzerOutcome] = []
    for i, analyzer in enumerate(analyzers):
        progress(f"analyzing: {analyzer.title}", 15 + int(60 * i / max(len(analyzers), 1)), "")
        outcomes.append(run_analyzer(analyzer, ctx))

    progress("validating and deduplicating findings", 78, "")
    raw = [f for o in outcomes for f in o.findings]
    findings, dropped = validate(raw, set(files), lambda p: len(ctx.lines(p)))

    def source_line(path: str, line: int) -> str:
        lines = ctx.lines(path)
        return lines[line - 1] if 0 < line <= len(lines) else ""

    fingerprint.compute(findings, source_line, family_of)
    findings = merge_duplicates(findings)
    policy_stats = None
    if config.policy is not None:
        from .policy import apply as apply_policy

        findings, effect = apply_policy(config.policy, findings)
        policy_stats = {"digest": config.policy.digest, "sources": config.policy.sources, **effect.to_dict()}
    from .reachability import annotate as annotate_reachability

    reach = annotate_reachability(findings, ctx)
    prev = config.previous_fingerprints or PreviousState()
    lifecycle = classify(findings, prev.previous, prev.ever_seen)

    progress("scoring", 85, "")
    assessed = {c for o in outcomes if o.status == "ok" for c in o.categories}
    card = score(findings, assessed)

    ai_summary: dict = {}
    if config.ai is not None:
        progress("AI-assisted analysis", 88, "")
        try:
            ai_summary, extra = _run_ai(config.ai, findings, languages, card, ctx)
        except Exception as exc:  # noqa: BLE001 - optional stage; the deterministic audit still stands
            ai_summary, extra = {"error": f"AI analysis failed ({type(exc).__name__})"}, []
        fingerprint.compute(extra, source_line, family_of)
        findings.extend(extra)

    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], str(f.category), f.file_path, f.line_start or 0))
    stats = {
        "files_analyzed": len(files),
        "raw_findings": len(raw),
        "dropped_invalid": dropped,
        "duration_seconds": round(time.monotonic() - started, 2),
    }
    if policy_stats is not None:
        stats["policy"] = policy_stats
    if reach:
        stats["reachability"] = reach
    return AuditResult(
        findings=findings,
        scorecard=card,
        languages=languages,
        outcomes=outcomes,
        lifecycle=lifecycle,
        stats=stats,
        ai_summary=ai_summary,
    )
