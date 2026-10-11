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
from .workspace import Limits, WorkspaceError, count_files, human_size, iter_files

# progress(stage, percent) marks the start of a stage; progress(stage, percent, message, path=, step=, level=) reports
# a detail inside it: ``path`` the file it concerns, ``step`` the stage's own percent (None when unknown), ``level``
# "ok" | "warn" | "error" | "" for outcome lines.
Progress = Callable[..., None]


def _noop(stage: str, percent: int, message: str = "", **detail: Any) -> None:
    return None


class _Stage:
    """One pipeline stage spanning the overall percent range [lo, hi]."""

    def __init__(self, progress: Progress, name: str, lo: int, hi: int):
        self.progress, self.name, self.lo, self.hi = progress, name, lo, hi
        progress(name, lo, "")

    def detail(self, message: str, *, done: int | None = None, total: int | None = None, path: str = "",
               level: str = "") -> None:
        if done is not None and total:
            done = min(done, total)
            pct, step = self.lo + (self.hi - self.lo) * done // total, done * 100 // total
        else:
            pct, step = self.lo, None
        self.progress(self.name, pct, message, path=path, step=step, level=level)


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
    app_profile: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "engine_version": self.engine_version,
            "scores": self.scorecard.to_dict(),
            "languages": self.languages.to_dict(),
            "app_profile": self.app_profile,
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


def run_analyzer(analyzer: Analyzer, ctx: AnalyzerContext,
                 on_start: Callable[[], None] | None = None) -> AnalyzerOutcome:
    """``on_start`` is called once the analyzer is known to run (after the applicability checks)."""
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
    if on_start is not None:
        on_start()
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


def _analysis_reporter(analyzer: Analyzer, ctx: AnalyzerContext, stage: _Stage) -> Callable[[], None]:
    """Report the start of an analyzer that runs, then each distinct file it reads."""

    def on_start() -> None:
        stage.detail(f"running {analyzer.tool} in the sandbox" if analyzer.tool else "reading source files")
        scanned: set[str] = set()

        def on_read(rel: str) -> None:
            if rel not in scanned:
                scanned.add(rel)
                stage.detail(f"scanned · file {len(scanned)}", path=rel)

        ctx.on_read = on_read

    return on_start


def _outcome_line(outcome: AnalyzerOutcome) -> tuple[str, str]:
    if outcome.status == "ok":
        n = len(outcome.findings)
        return f"{n} finding{'s' if n != 1 else ''} · {outcome.duration:.1f}s", "ok"
    if outcome.status == "skipped":
        return f"skipped · {outcome.reason}", ""
    return f"{outcome.status} · {outcome.reason}", "error" if outcome.status == "failed" else "warn"


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

    stage = _Stage(progress, "inspecting repository", 5, 8)
    entries, seen, skipped = count_files(root), 0, 0
    files = []

    def on_entry(rel: str, size: int, skip: str) -> None:
        nonlocal seen, skipped
        seen += 1
        skipped += bool(skip)
        stage.detail(f"skipped · {skip}" if skip else f"inspected · {human_size(size)}", done=seen, total=entries,
                     path=rel, level="warn" if skip else "")

    for rel in iter_files(root, max_file_bytes=config.limits.max_file_bytes, on_entry=on_entry):
        files.append(rel)
        if len(files) > config.limits.max_files:
            raise WorkspaceError(f"Repository exceeds the {config.limits.max_files} file limit.")
    stage.detail(f"{len(files)} files to analyze" + (f", {skipped} skipped" if skipped else ""),
                 done=entries, total=entries, level="ok")

    stage = _Stage(progress, "detecting languages", 8, 12)
    languages = detect(root, files, on_file=lambda i, rel, desc: stage.detail(desc, done=i + 1, total=len(files),
                                                                              path=rel))
    found = ", ".join(f"{lang} ({n})" for lang, n in languages.files_by_language.items()) or "no source files"
    stage.detail(f"{found}" + (f" · frameworks: {', '.join(languages.frameworks)}" if languages.frameworks else ""),
                 done=1, total=1, level="ok")
    ctx = AnalyzerContext(root=root, files=files, languages=languages, timeout=config.tool_timeout,
                          offline=config.offline)

    analyzers = registry.get(config.analyzers)
    if config.policy is not None and config.policy.disable_analyzers:
        analyzers = [a for a in analyzers if a.name not in config.policy.disable_analyzers]
    outcomes: list[AnalyzerOutcome] = []
    n_analyzers = max(len(analyzers), 1)
    for i, analyzer in enumerate(analyzers):
        stage = _Stage(progress, f"analyzing: {analyzer.title}", 15 + 60 * i // n_analyzers,
                       15 + 60 * (i + 1) // n_analyzers)
        outcomes.append(run_analyzer(analyzer, ctx, on_start=_analysis_reporter(analyzer, ctx, stage)))
        ctx.on_read = None
        message, level = _outcome_line(outcomes[-1])
        stage.detail(message, done=1, total=1, level=level)

    stage = _Stage(progress, "validating and deduplicating findings", 78, 85)
    raw = [f for o in outcomes for f in o.findings]
    findings, dropped = validate(raw, set(files), lambda p: len(ctx.lines(p)))
    stage.detail(f"{len(raw)} raw findings · {len(findings)} valid"
                 + (f" · {dropped} dropped (outside the repository)" if dropped else ""), done=1, total=5)

    def source_line(path: str, line: int) -> str:
        lines = ctx.lines(path)
        return lines[line - 1] if 0 < line <= len(lines) else ""

    fingerprint.compute(findings, source_line, family_of)
    before = len(findings)
    findings = merge_duplicates(findings)
    stage.detail(f"{before - len(findings)} duplicates merged · {len(findings)} distinct", done=2, total=5)
    policy_stats = None
    if config.policy is not None:
        from .policy import apply as apply_policy

        before = len(findings)
        findings, effect = apply_policy(config.policy, findings)
        policy_stats = {"digest": config.policy.digest, "sources": config.policy.sources, **effect.to_dict()}
        stage.detail(f"policy applied · {before - len(findings)} findings excluded", done=3, total=5)
    from .reachability import annotate as annotate_reachability

    reach = annotate_reachability(findings, ctx)
    stage.detail("reachability annotated", done=4, total=5)
    prev = config.previous_fingerprints or PreviousState()
    lifecycle = classify(findings, prev.previous, prev.ever_seen)
    stage.detail(f"{lifecycle.new} new · {lifecycle.existing} existing · {lifecycle.recurring} recurring · "
                 f"{len(lifecycle.resolved)} resolved", done=5, total=5, level="ok")

    stage = _Stage(progress, "scoring", 85, 88)
    assessed = {c for o in outcomes if o.status == "ok" for c in o.categories}
    card = score(findings, assessed)
    categories = list(card.categories.values())
    for i, cat in enumerate(categories, 1):
        line = (f"{cat.category}: {cat.score:.0f}/100 · {cat.findings} findings"
                if cat.assessed and cat.score is not None else f"{cat.category}: not assessed")
        stage.detail(line, done=i, total=len(categories))
    overall = f"{card.overall:.0f}/100" if card.overall is not None else "n/a"
    stage.detail(f"overall {overall} · risk {card.risk}", done=1, total=1, level="ok")

    ai_summary: dict = {}
    if config.ai is not None:
        stage = _Stage(progress, "AI-assisted analysis", 88, 95)
        stage.detail(f"explaining up to {len(findings)} findings")
        try:
            ai_summary, extra = _run_ai(config.ai, findings, languages, card, ctx)
        except Exception as exc:  # noqa: BLE001 - optional stage; the deterministic audit still stands
            ai_summary, extra = {"error": f"AI analysis failed ({type(exc).__name__})"}, []
        fingerprint.compute(extra, source_line, family_of)
        findings.extend(extra)
        if ai_summary.get("error"):
            stage.detail(ai_summary["error"], done=1, total=1, level="warn")
        else:
            stage.detail(f"done · {len(extra)} AI observations added", done=1, total=1, level="ok")

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
        app_profile=ctx.profile.to_dict(),
    )
