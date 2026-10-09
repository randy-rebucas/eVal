"""``eval-audit``: audit a local directory or ZIP without the web app (usable in CI).

    eval-audit ./my-repo --format md --output report.md --fail-on high
    eval-audit ./my-repo --ai local --ai-model qwen2.5-coder:7b     # AI explanations from a model on this machine
    eval-audit ./my-repo --ai local --offline                       # nothing leaves the machine
    eval-audit doctor                                               # check tools and the local model server

Exit codes: 0 = completed and below the --fail-on threshold, 1 = findings at/above the threshold,
2 = usage or input error. ``doctor``: 0 = ready for --ai local, 1 = not ready.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
import tempfile
from pathlib import Path

from . import ENGINE_VERSION
from .ai.base import AIError
from .ai.enrich import Enricher
from .ai.local import (
    DEFAULT_LOCAL_MODEL,
    DEFAULT_LOCAL_URL,
    LOCAL_BATCH_SIZE,
    LOCAL_MAX_FINDINGS,
    LOCAL_MAX_TOKENS,
    build_local_provider,
)
from .findings import SEVERITY_RANK
from .netguard import block_outbound
from .pipeline import PipelineConfig, run_pipeline
from .reports import FORMATS, render
from .workspace import WorkspaceError, extract_zip


def _add_local_ai_target(p) -> None:
    p.add_argument("--ai-model", default=os.environ.get("EVAL_LOCAL_AI_MODEL", DEFAULT_LOCAL_MODEL),
                   help=f"local model name (default: $EVAL_LOCAL_AI_MODEL or {DEFAULT_LOCAL_MODEL})")
    p.add_argument("--ai-url", default=os.environ.get("EVAL_LOCAL_AI_URL", DEFAULT_LOCAL_URL),
                   help=f"OpenAI-compatible endpoint, loopback only (default: $EVAL_LOCAL_AI_URL or "
                        f"{DEFAULT_LOCAL_URL})")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="eval-audit", description="eVal static production-readiness audit",
                                epilog="Run 'eval-audit doctor' to check analyzers and the local model server.")
    p.add_argument("path", help="directory or .zip archive to audit (never executed)")
    p.add_argument("--format", choices=FORMATS, default="md")
    p.add_argument("--output", "-o", help="write the report here instead of stdout")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="never",
                   help="exit 1 if any scored finding at or above this severity exists")
    p.add_argument("--analyzers", help="comma-separated analyzer names (default: all)")
    p.add_argument("--timeout", type=int, default=300, help="per-tool timeout in seconds")
    p.add_argument("--offline", action="store_true",
                   help="no network access: skip checks that need it (reported as not assessed) and block "
                        "outbound connections from eVal; a local model server is still allowed")
    ai = p.add_argument_group("AI-assisted analysis (never changes scores)")
    ai.add_argument("--ai", choices=["off", "local"], default="off",
                    help="'local': explain findings with a model server on this machine (Ollama, LM Studio, ...)")
    _add_local_ai_target(ai)
    ai.add_argument("--ai-max-findings", type=int, default=LOCAL_MAX_FINDINGS,
                    help="most severe findings to explain (default: %(default)s)")
    ai.add_argument("--ai-batch-size", type=int, default=LOCAL_BATCH_SIZE,
                    help="findings per model request; smaller suits smaller models (default: %(default)s)")
    ai.add_argument("--ai-timeout", type=int, default=300, help="per-request model timeout in seconds")
    p.add_argument("--version", action="version", version=f"eVal engine {ENGINE_VERSION}")
    return p


def build_doctor_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="eval-audit doctor",
                                description="Check installed analyzers, the local model server, and offline readiness")
    _add_local_ai_target(p)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["doctor"]:
        from .doctor import run_doctor

        dargs = build_doctor_parser().parse_args(argv[1:])
        return run_doctor(ai_url=dargs.ai_url, ai_model=dargs.ai_model, out=sys.stdout)

    args = build_parser().parse_args(argv)
    target = Path(args.path)
    analyzers = [a.strip() for a in args.analyzers.split(",")] if args.analyzers else None
    enricher = None
    if args.ai == "local":
        try:
            provider = build_local_provider(model=args.ai_model, base_url=args.ai_url, timeout=args.ai_timeout)
        except AIError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        enricher = Enricher(provider, max_findings=args.ai_max_findings, max_tokens=LOCAL_MAX_TOKENS,
                            batch_size=args.ai_batch_size)

    def progress(stage: str, pct: int, _msg: str = "") -> None:
        print(f"[{pct:3d}%] {stage}", file=sys.stderr)

    blocked: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix="eval-cli-") as tmp, \
                (block_outbound() if args.offline else contextlib.nullcontext([])) as blocked:
            root = target
            if target.is_file() and target.suffix.lower() == ".zip":
                root = Path(tmp) / "src"
                extract_zip(target, root)
            elif not target.is_dir():
                print(f"error: {target} is not a directory or .zip file", file=sys.stderr)
                return 2
            result = run_pipeline(root, PipelineConfig(analyzers=analyzers, tool_timeout=args.timeout,
                                                       progress=progress, ai=enricher, offline=args.offline))
    except (WorkspaceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if enricher is not None and result.ai_summary.get("error"):
        # The audit itself is complete; AI is best-effort and the report records why it is missing.
        hint = " (check with: eval-audit doctor)"
        print(f"warning: local AI ({args.ai_model} at {args.ai_url}): {result.ai_summary['error']}{hint}",
              file=sys.stderr)
    if blocked:
        print(f"warning: offline mode blocked {len(blocked)} outbound connection attempt(s): "
              f"{', '.join(dict.fromkeys(blocked))}", file=sys.stderr)

    model = result.to_dict()
    name = target.resolve().name  # `target.name` is empty for "." or ".."
    model["meta"] = {"title": f"eVal audit: {name}", "repository": str(target)}
    if args.offline:
        model["offline"] = {"enabled": True, "blocked_connections": list(dict.fromkeys(blocked))}
    report = render(model, args.format)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    if args.fail_on != "never":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(f.scored and SEVERITY_RANK[f.severity] >= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
