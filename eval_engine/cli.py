"""``eval-audit``: audit a local directory or ZIP without the web app (usable in CI).

    eval-audit ./my-repo --format md --output report.md --fail-on high

Exit codes: 0 = completed and below the --fail-on threshold, 1 = findings at/above the threshold,
2 = usage or input error.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from . import ENGINE_VERSION
from .findings import SEVERITY_RANK
from .pipeline import PipelineConfig, run_pipeline
from .reports import FORMATS, render
from .workspace import WorkspaceError, extract_zip


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="eval-audit", description="eVal static production-readiness audit")
    p.add_argument("path", help="directory or .zip archive to audit (never executed)")
    p.add_argument("--format", choices=FORMATS, default="md")
    p.add_argument("--output", "-o", help="write the report here instead of stdout")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="never",
                   help="exit 1 if any scored finding at or above this severity exists")
    p.add_argument("--analyzers", help="comma-separated analyzer names (default: all)")
    p.add_argument("--timeout", type=int, default=300, help="per-tool timeout in seconds")
    p.add_argument("--version", action="version", version=f"eVal engine {ENGINE_VERSION}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = Path(args.path)
    analyzers = [a.strip() for a in args.analyzers.split(",")] if args.analyzers else None

    def progress(stage: str, pct: int, _msg: str = "") -> None:
        print(f"[{pct:3d}%] {stage}", file=sys.stderr)

    try:
        with tempfile.TemporaryDirectory(prefix="eval-cli-") as tmp:
            root = target
            if target.is_file() and target.suffix.lower() == ".zip":
                root = Path(tmp) / "src"
                extract_zip(target, root)
            elif not target.is_dir():
                print(f"error: {target} is not a directory or .zip file", file=sys.stderr)
                return 2
            result = run_pipeline(root, PipelineConfig(analyzers=analyzers, tool_timeout=args.timeout,
                                                       progress=progress))
    except (WorkspaceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    model = result.to_dict()
    model["meta"] = {"title": f"eVal audit: {target.name}", "repository": str(target)}
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
