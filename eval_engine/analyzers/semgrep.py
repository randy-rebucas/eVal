"""Semgrep multi-language SAST.

Rules come from ``EVAL_SEMGREP_CONFIG`` (default ``p/default``, fetched from the Semgrep registry, so the
worker needs network access; point it at a local rules directory for air-gapped installs). Metrics are off.
Note: Semgrep honours a repository's ``.semgrepignore``; a hostile repository could use it to hide files.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, AnalyzerError
from .registry import register

SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
CONF = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}


def _category(metadata: dict, check_id: str) -> Category:
    cat = str(metadata.get("category", "")).lower()
    if cat == "security" or "security" in check_id:
        return Category.SECURITY
    if cat == "performance":
        return Category.PERFORMANCE
    return Category.MAINTAINABILITY


@register
class SemgrepAnalyzer(Analyzer):
    name = "semgrep"
    title = "Semgrep (multi-language SAST)"
    categories = (Category.SECURITY,)
    tool = "semgrep"
    network_use = ("semgrep.dev: downloads registry rules (default p/default); nothing is uploaded, metrics and "
                   "version check are off. None with a local EVAL_SEMGREP_CONFIG")
    address_space_limit = None  # semgrep-core reserves a large virtual heap; RLIMIT_AS makes it exit 2

    @staticmethod
    def _config() -> str:
        return os.environ.get("EVAL_SEMGREP_CONFIG", "p/default")

    def network_required(self, ctx: AnalyzerContext):
        config = self._config()
        if Path(config).exists():
            return None
        return f"rules {config!r} are fetched from the Semgrep registry; set EVAL_SEMGREP_CONFIG to a local rules path"

    def run(self, ctx: AnalyzerContext):
        config = self._config()
        result = self.run_tool(
            ctx,
            # --disable-nosem: `# nosemgrep` comments in the audited code must not suppress findings.
            ["scan", "--config", config, "--json", "--metrics", "off", "--disable-version-check", "--quiet",
             "--disable-nosem",
             "--timeout", "30", "--max-target-bytes", "2000000", "--exclude", "node_modules", "--exclude", ".venv",
             "."],
            ok_codes=(0, 1),
        )
        return self.parse(ctx, result.stdout)

    def parse(self, ctx: AnalyzerContext, stdout: str):
        try:
            data = json.loads(stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AnalyzerError("could not parse semgrep output") from exc
        findings = []
        for item in data.get("results", [])[:2000]:
            extra = item.get("extra") or {}
            meta = extra.get("metadata") or {}
            check_id = item.get("check_id", "unknown")
            short = check_id.rsplit(".", 1)[-1]
            conf = CONF.get(str(meta.get("confidence", "MEDIUM")).upper(), Confidence.MEDIUM)
            cwe = meta.get("cwe")
            cwe_text = (", ".join(cwe) if isinstance(cwe, list) else str(cwe)) if cwe else ""
            refs = meta.get("references") if isinstance(meta.get("references"), list) else []
            findings.append(
                self.finding(
                    ctx,
                    rule=f"semgrep:{check_id}"[:160],
                    title=f"{short}: {extra.get('message', '')}"[:300],
                    category=_category(meta, check_id),
                    severity=SEV.get(str(extra.get("severity", "INFO")).upper(), Severity.LOW),
                    confidence=conf,
                    kind=FindingKind.CONFIRMED if conf == Confidence.HIGH else FindingKind.POTENTIAL,
                    description=extra.get("message", "") + (f" ({cwe_text})" if cwe_text else ""),
                    remediation=str(meta.get("fix") or extra.get("fix") or "See the rule reference for the fix."),
                    file_path=self.relpath(ctx, item.get("path", "")),
                    line=(item.get("start") or {}).get("line"),
                    line_end=(item.get("end") or {}).get("line"),
                    references=[str(r) for r in refs[:5]],
                )
            )
        return findings
