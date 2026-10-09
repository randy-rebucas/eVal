"""Ruff: Python correctness and maintainability. Runs with ``--isolated`` so repository config is ignored, and
``--ignore-noqa`` so inline suppressions are too."""

from __future__ import annotations

import json

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, AnalyzerError
from .registry import register

# Security rules are left to Bandit (deeper Python security coverage) to avoid double reporting.
SELECT = "F,E9,B,PLE,ASYNC,BLE001,E722"
MEDIUM_CODES = {"F821", "F822", "F823", "F811", "B006", "B008", "B023", "B904", "E722", "BLE001", "PLE"}
HIGH_CODES = {"E999", "syntax-error"}


@register
class RuffAnalyzer(Analyzer):
    name = "ruff"
    title = "Ruff (Python lint)"
    categories = (Category.MAINTAINABILITY,)
    languages = ("python",)
    tool = "ruff"

    def run(self, ctx: AnalyzerContext):
        result = self.run_tool(
            ctx,
            # --ignore-noqa: inline noqa suppressions in the audited code must not hide findings.
            ["check", ".", "--isolated", "--ignore-noqa", "--select", SELECT, "--output-format", "json", "--no-cache",
             "--exit-zero", "--target-version", "py312", "--extend-exclude", ".venv,venv,node_modules,dist,build"],
            ok_codes=(0,),
        )
        try:
            items = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise AnalyzerError("could not parse ruff output") from exc
        findings = []
        for item in items[:2000]:
            code = item.get("code") or "syntax-error"
            path = self.relpath(ctx, item.get("filename", ""))
            line = (item.get("location") or {}).get("row")
            if code in HIGH_CODES or code == "syntax-error":
                sev = Severity.HIGH
            elif code in MEDIUM_CODES or code[:3] in MEDIUM_CODES:
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW
            findings.append(
                self.finding(
                    ctx,
                    rule=f"ruff:{code}",
                    title=f"{code}: {item.get('message', '')}"[:300],
                    category=Category.MAINTAINABILITY,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    kind=FindingKind.CONFIRMED,
                    description=f"Ruff rule {code} reported: {item.get('message', '')}",
                    remediation="Apply the fix described in the rule documentation."
                    + (" Ruff can fix this automatically (`ruff check --fix`)." if item.get("fix") else ""),
                    file_path=path,
                    line=line,
                    references=[item["url"]] if item.get("url") else [],
                )
            )
        return findings
