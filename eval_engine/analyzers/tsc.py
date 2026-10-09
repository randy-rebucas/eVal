"""TypeScript compiler checks (``tsc --noEmit``). Dependencies are not installed, so module-resolution
errors are filtered out and the remaining type errors are reported as potential issues."""

from __future__ import annotations

import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext
from .registry import register

LINE_RE = re.compile(r"^(?P<file>.+?)\((?P<line>\d+),(?P<col>\d+)\): error (?P<code>TS\d+): (?P<msg>.*)$")
# Cannot find module / declaration file / JSX runtime / lib types – artefacts of uninstalled dependencies.
IGNORED = {"TS2307", "TS2792", "TS7016", "TS2875", "TS2688", "TS6053", "TS2503", "TS7026", "TS2580", "TS2584",
           "TS2304", "TS2591", "TS5083", "TS6046", "TS5023", "TS18003"}
MAX_FINDINGS = 300


@register
class TscAnalyzer(Analyzer):
    name = "tsc"
    title = "TypeScript compiler"
    categories = (Category.MAINTAINABILITY,)
    languages = ("typescript",)
    tool = "tsc"

    def applicable(self, ctx: AnalyzerContext):
        reason = super().applicable(ctx)
        if reason:
            return reason
        if not ctx.exists("tsconfig.json"):
            return "no root tsconfig.json"
        return None

    def run(self, ctx: AnalyzerContext):
        result = self.run_tool(ctx, ["--noEmit", "--pretty", "false", "-p", "tsconfig.json"], ok_codes=(0, 1, 2))
        findings = []
        for raw in result.stdout.splitlines():
            m = LINE_RE.match(raw.strip())
            if not m or m.group("code") in IGNORED:
                continue
            if len(findings) >= MAX_FINDINGS:
                break
            path = self.relpath(ctx, m.group("file"))
            findings.append(
                self.finding(
                    ctx,
                    rule=f"tsc:{m.group('code')}",
                    title=f"{m.group('code')}: {m.group('msg')}"[:300],
                    category=Category.MAINTAINABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL,
                    description=m.group("msg") + " (Checked without installed dependencies.)",
                    remediation="Fix the type error; run `tsc --noEmit` in CI to keep the build type-safe.",
                    file_path=path,
                    line=int(m.group("line")),
                )
            )
        return findings
