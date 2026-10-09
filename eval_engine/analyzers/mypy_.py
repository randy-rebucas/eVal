"""mypy type checking.

Security: mypy config files can declare *plugins*, which are Python modules mypy imports — i.e. code
execution. eVal therefore always passes its own empty ``--config-file`` so repository config is ignored.
Dependencies are not installed, so missing-import errors are suppressed and results are type-level hints,
reported as potential issues.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext
from .registry import register

MEDIUM_CODES = {"attr-defined", "call-arg", "arg-type", "union-attr", "index", "return-value",
                "operator", "call-overload", "misc"}
# name-defined: with dependencies uninstalled, dynamic bases such as `db.Model` are reported as undefined.
# Genuinely undefined names are already reported by Ruff (F821), so this code is dropped as noise.
# import-not-found / import-untyped: expected without installed dependencies.
IGNORED_CODES = {"name-defined", "import-not-found", "import-untyped", "import"}
MAX_FINDINGS = 300


@register
class MypyAnalyzer(Analyzer):
    name = "mypy"
    title = "mypy (Python types)"
    categories = (Category.MAINTAINABILITY,)
    languages = ("python",)
    tool = "mypy"

    def run(self, ctx: AnalyzerContext):
        targets = [f for f in ctx.files_with_suffix(".py") if "/site-packages/" not in f][:3000]
        if not targets:
            return []
        with tempfile.TemporaryDirectory(prefix="eval-mypy-") as tmp:
            cfg = Path(tmp) / "mypy.ini"
            cfg.write_text("[mypy]\n", encoding="utf-8")
            listing = Path(tmp) / "files.txt"
            listing.write_text("\n".join(targets), encoding="utf-8")
            result = self.run_tool(
                ctx,
                ["--config-file", str(cfg), "--no-site-packages", "--ignore-missing-imports", "--follow-imports=silent",
                 "--no-incremental", "--cache-dir", str(Path(tmp) / "cache"), "--show-error-codes",
                 "--no-error-summary", "--output", "json", "--explicit-package-bases", *targets],
                ok_codes=(0, 1, 2),
            )
        findings = []
        for raw in result.stdout.splitlines():
            if len(findings) >= MAX_FINDINGS:
                break
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if item.get("severity") != "error":
                continue
            code = item.get("code") or "error"
            if code in IGNORED_CODES or (item.get("line") or 0) < 1:
                continue
            path = self.relpath(ctx, item.get("file", ""))
            findings.append(
                self.finding(
                    ctx,
                    rule=f"mypy:{code}",
                    title=f"Type error [{code}]: {item.get('message', '')}"[:300],
                    category=Category.MAINTAINABILITY,
                    severity=Severity.MEDIUM if code in MEDIUM_CODES else Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL,
                    description=(item.get("message", "") + (f" Hint: {item['hint']}" if item.get("hint") else "")
                                 + " (Checked without installed dependencies; third-party types are unknown.)"),
                    remediation="Fix the type mismatch or add precise annotations; consider running mypy in CI.",
                    file_path=path,
                    line=item.get("line"),
                )
            )
        return findings
