"""ESLint for JavaScript.

Security: ``eslint.config.js`` is executable JavaScript, and plugins are code. eVal never loads repository
config; it runs ESLint with its own static config from a temporary directory and no plugins. Only plain
JavaScript is linted here (TypeScript type checks come from the ``tsc`` analyzer).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, AnalyzerError
from .registry import register

SECURITY_RULES = {"no-eval", "no-implied-eval", "no-new-func", "no-script-url"}
CONFIG = """export default [
  { ignores: ["**/node_modules/**", "**/dist/**", "**/build/**", "**/.next/**", "**/coverage/**", "**/*.min.js",
              "**/vendor/**"] },
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.jsx"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module",
                       parserOptions: { ecmaFeatures: { jsx: true } } },
    linterOptions: { noInlineConfig: true, reportUnusedDisableDirectives: "off" },
    rules: {
      "no-eval": "error", "no-implied-eval": "error", "no-new-func": "error", "no-script-url": "error",
      "no-debugger": "error", "no-unreachable": "error", "no-dupe-keys": "error", "no-dupe-else-if": "error",
      "no-unsafe-finally": "error", "no-unsafe-negation": "error", "no-self-assign": "error",
      "no-cond-assign": "error", "no-constant-condition": "warn", "no-unused-vars": "warn",
      "no-empty": "warn", "eqeqeq": ["warn", "smart"], "no-prototype-builtins": "warn",
      "no-async-promise-executor": "error", "require-atomic-updates": "off"
    }
  }
];
"""


@register
class ESLintAnalyzer(Analyzer):
    name = "eslint"
    title = "ESLint (JavaScript)"
    categories = (Category.MAINTAINABILITY, Category.SECURITY)
    languages = ("javascript",)
    tool = "eslint"

    def run(self, ctx: AnalyzerContext):
        with tempfile.TemporaryDirectory(prefix="eval-eslint-") as tmp:
            cfg = Path(tmp) / "eslint.config.mjs"
            cfg.write_text(CONFIG, encoding="utf-8")
            result = self.run_tool(
                ctx,
                ["--config", str(cfg), "--format", "json", "--no-warn-ignored", "."],
                ok_codes=(0, 1),
            )
        try:
            files = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise AnalyzerError("could not parse eslint output") from exc
        findings = []
        for entry in files:
            path = self.relpath(ctx, entry.get("filePath", ""))
            for msg in entry.get("messages", [])[:200]:
                rule = msg.get("ruleId") or "parse-error"
                security = rule in SECURITY_RULES
                if rule == "parse-error":
                    sev = Severity.LOW
                elif security:
                    sev = Severity.HIGH
                else:
                    sev = Severity.MEDIUM if msg.get("severity") == 2 else Severity.LOW
                findings.append(
                    self.finding(
                        ctx,
                        rule=f"eslint:{rule}",
                        title=f"{rule}: {msg.get('message', '')}"[:300],
                        category=Category.SECURITY if security else Category.MAINTAINABILITY,
                        severity=sev,
                        confidence=Confidence.HIGH if rule != "parse-error" else Confidence.LOW,
                        kind=FindingKind.CONFIRMED if rule != "parse-error" else FindingKind.POTENTIAL,
                        description=msg.get("message", ""),
                        remediation=(
                            "Remove dynamic code evaluation; use explicit functions or a safe parser."
                            if security else "Fix the reported lint issue."
                        ),
                        file_path=path,
                        line=msg.get("line"),
                        references=[f"https://eslint.org/docs/latest/rules/{rule}"] if rule != "parse-error" else [],
                    )
                )
        return findings
