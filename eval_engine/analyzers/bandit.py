"""Bandit: Python security linter (AST-based, never imports the audited code)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, AnalyzerError, is_test_path
from .registry import register

SEV = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
CONF = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}
EXCLUDE = "./.venv,./venv,./node_modules,./build,./dist,./.tox"
# Bandit matches patterns; it does not trace data. A match is reported as confirmed only where the matched code is
# itself the weakness whatever the input (debugger on, TLS checks off, weak key sizes). Everything else, e.g.
# shell=True, pickle.loads, string-built SQL or a bare "import subprocess", needs attacker-controlled input to be
# exploitable, so it stays potential unless eVal's taint analysis traces such input to the same line.
CONFIRMED_TESTS = {"B201", "B501", "B502", "B503", "B504", "B505", "B507", "B413"}

REMEDIATION = {
    "B105": "Load the secret from the environment or a secrets manager; rotate the exposed value.",
    "B106": "Load the secret from the environment or a secrets manager; rotate the exposed value.",
    "B107": "Do not use secrets as default argument values; inject them from configuration.",
    "B201": "Never enable the Flask debugger outside local development (it allows remote code execution).",
    "B301": "Do not unpickle untrusted data; use JSON or a schema-validated format.",
    "B324": "Use SHA-256 or better; for passwords use a password hashing function (scrypt/argon2/bcrypt).",
    "B501": "Keep TLS certificate verification enabled.",
    "B506": "Use yaml.safe_load().",
    "B602": "Pass an argument list with shell=False and validate inputs.",
    "B608": "Use parameterized queries / bound parameters instead of string-built SQL.",
    "B113": "Always pass a timeout to outbound HTTP requests.",
}


@register
class BanditAnalyzer(Analyzer):
    name = "bandit"
    title = "Bandit (Python security)"
    categories = (Category.SECURITY,)
    languages = ("python",)
    tool = "bandit"

    def run(self, ctx: AnalyzerContext):
        # With -r, Bandit loads a repository .bandit file (skips/excludes) unless --ini names another, and it
        # honours inline nosec suppressions. eVal's empty ini plus --ignore-nosec stop a repository hiding findings.
        with tempfile.TemporaryDirectory(prefix="eval-bandit-") as tmp:
            ini = Path(tmp) / "bandit.ini"
            ini.write_text("[bandit]\n", encoding="utf-8")
            result = self.run_tool(
                ctx,
                ["-r", ".", "--ini", str(ini), "--ignore-nosec", "-f", "json", "-q", "-x", EXCLUDE, "-s", "B101",
                 "--exit-zero"],
                ok_codes=(0,),
            )
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AnalyzerError("could not parse bandit output") from exc
        findings = []
        for item in data.get("results", [])[:2000]:
            test_id = item.get("test_id", "B000")
            path = self.relpath(ctx, item.get("filename", ""))
            sev = SEV.get(item.get("issue_severity", "LOW"), Severity.LOW)
            conf = CONF.get(item.get("issue_confidence", "LOW"), Confidence.LOW)
            in_tests = is_test_path(path)
            if in_tests and sev != Severity.LOW:
                sev = Severity.LOW  # still reported: test code ships secrets and bad patterns too
            cwe = item.get("issue_cwe") or {}
            refs = [r for r in (item.get("more_info"), cwe.get("link")) if r]
            findings.append(
                self.finding(
                    ctx,
                    rule=f"bandit:{test_id}",
                    title=f"{item.get('test_name', test_id).replace('_', ' ')}: {item.get('issue_text', '')}"[:300],
                    category=Category.SECURITY,
                    severity=sev,
                    confidence=conf,
                    kind=FindingKind.CONFIRMED if conf == Confidence.HIGH and test_id in CONFIRMED_TESTS
                    else FindingKind.POTENTIAL,
                    description=(item.get("issue_text", "") + (f" (CWE-{cwe['id']})" if cwe.get("id") else "")
                                 + (" Found in test code; severity reduced." if in_tests else "")),
                    remediation=REMEDIATION.get(test_id, "Review the flagged code; see the Bandit reference."),
                    file_path=path,
                    line=item.get("line_number"),
                    line_end=max(item.get("line_range") or [item.get("line_number") or 0]) or None,
                    references=refs,
                )
            )
        return findings
