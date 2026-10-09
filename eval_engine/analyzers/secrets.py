"""Hardcoded secret detection (provider token formats, private keys, credential assignments, committed .env)."""

from __future__ import annotations

import math
import re

from ..findings import Category, Confidence, FindingKind, Severity
from ..redaction import REDACT_ONLY, SECRET_PATTERNS
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

TEXT_SUFFIXES = (
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".rb", ".java", ".kt", ".cs", ".php", ".rs",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties", ".xml", ".tf", ".sh",
    ".bash", ".ps1", ".txt", ".md", ".dockerfile", ".gradle", ".swift", ".scala",
)
PROVIDER_PATTERNS = [(n, p) for n, p in SECRET_PATTERNS if n not in REDACT_ONLY | {"url_credentials"}]
ASSIGNMENT = re.compile(
    r"""(?ix)
    (?:(?<=\\[nrt])|(?<![\w\\]))(?P<name>[A-Za-z_][\w.-]*?(?:password|passwd|pwd|secret|api_?key|apikey|access_?key|auth_?token|
       private_?key|client_?secret|token))\b
    ["']?\s*(?::=|=|:|=>)\s*
    (?P<q>["'`])(?P<value>[^"'`\s]{8,200})(?P=q)
    """
)
URL_CREDS = re.compile(r"\b[a-z][a-z0-9+.\-]*://(?P<user>[^\s:/@'\"]+):(?P<pw>[^\s@/'\"]{3,})@[^\s'\"]+", re.I)
PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.+|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|changeme|change_me|example|placeholder|dummy|test|"
    r"your[_-]?.*|redacted|null|none|undefined|password|secret|todo|fixme|replace[_-]?me|xxx.*|sample.*)$"
)
# Lower-case words joined by - or _ (e.g. "hardcoded-secret", "client_credentials") are identifiers or labels,
# not credentials.
WORD_SLUG = re.compile(r"^[a-z]+(?:[-_][a-z]+)+$")
ENV_FILE = re.compile(r"(^|/)\.env(\.[A-Za-z0-9_-]+)?$")
ENV_SAFE_SUFFIX = (".example", ".sample", ".template", ".dist", ".defaults", ".test")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _looks_real(value: str) -> bool:
    if PLACEHOLDER.match(value) or WORD_SLUG.match(value):
        return False
    if value.startswith(("http://", "https://", "/", "./", "$", "%", "{")):
        return False
    return shannon_entropy(value) >= 3.0 and len(set(value)) >= 6


@register
class SecretsAnalyzer(Analyzer):
    name = "secrets"
    title = "Hardcoded secrets"
    categories = (Category.SECURITY,)

    def run(self, ctx: AnalyzerContext):
        findings = []
        for rel in ctx.files:
            name = rel.rsplit("/", 1)[-1]
            if ENV_FILE.search(rel) and not rel.endswith(ENV_SAFE_SUFFIX):
                findings.append(
                    self.finding(
                        ctx,
                        rule="secrets.env-file-committed",
                        title=f"Environment file committed: {name}",
                        category=Category.SECURITY,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        kind=FindingKind.CONFIRMED,
                        description="A .env file is checked into the repository. These usually hold real "
                        "credentials and are easily leaked through forks, CI logs, and archives.",
                        remediation="Remove the file from the repository and its history, add it to .gitignore, "
                        "commit a .env.example with placeholders, and rotate any secrets it contained.",
                        file_path=rel,
                        evidence=f"{rel} is present in the repository",
                    )
                )
            if not (rel.lower().endswith(TEXT_SUFFIXES) or name.startswith((".env", "Dockerfile"))):
                continue
            if name.endswith((".lock", "-lock.json", ".min.js")) or name == "package-lock.json":
                continue
            findings.extend(self._scan_file(ctx, rel))
        return findings

    def _scan_file(self, ctx: AnalyzerContext, rel: str):
        out = []
        in_tests = is_test_path(rel)
        for lineno, line in enumerate(ctx.lines(rel), start=1):
            if len(line) > 2000:
                continue
            for pname, pattern in PROVIDER_PATTERNS:
                if pattern.search(line):
                    out.append(self._secret(ctx, rel, lineno, f"secrets.{pname.replace('_', '-')}",
                                            f"Hardcoded {pname.replace('_', ' ')}", in_tests, provider=True))
                    break
            else:
                m = ASSIGNMENT.search(line)
                if m and _looks_real(m.group("value")):
                    out.append(self._secret(ctx, rel, lineno, "secrets.hardcoded-credential",
                                            f"Hardcoded credential assigned to '{m.group('name')}'", in_tests))
                    continue
                u = URL_CREDS.search(line)
                if u and not PLACEHOLDER.match(u.group("pw")) and u.group("pw") not in ("password", "pass"):
                    out.append(self._secret(ctx, rel, lineno, "secrets.credentials-in-url",
                                            "Credentials embedded in a connection URL", in_tests))
        return out

    def _secret(self, ctx, rel, line, rule, title, in_tests, provider=False):
        if provider:
            sev = Severity.MEDIUM if in_tests else Severity.CRITICAL
            conf = Confidence.HIGH
        else:
            sev = Severity.LOW if in_tests else Severity.HIGH
            conf = Confidence.MEDIUM
        return self.finding(
            ctx,
            rule=rule,
            title=title + (" (test code)" if in_tests else ""),
            category=Category.SECURITY,
            severity=sev,
            confidence=conf,
            kind=FindingKind.CONFIRMED if provider else FindingKind.POTENTIAL,
            description=(
                "A value matching a known credential format is committed to source control."
                if provider else
                "A high-entropy literal is assigned to a credential-like name. If it is a real secret, anyone "
                "with repository access can use it."
            ),
            remediation="Revoke and rotate the credential, remove it from git history, and load it at runtime "
            "from environment variables or a secrets manager.",
            file_path=rel,
            line=line,
            references=["https://cwe.mitre.org/data/definitions/798.html"],
        )
