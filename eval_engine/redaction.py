"""Secret redaction for logs, persisted evidence, and AI prompts.

Patterns are deliberately conservative toward over-redaction: leaking a secret into a log or an AI
provider is worse than masking a harmless string.
"""

from __future__ import annotations

import logging
import re

REDACTED = "[REDACTED]"

# (name, pattern). Each pattern's full match is replaced; group "keep" (if present) is preserved.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")),
    # An excerpt can start inside a PEM block, after its BEGIN line: mask bare base64 key-body lines too.
    ("pem_body", re.compile(r"^(?P<keep>[ \t]*(?:\d+ \| )?[ \t]*[\"']?)[A-Za-z0-9+/]{60,}={0,2}(?=[\"',]*[ \t]*$)",
                            re.M)),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("url_credentials", re.compile(r"(?P<keep>[a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s:/@]+:[^\s@/]+@")),
    (
        "assignment",
        re.compile(
            r"(?P<keep>(?i:[\w.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|"
            r"private[_\-]?key|client[_\-]?secret)[\w.\-]*)\s*[:=]\s*[\"']?)"
            r"(?!(?:os\.|process\.env|getenv|environ|config|settings|self\.|request\.|None\b|null\b|"
            r"True\b|False\b|\$\{|\{\{|<|\[REDACTED\]))"
            r"[^\s\"',;()]{4,}"
        ),
    ),
]


# Patterns that are deliberately broad: used to mask text, never as evidence that a secret was found.
REDACT_ONLY = frozenset({"assignment", "pem_body"})


def redact(text: str) -> str:
    if not text:
        return text
    out = text
    for _name, pattern in SECRET_PATTERNS:
        out = pattern.sub(lambda m: (m.groupdict().get("keep") or "") + REDACTED, out)
    return out


def contains_secret(text: str) -> bool:
    return any(p.search(text) for _n, p in SECRET_PATTERNS if _n not in REDACT_ONLY) if text else False


class RedactingFilter(logging.Filter):
    """Logging filter that redacts the fully formatted message."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - never break logging
            return True
        redacted = redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True
