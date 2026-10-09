"""Stable finding fingerprints.

A fingerprint identifies "the same problem" across audits even when unrelated edits shift line numbers:

    sha256( family_or_rule_id | file_path | normalized_code_line | occurrence_index )

* ``family`` groups equivalent rules from different tools (see ``dedupe.RULE_FAMILIES``).
* ``normalized_code_line`` is the flagged source line with whitespace collapsed (not the line number).
* ``occurrence_index`` disambiguates identical lines in the same file: it is the rank of the line among the
  *distinct line numbers* carrying that key, so two tools flagging the same line share a fingerprint.
Repository-level findings (no file) use the rule and title.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from .findings import Finding

_WS = re.compile(r"\s+")


def normalize_line(text: str) -> str:
    return _WS.sub(" ", text).strip()[:300]


def compute(findings: list[Finding], source_line, family_of) -> None:
    """Assign ``fingerprint`` in place. ``source_line(path, line) -> str`` reads the flagged line."""
    lines_seen: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    ordered = sorted(findings, key=lambda f: (f.file_path, f.line_start or 0, f.rule_id))
    for f in ordered:
        key_rule = family_of(f.rule_id) or f.rule_id
        if f.file_path and f.line_start:
            anchor = normalize_line(source_line(f.file_path, f.line_start) or "")
        else:
            anchor = normalize_line(f.title)
        k = (key_rule, f.file_path, anchor)
        line = f.line_start or 0
        if line not in lines_seen[k]:
            lines_seen[k].append(line)
        idx = lines_seen[k].index(line)
        raw = "|".join((key_rule, f.file_path, anchor, str(idx)))
        f.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
