"""AI-generated fixes for detected findings, as exact find/replace edits.

Unlike explanations, a fix needs the code it changes, so excerpts of the affected files are sent. Safety
properties:
* Only files that carry a selected finding are read, and large files are cut to windows around the findings.
* Secrets in the excerpts are replaced by numbered placeholders (``__EVAL_SECRET_1__``) before sending and
  restored only inside edits that copy them back verbatim; the model never sees them.
* Repository text is wrapped in ``<untrusted_repository_content>`` and the prompt forbids following it.
* Each edit's ``find`` text must occur exactly once in the current file, or the edit is rejected; edits can
  only touch files that were sent. Nothing is applied to a repository here: the caller turns the result into a
  diff for a person to review before any pull request is opened.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..redaction import REDACTED, SECRET_PATTERNS
from .base import AIError, AIOutputError, AIProvider
from .enrich import DELIM, load_prompt

FIX_PROMPT_VERSION = "v1"
MAX_FINDINGS = 10
MAX_FILES = 5
WHOLE_FILE_LINES = 400  # files up to this many lines are sent whole; longer ones as windows around findings
WINDOW = 40
PLACEHOLDER_RE = re.compile(r"__EVAL_SECRET_(\d+)__")

FIX_SCHEMA = {
    "type": "object",
    "properties": {
        "fixes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "summary": {"type": "string"},
                    "edits": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {"type": "string"},
                                "find": {"type": "string"},
                                "replace": {"type": "string"},
                            },
                            "required": ["file", "find", "replace"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["id", "summary", "edits"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["fixes"],
    "additionalProperties": False,
}


@dataclass
class FixTarget:
    """A finding to fix: ``id`` is opaque to the model (e.g. the database id)."""

    id: str
    rule_id: str
    title: str
    severity: str
    description: str
    remediation: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None


@dataclass
class FixResult:
    files: dict[str, str] = field(default_factory=dict)  # path -> new content (only changed files)
    fixed: list[dict] = field(default_factory=list)  # {"id", "summary", "edits"}
    failed: list[dict] = field(default_factory=list)  # {"id", "reason"}
    provider: str = ""
    model: str = ""


class SecretMask:
    """Swap secrets for numbered placeholders, and back."""

    def __init__(self):
        self.values: list[str] = []

    def mask(self, text: str) -> str:
        for _name, pattern in SECRET_PATTERNS:
            text = pattern.sub(self._sub, text)
        return text

    def _sub(self, m: re.Match) -> str:
        keep = m.groupdict().get("keep") or ""
        secret = m.group(0)[len(keep):]
        if PLACEHOLDER_RE.fullmatch(secret) or secret == REDACTED:
            return m.group(0)
        if secret not in self.values:
            self.values.append(secret)
        return f"{keep}__EVAL_SECRET_{self.values.index(secret) + 1}__"

    def unmask(self, text: str) -> str:
        def back(m: re.Match) -> str:
            i = int(m.group(1)) - 1
            if not 0 <= i < len(self.values):
                raise ValueError("unknown secret placeholder")
            return self.values[i]

        return PLACEHOLDER_RE.sub(back, text)


def excerpt(content: str, lines: list[tuple[int | None, int | None]]) -> list[dict]:
    """The whole file when short, else merged windows around the finding lines."""
    all_lines = content.splitlines(keepends=True)
    if len(all_lines) <= WHOLE_FILE_LINES or not any(start for start, _ in lines):
        return [{"lines": f"1-{len(all_lines)}", "text": content[:200_000]}]
    spans = sorted((max(1, s - WINDOW), min(len(all_lines), (e or s) + WINDOW)) for s, e in lines if s)
    merged: list[list[int]] = []
    for s, e in spans:
        if merged and s <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return [{"lines": f"{s}-{e}", "text": "".join(all_lines[s - 1:e])} for s, e in merged]


def _neutralize(text: str) -> str:
    return text.replace(f"</{DELIM}", f"</{DELIM}_").replace(f"<{DELIM}", f"<{DELIM}_")


def build_request(targets: list[FixTarget], sources: dict[str, str], mask: SecretMask) -> str:
    by_file: dict[str, list[FixTarget]] = {}
    for t in targets:
        by_file.setdefault(t.file_path, []).append(t)
    files = [{"file": path, "excerpts": [{"lines": x["lines"], "text": _neutralize(mask.mask(x["text"]))}
                                         for x in excerpt(sources[path], [(t.line_start, t.line_end) for t in ts])]}
             for path, ts in by_file.items()]
    findings = [{"id": t.id, "rule": t.rule_id, "severity": t.severity, "title": _neutralize(mask.mask(t.title)),
                 "location": f"{t.file_path}:{t.line_start}" if t.line_start else t.file_path,
                 "description": _neutralize(mask.mask(t.description))[:800],
                 "recommended_remediation": _neutralize(mask.mask(t.remediation))[:600]} for t in targets]
    return load_prompt("fix").format(findings=json.dumps(findings, indent=1), files=json.dumps(files, indent=1))


def apply_edits(data: dict, targets: list[FixTarget], sources: dict[str, str], mask: SecretMask) -> FixResult:
    """Validate the model's answer and apply each finding's edits all-or-nothing."""
    items = data.get("fixes") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise AIOutputError("AI response did not match the expected schema.")
    known = {t.id for t in targets}
    current = dict(sources)
    result = FixResult()
    seen: set[str] = set()
    for item in items[: len(targets) * 2]:
        if not isinstance(item, dict) or item.get("id") not in known or item["id"] in seen:
            continue
        fid = item["id"]
        seen.add(fid)
        summary = str(item.get("summary") or "")[:1000].strip()
        edits = item.get("edits") if isinstance(item.get("edits"), list) else []
        if not edits:
            result.failed.append({"id": fid, "reason": summary or "The model proposed no change."})
            continue
        staged = dict(current)
        applied, reason = [], ""
        for edit in edits[:20]:
            path = edit.get("file") if isinstance(edit, dict) else None
            if path not in staged:
                reason = "an edit targeted a file that was not provided"
                break
            try:
                find, replace = mask.unmask(str(edit.get("find") or "")), mask.unmask(str(edit.get("replace") or ""))
            except ValueError:
                reason = "an edit referenced an unknown secret placeholder"
                break
            if not find.strip():
                reason = "an edit had empty search text"
                break
            count = staged[path].count(find)
            if count != 1:
                reason = "the code to change was not found" if count == 0 else "the code to change is ambiguous"
                break
            staged[path] = staged[path].replace(find, replace, 1)
            applied.append(path)
        if reason:
            result.failed.append({"id": fid, "reason": f"Not applied: {reason}."})
            continue
        if all(staged[p] == current[p] for p in set(applied)):
            result.failed.append({"id": fid, "reason": "The proposed edits did not change anything."})
            continue
        current = staged
        result.fixed.append({"id": fid, "summary": summary, "files": sorted(set(applied))})
    for t in targets:
        if t.id not in seen:
            result.failed.append({"id": t.id, "reason": "The model did not return a fix."})
    result.files = {p: c for p, c in current.items() if c != sources[p]}
    return result


def generate_fixes(provider: AIProvider, targets: list[FixTarget], sources: dict[str, str],
                   max_tokens: int = 32000, output_retries: int = 1) -> FixResult:
    """Ask ``provider`` for fixes to ``targets``; ``sources`` maps each target's file path to its content."""
    targets = [t for t in targets if t.file_path in sources][:MAX_FINDINGS]
    if not targets:
        raise AIError("None of the selected findings point at a readable source file.")
    mask = SecretMask()
    user = build_request(targets, sources, mask)
    for attempt in range(output_retries + 1):
        try:
            data = provider.complete_json(system=load_prompt("fix_system"), user=user, schema=FIX_SCHEMA,
                                          max_tokens=max_tokens)
            result = apply_edits(data, targets, sources, mask)
            break
        except AIOutputError:
            if attempt == output_retries:
                raise
    result.provider, result.model = provider.info.name, provider.info.model
    return result
