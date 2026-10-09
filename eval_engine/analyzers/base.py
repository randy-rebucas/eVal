"""Analyzer interface. Analyzers are static: they read files or run allow-listed tools, never repository code."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from ..findings import Category, Confidence, Finding, FindingKind, Severity
from ..languages import LanguageReport
from ..redaction import redact
from ..workspace import read_text

MAX_EVIDENCE_CHARS = 800


_TEST_DIRS = {"tests", "test", "__tests__", "spec", "specs", "testing", "fixtures", "e2e"}


def is_test_path(path: str) -> bool:
    parts = path.lower().split("/")
    name = parts[-1]
    return (
        any(p in _TEST_DIRS for p in parts[:-1])
        or name.startswith("test_")
        or name.endswith(("_test.py", "_test.go", "conftest.py"))
        or ".test." in name
        or ".spec." in name
    )


class AnalyzerError(Exception):
    """Analyzer could not complete; message is shown to users (keep it free of secrets/paths)."""


class ToolTimeout(AnalyzerError):
    pass


@dataclass
class AnalyzerContext:
    root: Path
    files: list[str]
    languages: LanguageReport
    timeout: int = 300
    _cache: dict[str, str | None] = field(default_factory=dict, repr=False)
    _file_set: set[str] = field(init=False, repr=False)
    _ast_cache: dict = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._file_set = set(self.files)

    def read(self, rel: str) -> str | None:
        if rel not in self._cache:
            self._cache[rel] = read_text(self.root, rel)
        return self._cache[rel]

    def python_ast(self, rel: str):
        """Parse (never import or execute) a Python file. Returns None on syntax errors or huge files."""
        import ast
        import warnings

        if rel not in self._ast_cache:
            text = self.read(rel)
            tree = None
            if text is not None and len(text) < 1_500_000:
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        tree = ast.parse(text, filename=rel)
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    tree = None
            self._ast_cache[rel] = tree
        return self._ast_cache[rel]

    def python_files(self) -> list[str]:
        return self.files_with_suffix(".py")

    def lines(self, rel: str) -> list[str]:
        text = self.read(rel)
        return text.splitlines() if text else []

    def files_with_suffix(self, *suffixes: str) -> list[str]:
        lowered = tuple(s.lower() for s in suffixes)
        return [f for f in self.files if f.lower().endswith(lowered)]

    def files_named(self, *names: str) -> list[str]:
        return [f for f in self.files if f.rsplit("/", 1)[-1] in names]

    def exists(self, rel: str) -> bool:
        return rel in self._file_set

    def snippet(self, rel: str, line: int | None, context: int = 2) -> str:
        """Redacted source excerpt around ``line`` (1-based) with line numbers."""
        lines = self.lines(rel)
        if not lines or not line or line < 1 or line > len(lines):
            return ""
        start, end = max(1, line - context), min(len(lines), line + context)
        width = len(str(end))
        out = "\n".join(f"{n:>{width}} | {lines[n - 1][:240]}" for n in range(start, end + 1))
        return redact(out)[:MAX_EVIDENCE_CHARS]


@dataclass
class AnalyzerOutcome:
    name: str
    title: str
    status: str  # ok | skipped | failed | timeout
    reason: str = ""
    findings: list[Finding] = field(default_factory=list)
    duration: float = 0.0
    categories: list[str] = field(default_factory=list)
    tool: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "status": self.status,
            "reason": self.reason,
            "findings": len(self.findings),
            "duration": round(self.duration, 2),
            "categories": self.categories,
            "tool": self.tool,
        }


class Analyzer:
    name: ClassVar[str]
    title: ClassVar[str]
    categories: ClassVar[tuple[Category, ...]]
    languages: ClassVar[tuple[str, ...]] = ()  # empty = language-agnostic
    tool: ClassVar[str | None] = None  # external executable required (see sandbox.ALLOWED_TOOLS)

    def applicable(self, ctx: AnalyzerContext) -> str | None:
        """Return None when the analyzer should run, else a human-readable reason to skip."""
        if self.languages and not any(ctx.languages.has(lang) for lang in self.languages):
            return f"no {'/'.join(self.languages)} files detected"
        return None

    def run(self, ctx: AnalyzerContext) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    # ------------------------------------------------------------------ helpers for subclasses
    def finding(
        self,
        ctx: AnalyzerContext,
        *,
        rule: str,
        title: str,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        kind: FindingKind,
        description: str,
        remediation: str,
        file_path: str = "",
        line: int | None = None,
        line_end: int | None = None,
        evidence: str | None = None,
        references: list[str] | None = None,
    ) -> Finding:
        rule_id = rule if ":" in rule else f"{self.rule_prefix}:{rule}"
        if evidence is None:
            evidence = ctx.snippet(file_path, line) if file_path and line else ""
        return Finding(
            rule_id=rule_id,
            title=title[:300],
            category=category,
            severity=severity,
            confidence=confidence,
            kind=kind,
            description=description,
            remediation=remediation,
            file_path=file_path,
            line_start=line,
            line_end=line_end or line,
            evidence=redact(evidence)[:MAX_EVIDENCE_CHARS],
            references=references or [],
            sources=[self.name],
        )

    @property
    def rule_prefix(self) -> str:
        return "eval" if self.tool is None else self.tool

    def run_tool(self, ctx: AnalyzerContext, args: list[str], ok_codes: tuple[int, ...] = (0, 1)):
        """Run this analyzer's external tool in the sandbox, from the repository root."""
        from .. import sandbox

        if self.tool is None:
            raise AnalyzerError(f"{self.name} does not declare an external tool")
        result = sandbox.run(self.tool, args, cwd=ctx.root, timeout=ctx.timeout)
        if result.timed_out:
            raise ToolTimeout(f"{self.tool} exceeded the {ctx.timeout}s time limit")
        if result.returncode not in ok_codes:
            first = (result.stderr.strip().splitlines() or [""])[-1][:200]
            raise AnalyzerError(f"{self.tool} exited with code {result.returncode}: {redact(first)}")
        if result.truncated:
            raise AnalyzerError(f"{self.tool} produced more output than the capture limit")
        return result

    @staticmethod
    def relpath(ctx: AnalyzerContext, path: str) -> str:
        """Normalize a tool-reported path (absolute or ./relative) to a repo-relative POSIX path."""
        p = path.replace("\\", "/")
        root = str(ctx.root.resolve()).replace("\\", "/").rstrip("/") + "/"
        if p.lower().startswith(root.lower()):
            p = p[len(root):]
        while p.startswith("./"):
            p = p[2:]
        return p
