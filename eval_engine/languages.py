"""Language and framework detection from file extensions and dependency manifests (never by executing code)."""

from __future__ import annotations

import json
import re
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .workspace import read_text

EXTENSIONS = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".go": "go", ".rb": "ruby", ".java": "java", ".kt": "kotlin", ".cs": "csharp", ".php": "php",
    ".rs": "rust", ".swift": "swift", ".scala": "scala", ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp",
    ".sql": "sql", ".sh": "shell", ".bash": "shell", ".tf": "terraform", ".html": "html", ".css": "css",
    ".vue": "vue", ".svelte": "svelte", ".dart": "dart", ".ex": "elixir", ".exs": "elixir",
}
CODE_LANGUAGES = {
    "python", "javascript", "typescript", "go", "ruby", "java", "kotlin", "csharp", "php", "rust", "swift",
    "scala", "c", "cpp", "dart", "elixir", "vue", "svelte",
}

PY_FRAMEWORKS: dict[str, tuple[str, ...]] = {
    "flask": ("flask",), "django": ("django",), "fastapi": ("fastapi",), "sqlalchemy": ("sqlalchemy",),
    "celery": ("celery",), "starlette": ("starlette",), "pydantic": ("pydantic",), "pytest": ("pytest",),
    "flask-sqlalchemy": ("flask", "sqlalchemy"), "flask-login": ("flask",), "flask-restful": ("flask",),
    "sqlmodel": ("sqlalchemy", "pydantic"), "djangorestframework": ("django",), "alembic": ("sqlalchemy",),
}
JS_FRAMEWORKS = {
    "express": "express", "next": "nextjs", "react": "react", "vue": "vue", "@nestjs/core": "nestjs",
    "fastify": "fastify", "koa": "koa", "prisma": "prisma", "@prisma/client": "prisma", "sequelize": "sequelize",
    "typeorm": "typeorm", "mongoose": "mongoose", "jest": "jest", "vitest": "vitest", "mocha": "mocha",
    "svelte": "svelte", "@angular/core": "angular",
}
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


@dataclass
class LanguageReport:
    files_by_language: dict[str, int] = field(default_factory=dict)
    lines_by_language: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    total_files: int = 0

    @property
    def primary(self) -> str | None:
        code = {k: v for k, v in self.lines_by_language.items() if k in CODE_LANGUAGES}
        return max(code, key=code.get) if code else None

    def has(self, language: str) -> bool:
        return self.files_by_language.get(language, 0) > 0

    def to_dict(self) -> dict:
        return {
            "files_by_language": self.files_by_language,
            "lines_by_language": self.lines_by_language,
            "frameworks": self.frameworks,
            "manifests": self.manifests,
            "total_files": self.total_files,
            "primary": self.primary,
        }


MANIFESTS = (
    "package.json", "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "Pipfile", "poetry.lock",
    "go.mod", "Gemfile", "pom.xml", "build.gradle", "build.gradle.kts", "Cargo.toml", "composer.json",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "uv.lock",
)


def detect(root: Path, files: list[str]) -> LanguageReport:
    files_count: Counter[str] = Counter()
    lines: Counter[str] = Counter()
    manifests = []
    for rel in files:
        name = rel.rsplit("/", 1)[-1]
        if name in MANIFESTS or name.startswith("requirements") and name.endswith(".txt"):
            manifests.append(rel)
        lang = EXTENSIONS.get(Path(name).suffix.lower())
        if lang is None:
            if name == "Dockerfile" or name.startswith("Dockerfile."):
                lang = "dockerfile"
            else:
                continue
        files_count[lang] += 1
        text = read_text(root, rel, max_bytes=1024 * 1024)
        if text is not None:
            lines[lang] += text.count("\n") + (0 if text.endswith("\n") or not text else 1)
    return LanguageReport(
        files_by_language=dict(files_count.most_common()),
        lines_by_language=dict(lines.most_common()),
        frameworks=sorted(_frameworks(root, manifests)),
        manifests=sorted(manifests),
        total_files=len(files),
    )


def python_dependencies(root: Path, manifests: list[str]) -> set[str]:
    deps: set[str] = set()
    for rel in manifests:
        name = rel.rsplit("/", 1)[-1]
        text = read_text(root, rel)
        if not text:
            continue
        if name.startswith("requirements") and name.endswith(".txt"):
            for line in text.splitlines():
                if line.strip().startswith(("#", "-")):
                    continue
                if m := _REQ_NAME.match(line):
                    deps.add(m.group(1).lower())
        elif name == "pyproject.toml":
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            project_deps = list(data.get("project", {}).get("dependencies", []) or [])
            for group in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
                project_deps.extend(group)
            poetry = data.get("tool", {}).get("poetry", {})
            project_deps.extend(poetry.get("dependencies", {}).keys())
            for spec in project_deps:
                if isinstance(spec, str) and (m := _REQ_NAME.match(spec)):
                    deps.add(m.group(1).lower())
    return deps


def js_dependencies(root: Path, manifests: list[str]) -> set[str]:
    deps: set[str] = set()
    for rel in manifests:
        if not rel.endswith("package.json"):
            continue
        text = read_text(root, rel)
        try:
            data = json.loads(text or "")
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            section = data.get(key)
            if isinstance(section, dict):
                deps.update(k.lower() for k in section)
    return deps


def _frameworks(root: Path, manifests: list[str]) -> set[str]:
    found = set()
    for dep in python_dependencies(root, manifests):
        found.update(PY_FRAMEWORKS.get(dep.replace("_", "-"), ()))
        if dep.startswith("flask-"):
            found.add("flask")
    for dep in js_dependencies(root, manifests):
        if dep in JS_FRAMEWORKS:
            found.add(JS_FRAMEWORKS[dep])
    return found
