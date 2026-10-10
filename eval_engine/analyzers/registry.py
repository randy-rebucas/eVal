from __future__ import annotations

from .base import Analyzer

_REGISTRY: dict[str, type[Analyzer]] = {}


def register(cls: type[Analyzer]) -> type[Analyzer]:
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"duplicate analyzer name {cls.name!r}")
    _REGISTRY[cls.name] = cls
    return cls


def all_analyzers() -> list[Analyzer]:
    _load_builtin()
    return [cls() for _, cls in sorted(_REGISTRY.items())]


def get(names: list[str] | None) -> list[Analyzer]:
    analyzers = all_analyzers()
    if names is None:
        return analyzers
    wanted = set(names)
    unknown = wanted - {a.name for a in analyzers}
    if unknown:
        raise ValueError(f"unknown analyzers: {', '.join(sorted(unknown))}")
    return [a for a in analyzers if a.name in wanted]


def _load_builtin() -> None:
    # Importing the modules triggers @register. Kept explicit so the set of analyzers is auditable.
    from . import (  # noqa: F401
        ai_code,
        api_security,
        architecture,
        bandit,
        configuration,
        database,
        dependencies,
        devops,
        eslint,
        maintainability,
        mypy_,
        performance,
        ruff,
        secrets,
        semgrep,
        taint,
        testing,
        trivy,
        tsc,
    )
