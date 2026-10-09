"""Provider-neutral AI interface. Providers return parsed JSON objects that callers must still validate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class AIError(Exception):
    """AI call failed or returned unusable output. Message is safe to show (no secrets, no prompt text)."""


@dataclass(frozen=True)
class ProviderInfo:
    name: str
    model: str


class AIProvider(Protocol):
    info: ProviderInfo

    def complete_json(self, *, system: str, user: str, schema: dict, max_tokens: int) -> dict:
        """Return a JSON object conforming (as far as the provider guarantees) to ``schema``."""
        ...


class StaticProvider:
    """Deterministic provider for tests and offline demos: returns a canned (or computed) response."""

    def __init__(self, responder, name: str = "static", model: str = "static"):
        self.info = ProviderInfo(name, model)
        self._responder = responder
        self.calls: list[dict] = []

    def complete_json(self, *, system: str, user: str, schema: dict, max_tokens: int) -> dict:
        self.calls.append({"system": system, "user": user, "schema": schema})
        result = self._responder(system=system, user=user, schema=schema)
        if isinstance(result, Exception):
            raise result
        return result
