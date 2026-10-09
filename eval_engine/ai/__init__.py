"""Pluggable AI providers and the finding enricher. AI is optional and never affects scores."""

from __future__ import annotations

from .base import AIError, AIOutputError, AIProvider, StaticProvider

PROVIDERS = ("anthropic", "openai", "openai_compatible")


def build_provider(name: str, *, api_key: str, model: str = "", base_url: str = "", timeout: float = 120.0):
    if name == "anthropic":
        from .anthropic_provider import AnthropicProvider

        return AnthropicProvider(api_key=api_key, model=model, timeout=timeout)
    if name in ("openai", "openai_compatible"):
        from .openai_provider import OpenAIProvider

        if name == "openai_compatible" and not base_url:
            raise AIError("An OpenAI-compatible provider needs a base URL.")
        return OpenAIProvider(api_key=api_key, model=model, base_url=base_url if name == "openai_compatible" else "",
                              timeout=timeout)
    raise AIError(f"Unknown AI provider {name!r}.")


__all__ = ["PROVIDERS", "AIError", "AIOutputError", "AIProvider", "StaticProvider", "build_provider"]
