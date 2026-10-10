"""Pluggable AI providers and the finding enricher. AI is optional and never affects scores."""

from __future__ import annotations

from .base import AIError, AIOutputError, AIProvider, StaticProvider

PROVIDERS = ("anthropic", "openai", "openai_compatible")

# Models offered in the settings picker, first one preselected. Any other model name can still be typed in;
# OpenAI-compatible servers serve whatever the operator has pulled, so those are only common local defaults.
MODEL_SUGGESTIONS: dict[str, tuple[str, ...]] = {
    "anthropic": ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1"),
    "openai": ("gpt-5", "gpt-5-mini", "gpt-4.1"),
    "openai_compatible": ("qwen2.5-coder:7b", "qwen2.5-coder:14b", "llama3.1:8b", "deepseek-coder-v2:16b"),
}


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


# OpenAI's catalog also lists embedding, audio, image and moderation models; only chat models can serve audits.
_OPENAI_CHAT_PREFIXES = ("gpt-", "o1", "o3", "o4", "chatgpt-")
_OPENAI_NON_CHAT = ("audio", "realtime", "tts", "transcribe", "image", "search", "embedding", "instruct", "moderation")


def list_models(name: str, *, api_key: str, base_url: str = "", timeout: float = 15.0) -> list[str]:
    """Model IDs the account (or OpenAI-compatible server) can use, newest first where the API orders them."""
    if name == "anthropic":
        import anthropic

        client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=0)
        try:
            return [m.id for m in client.models.list(limit=100)]
        except anthropic.AuthenticationError as exc:
            raise AIError("Anthropic rejected the API key.") from exc
        except anthropic.APIStatusError as exc:
            raise AIError(f"Anthropic API error ({exc.status_code}).") from exc
        except anthropic.APIConnectionError as exc:  # includes timeouts
            raise AIError("Could not reach the Anthropic API.") from exc
    if name in ("openai", "openai_compatible"):
        import openai

        if name == "openai_compatible" and not base_url:
            raise AIError("An OpenAI-compatible provider needs a base URL.")
        client = openai.OpenAI(api_key=api_key or "not-needed", timeout=timeout, max_retries=0,
                               base_url=base_url if name == "openai_compatible" else None)
        try:
            ids = [m.id for m in client.models.list()]
        except openai.AuthenticationError as exc:
            raise AIError("The AI provider rejected the API key.") from exc
        except openai.APIStatusError as exc:
            raise AIError(f"The AI provider returned an error ({exc.status_code}).") from exc
        except openai.APIConnectionError as exc:
            raise AIError("Could not reach the AI provider.") from exc
        if name == "openai":
            ids = sorted(i for i in ids if i.startswith(_OPENAI_CHAT_PREFIXES)
                         and not any(word in i for word in _OPENAI_NON_CHAT))
        return ids
    raise AIError(f"Unknown AI provider {name!r}.")


__all__ = ["MODEL_SUGGESTIONS", "PROVIDERS", "AIError", "AIOutputError", "AIProvider", "StaticProvider",
           "build_provider", "list_models"]
