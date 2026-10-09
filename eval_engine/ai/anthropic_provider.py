"""Anthropic Claude provider (official ``anthropic`` SDK) using structured JSON outputs."""

from __future__ import annotations

import json

from .base import AIError, ProviderInfo

DEFAULT_MODEL = "claude-opus-5-5"


class AnthropicProvider:
    def __init__(self, api_key: str, model: str = "", timeout: float = 120.0, effort: str = "medium"):
        import anthropic

        self._anthropic = anthropic
        self._client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=2)
        self.info = ProviderInfo("anthropic", model or DEFAULT_MODEL)
        self._effort = effort

    def complete_json(self, *, system: str, user: str, schema: dict, max_tokens: int) -> dict:
        a = self._anthropic
        try:
            # Server-side refusal fallback ("default" routing) is enabled so a safety-classifier decline on a
            # security-heavy prompt is retried on a suitable model inside the same call.
            response = self._client.beta.messages.create(
                model=self.info.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"effort": self._effort, "format": {"type": "json_schema", "schema": schema}},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except a.AuthenticationError as exc:
            raise AIError("Anthropic rejected the API key.") from exc
        except a.PermissionDeniedError as exc:
            raise AIError("The Anthropic API key lacks permission for this model.") from exc
        except a.NotFoundError as exc:
            raise AIError(f"Anthropic model {self.info.model!r} was not found.") from exc
        except a.RateLimitError as exc:
            raise AIError("Anthropic rate limit reached; try again later.") from exc
        except a.BadRequestError as exc:
            raise AIError("Anthropic rejected the request (400).") from exc
        except a.APIStatusError as exc:
            raise AIError(f"Anthropic API error ({exc.status_code}).") from exc
        except a.APITimeoutError as exc:
            raise AIError("Anthropic request timed out.") from exc
        except a.APIConnectionError as exc:
            raise AIError("Could not reach the Anthropic API.") from exc

        if response.stop_reason == "refusal":
            raise AIError("The model declined to analyze this content.")
        if response.stop_reason == "max_tokens":
            raise AIError("The model response was truncated (max_tokens).")
        text = next((b.text for b in response.content if b.type == "text"), "")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AIError("The model returned invalid JSON.") from exc
        if not isinstance(data, dict):
            raise AIError("The model returned a non-object JSON value.")
        return data
