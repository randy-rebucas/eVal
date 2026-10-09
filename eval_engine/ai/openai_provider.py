"""OpenAI provider (official ``openai`` SDK). Also serves OpenAI-compatible endpoints such as local model
gateways (Ollama, vLLM, LM Studio) via ``base_url``; those get JSON mode instead of strict schemas because
schema support varies between servers."""

from __future__ import annotations

import json

from .base import AIError, AIOutputError, ProviderInfo


class OpenAIProvider:
    def __init__(self, api_key: str, model: str, base_url: str = "", timeout: float = 120.0,
                 ignore_proxy_env: bool = False):
        import openai

        if not model:
            raise AIError("A model name is required for OpenAI and OpenAI-compatible providers.")
        self._openai = openai
        self._compatible = bool(base_url)
        # ignore_proxy_env: never route requests through HTTP(S)_PROXY / ALL_PROXY (used for on-device models,
        # whose traffic must not leave the machine).
        http_client = openai.DefaultHttpx2Client(trust_env=False) if ignore_proxy_env else None
        self._client = openai.OpenAI(api_key=api_key or "not-needed", base_url=base_url or None, timeout=timeout,
                                     max_retries=2, http_client=http_client)
        self.info = ProviderInfo("openai_compatible" if self._compatible else "openai", model)

    def complete_json(self, *, system: str, user: str, schema: dict, max_tokens: int) -> dict:
        o = self._openai
        if self._compatible:
            response_format = {"type": "json_object"}
            system = system + "\n\nRespond with a single JSON object matching this JSON Schema:\n" + json.dumps(schema)
        else:
            response_format = {"type": "json_schema",
                               "json_schema": {"name": "eval_output", "schema": schema, "strict": True}}
        try:
            response = self._client.chat.completions.create(
                model=self.info.model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                response_format=response_format,
                max_completion_tokens=max_tokens,
            )
        except o.AuthenticationError as exc:
            raise AIError("The AI provider rejected the API key.") from exc
        except o.NotFoundError as exc:
            raise AIError(f"Model {self.info.model!r} was not found.") from exc
        except o.RateLimitError as exc:
            raise AIError("AI provider rate limit reached; try again later.") from exc
        except o.APIStatusError as exc:
            raise AIError(f"AI provider error ({exc.status_code}).") from exc
        except o.APITimeoutError as exc:
            raise AIError("AI request timed out.") from exc
        except o.APIConnectionError as exc:
            raise AIError("Could not reach the AI provider.") from exc
        choice = response.choices[0] if response.choices else None
        if choice is None or choice.finish_reason == "length":
            raise AIError("The model response was empty or truncated.")
        if getattr(choice.message, "refusal", None):
            raise AIError("The model declined to analyze this content.")
        try:
            data = json.loads(choice.message.content or "")
        except json.JSONDecodeError as exc:
            raise AIOutputError("The model returned invalid JSON.") from exc
        if not isinstance(data, dict):
            raise AIOutputError("The model returned a non-object JSON value.")
        return data
