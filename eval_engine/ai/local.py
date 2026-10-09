"""On-device AI: an OpenAI-compatible model server (Ollama, LM Studio, llama.cpp, vLLM) on this machine.

Only loopback endpoints are accepted, so "local" is enforced rather than claimed: findings and redacted
evidence never leave the device. No API key is needed.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from .base import AIError, ProviderInfo

DEFAULT_LOCAL_URL = "http://127.0.0.1:11434/v1"  # Ollama's OpenAI-compatible API
DEFAULT_LOCAL_MODEL = "qwen2.5-coder:7b"
# Small local models handle short batches far better than the cloud defaults (15 findings in one 16k request).
LOCAL_MAX_FINDINGS = 6
LOCAL_BATCH_SIZE = 3
LOCAL_MAX_TOKENS = 4096


def is_loopback_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def build_local_provider(*, model: str = DEFAULT_LOCAL_MODEL, base_url: str = DEFAULT_LOCAL_URL,
                         timeout: float = 300.0):
    if not is_loopback_url(base_url):
        raise AIError(f"Local AI must run on this machine; {base_url!r} is not a loopback address "
                      "(use 127.0.0.1, ::1 or localhost).")
    from .openai_provider import OpenAIProvider

    try:
        provider = OpenAIProvider(api_key="", model=model, base_url=base_url, timeout=timeout, ignore_proxy_env=True)
    except ImportError as exc:  # pragma: no cover - depends on installed extras
        raise AIError("Local AI needs the 'openai' package: pip install 'eval-auditor[ai]'.") from exc
    provider.info = ProviderInfo("local", model)
    return provider
