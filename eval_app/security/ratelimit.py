"""Fixed-window rate limiter. Uses Redis when configured, otherwise (or while Redis is unreachable) a per-process
in-memory store (adequate for tests and single-process development only)."""

from __future__ import annotations

import hashlib
import threading
import time

from flask import current_app

_lock = threading.Lock()
_memory: dict[str, tuple[int, float]] = {}


def _key(scope: str, ident: str) -> str:
    return f"eval:rl:{scope}:" + hashlib.sha256(ident.encode()).hexdigest()[:32]


def hit(scope: str, ident: str, limit: int, window_seconds: int) -> bool:
    """Record an attempt; return True if the caller is still within the limit."""
    key = _key(scope, ident)
    url = current_app.config.get("RATELIMIT_REDIS_URL")
    if url:
        import redis

        # Short timeouts: an unreachable Redis must not stall logins (we fall back to in-process limits).
        client = redis.Redis.from_url(url, socket_connect_timeout=0.5, socket_timeout=0.5)
        try:
            pipe = client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_seconds, nx=True)
            count, _ = pipe.execute()
            return int(count) <= limit
        except redis.RedisError:
            # Don't fail open: an attacker able to disrupt Redis would otherwise disable login throttling.
            current_app.logger.warning("rate limiter Redis unavailable; using in-process limits for scope=%s", scope)
    now = time.monotonic()
    with _lock:
        count, reset = _memory.get(key, (0, now + window_seconds))
        if now > reset:
            count, reset = 0, now + window_seconds
        count += 1
        _memory[key] = (count, reset)
        return count <= limit


def reset_memory() -> None:
    with _lock:
        _memory.clear()
