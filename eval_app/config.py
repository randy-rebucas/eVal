"""Environment-driven configuration. No secrets are hardcoded; production refuses to boot without them."""

from __future__ import annotations

import os
from pathlib import Path


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def database_url(raw: str) -> str:
    """Hosting providers (Render, Heroku) hand out ``postgres://`` / ``postgresql://`` URLs, which SQLAlchemy maps
    to psycopg2. eVal ships psycopg 3, so select its driver explicitly; other URLs pass through unchanged."""
    for prefix in ("postgres://", "postgresql://"):
        if raw.startswith(prefix):
            return "postgresql+psycopg://" + raw[len(prefix):]
    return raw


class BaseConfig:
    SECRET_KEY = os.environ.get("EVAL_SECRET_KEY", "")
    SQLALCHEMY_DATABASE_URI = database_url(os.environ.get("DATABASE_URL", ""))
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Comma-separated Fernet keys; first key encrypts, all keys decrypt (rotation).
    ENCRYPTION_KEYS = os.environ.get("EVAL_ENCRYPTION_KEYS", "")

    CELERY_BROKER_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    CELERY_TASK_ALWAYS_EAGER = _bool("CELERY_TASK_ALWAYS_EAGER", False)
    RATELIMIT_REDIS_URL = os.environ.get("REDIS_URL", "")

    DATA_DIR = Path(os.environ.get("EVAL_DATA_DIR", "./var")).resolve()
    # Scratch space for checked-out/extracted sources; wiped after each audit. tmpfs in the worker container.
    WORK_DIR = Path(os.environ["EVAL_WORK_DIR"]).resolve() if os.environ.get("EVAL_WORK_DIR") else None
    MAX_CONTENT_LENGTH = _int("EVAL_MAX_UPLOAD_MB", 50) * 1024 * 1024

    # Workspace limits (see eval_engine.workspace.Limits)
    WORKSPACE_MAX_FILES = _int("EVAL_WORKSPACE_MAX_FILES", 20000)
    WORKSPACE_MAX_TOTAL_MB = _int("EVAL_WORKSPACE_MAX_TOTAL_MB", 500)
    WORKSPACE_MAX_FILE_MB = _int("EVAL_WORKSPACE_MAX_FILE_MB", 20)
    ANALYZER_TIMEOUT_SECONDS = _int("EVAL_ANALYZER_TIMEOUT_SECONDS", 300)
    GIT_ALLOWED_HOSTS = [
        h.strip() for h in os.environ.get("EVAL_GIT_ALLOWED_HOSTS", "github.com").split(",") if h.strip()
    ]

    GITHUB_API_URL = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    # "Connect GitHub" sign-in (a GitHub OAuth App). Callback URL: https://YOUR-HOST/integrations/github/callback
    GITHUB_OAUTH_CLIENT_ID = os.environ.get("GITHUB_OAUTH_CLIENT_ID", "")
    GITHUB_OAUTH_CLIENT_SECRET = os.environ.get("GITHUB_OAUTH_CLIENT_SECRET", "")
    # Social sign-in; each provider is offered once both values are set. Callback: https://YOUR-HOST/login/<p>/callback
    # GitHub falls back to the GITHUB_OAUTH_* app above (register its callback as the site root to cover both).
    # GitHub App (webhook-driven PR audits and check runs). Webhook URL: https://YOUR-HOST/webhooks/github;
    # Setup URL (with "Request user authorization during installation"): https://YOUR-HOST/integrations/github/app/setup
    GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
    GITHUB_APP_SLUG = os.environ.get("GITHUB_APP_SLUG", "")
    GITHUB_APP_PRIVATE_KEY = os.environ.get("GITHUB_APP_PRIVATE_KEY", "")  # PEM; literal \n escapes are accepted
    GITHUB_APP_PRIVATE_KEY_FILE = os.environ.get("GITHUB_APP_PRIVATE_KEY_FILE", "")
    GITHUB_APP_WEBHOOK_SECRET = os.environ.get("GITHUB_APP_WEBHOOK_SECRET", "")
    GITHUB_APP_CLIENT_ID = os.environ.get("GITHUB_APP_CLIENT_ID", "")
    GITHUB_APP_CLIENT_SECRET = os.environ.get("GITHUB_APP_CLIENT_SECRET", "")
    # Public base URL of this server, for links built outside a request (check runs, notifications).
    PUBLIC_URL = os.environ.get("EVAL_PUBLIC_URL", "")
    AUTH_GITHUB_CLIENT_ID = os.environ.get("AUTH_GITHUB_CLIENT_ID", "")
    AUTH_GITHUB_CLIENT_SECRET = os.environ.get("AUTH_GITHUB_CLIENT_SECRET", "")
    AUTH_GOOGLE_CLIENT_ID = os.environ.get("AUTH_GOOGLE_CLIENT_ID", "")
    AUTH_GOOGLE_CLIENT_SECRET = os.environ.get("AUTH_GOOGLE_CLIENT_SECRET", "")
    AUTH_LINKEDIN_CLIENT_ID = os.environ.get("AUTH_LINKEDIN_CLIENT_ID", "")
    AUTH_LINKEDIN_CLIENT_SECRET = os.environ.get("AUTH_LINKEDIN_CLIENT_SECRET", "")

    # Browser origins allowed to call /api/v1 cross-origin (bearer token only, never cookies). Comma-separated;
    # "https://*.example.com" matches subdomains, "*" any origin, empty disables CORS. The default covers the web
    # extension host of vscode.dev / github.dev, which runs on *.vscode-cdn.net.
    API_CORS_ORIGINS = [
        o.strip().rstrip("/") for o in os.environ.get(
            "EVAL_API_CORS_ORIGINS", "https://*.vscode-cdn.net,https://vscode.dev,https://github.dev",
        ).split(",") if o.strip()
    ]

    # Operator allow-list for OpenAI-compatible AI endpoints (e.g. http://ollama:11434/v1). Prevents SSRF.
    AI_ALLOWED_BASE_URLS = os.environ.get("EVAL_AI_ALLOWED_BASE_URLS", "")
    AI_TIMEOUT_SECONDS = _int("EVAL_AI_TIMEOUT_SECONDS", 120)

    # Optional sandbox terminal (docs/SANDBOX.md): a separate service that runs one isolated container per session.
    # Off unless both URLs and the shared secret are set; each organization's admin must also turn it on.
    SANDBOX_URL = os.environ.get("EVAL_SANDBOX_URL", "").rstrip("/")  # internal, e.g. http://sandbox:8100
    SANDBOX_PUBLIC_URL = os.environ.get("EVAL_SANDBOX_PUBLIC_URL", "").rstrip("/")  # browsers, e.g. wss://sbx.example
    SANDBOX_SECRET = os.environ.get("EVAL_SANDBOX_SECRET", "")
    SANDBOX_MAX_MINUTES = _int("EVAL_SANDBOX_MAX_MINUTES", 30)

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("EVAL_SECURE_COOKIES", True)
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_HTTPONLY = True
    WTF_CSRF_TIME_LIMIT = None

    LOGIN_RATE_LIMIT = _int("EVAL_LOGIN_RATE_LIMIT", 10)  # attempts per 5 minutes per IP+email
    LOGIN_IP_RATE_LIMIT = _int("EVAL_LOGIN_IP_RATE_LIMIT", 50)  # attempts per 5 minutes per IP (any email)
    ALLOW_REGISTRATION = _bool("EVAL_ALLOW_REGISTRATION", True)
    # Number of trusted reverse proxies in front of the app (X-Forwarded-For/-Proto). 0 = direct exposure.
    # Without it, every client appears to come from the proxy's IP and shares one rate-limit bucket.
    PROXY_FIX_HOPS = _int("EVAL_PROXY_FIX_HOPS", 0)
    MAX_ORGS_PER_USER = _int("EVAL_MAX_ORGS_PER_USER", 5)  # organizations a user may create (owner role)
    # Longest an accepted risk (or a time-boxed false positive) may last before the finding reopens for review.
    ACCEPTED_RISK_MAX_DAYS = _int("EVAL_ACCEPTED_RISK_MAX_DAYS", 365)
    TESTING = False
    DEBUG = False


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SESSION_COOKIE_SECURE = _bool("EVAL_SECURE_COOKIES", False)
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE


class TestingConfig(BaseConfig):
    TESTING = True
    SECRET_KEY = "test-secret-key-not-for-production"  # noqa: S105  # nosec B105
    SQLALCHEMY_DATABASE_URI = os.environ.get("TEST_DATABASE_URL", "sqlite:///:memory:")
    SQLALCHEMY_ENGINE_OPTIONS: dict = {}
    # Deterministic test key (urlsafe base64 of 32 bytes); never used outside tests.
    ENCRYPTION_KEYS = "dGVzdC1rZXktdGVzdC1rZXktdGVzdC1rZXktdGVzdC0="
    CELERY_TASK_ALWAYS_EAGER = True
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    RATELIMIT_REDIS_URL = ""


class ProductionConfig(BaseConfig):
    pass


CONFIGS = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def validate(config: dict) -> None:
    """Fail fast on missing or weak settings outside of tests."""
    if config.get("TESTING"):
        return
    problems = []
    if len(config.get("SECRET_KEY") or "") < 32:
        problems.append("EVAL_SECRET_KEY must be set to at least 32 characters")
    if not config.get("SQLALCHEMY_DATABASE_URI"):
        problems.append("DATABASE_URL must be set")
    if not config.get("ENCRYPTION_KEYS"):
        problems.append("EVAL_ENCRYPTION_KEYS must be set (generate with `python -m eval_app.security.crypto`)")
    sandbox = [config.get(k) for k in ("SANDBOX_URL", "SANDBOX_PUBLIC_URL", "SANDBOX_SECRET")]
    if any(sandbox) and not all(sandbox):
        problems.append("EVAL_SANDBOX_URL, EVAL_SANDBOX_PUBLIC_URL and EVAL_SANDBOX_SECRET must be set together")
    elif all(sandbox):
        if len(config["SANDBOX_SECRET"]) < 32:
            problems.append("EVAL_SANDBOX_SECRET must be at least 32 characters")
        if not config["SANDBOX_PUBLIC_URL"].startswith(("wss://", "ws://")):
            problems.append("EVAL_SANDBOX_PUBLIC_URL must be a wss:// URL (ws:// for local development only)")
    if problems:
        raise RuntimeError("Invalid configuration: " + "; ".join(problems))
