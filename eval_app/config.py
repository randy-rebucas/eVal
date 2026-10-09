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


class BaseConfig:
    SECRET_KEY = os.environ.get("EVAL_SECRET_KEY", "")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "")
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

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("EVAL_SECURE_COOKIES", True)
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_HTTPONLY = True
    WTF_CSRF_TIME_LIMIT = None

    LOGIN_RATE_LIMIT = _int("EVAL_LOGIN_RATE_LIMIT", 10)  # attempts per 5 minutes per IP+email
    ALLOW_REGISTRATION = _bool("EVAL_ALLOW_REGISTRATION", True)
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
    if problems:
        raise RuntimeError("Invalid configuration: " + "; ".join(problems))
