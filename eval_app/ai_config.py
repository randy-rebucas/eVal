"""Per-organization AI configuration: settings management and enricher construction for the audit task.

AI is disabled by default. When enabled, the org's encrypted API key is decrypted only inside the worker.
OpenAI-compatible base URLs must be on the operator allow-list (EVAL_AI_ALLOWED_BASE_URLS) so tenants cannot
point the worker at arbitrary internal hosts (SSRF).
"""

from __future__ import annotations

import uuid

from flask import current_app

from eval_engine.ai import PROVIDERS, AIError, build_provider, list_models
from eval_engine.ai.enrich import Enricher

from .extensions import db
from .models import AISettings, IntegrationCredential, Organization
from .security import crypto, events


class AISettingsError(Exception):
    pass


def get_settings(org_id) -> AISettings | None:
    return db.session.execute(db.select(AISettings).where(AISettings.organization_id == org_id)).scalar_one_or_none()


def allowed_base_urls() -> list[str]:
    raw = current_app.config.get("AI_ALLOWED_BASE_URLS") or ""
    return [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]


def _org_credential(org: Organization, provider: str, credential_id) -> IntegrationCredential | None:
    if not credential_id:
        return None
    try:
        cid = uuid.UUID(str(credential_id))
    except ValueError as exc:
        raise AISettingsError("Unknown credential.") from exc
    cred = db.session.execute(db.select(IntegrationCredential).where(
        IntegrationCredential.id == cid, IntegrationCredential.organization_id == org.id,
        IntegrationCredential.provider == provider)).scalar_one_or_none()
    if cred is None:
        raise AISettingsError("Choose a credential for the selected provider.")
    return cred


def fetch_models(org: Organization, *, provider: str, credential_id, base_url: str) -> list[str]:
    """Ask the provider which models the org's key (or the allow-listed compatible server) can use."""
    if provider not in PROVIDERS:
        raise AISettingsError("Unknown AI provider.")
    base_url = base_url.strip().rstrip("/")
    if provider == "openai_compatible":
        if base_url not in allowed_base_urls():
            raise AISettingsError("Choose an allow-listed base URL first.")
    else:
        base_url = ""
    cred = _org_credential(org, provider, credential_id)
    if cred is None and provider != "openai_compatible":
        raise AISettingsError("Select an API key for this provider to load its models.")
    try:
        key = crypto.decrypt(cred.encrypted_secret) if cred else ""
        return list_models(provider, api_key=key, base_url=base_url)
    except (AIError, crypto.CredentialDecryptionError) as exc:
        raise AISettingsError(str(exc)) from exc


def save_settings(org: Organization, *, enabled: bool, provider: str, model: str, base_url: str,
                  credential_id, max_findings: int) -> AISettings:
    if provider not in PROVIDERS:
        raise AISettingsError("Unknown AI provider.")
    model = model.strip()[:120]
    base_url = base_url.strip().rstrip("/")[:300]
    if provider in ("openai", "openai_compatible") and not model:
        raise AISettingsError("Enter the model name to use.")
    if provider == "openai_compatible":
        if base_url not in allowed_base_urls():
            raise AISettingsError("That base URL is not on the operator allow-list (EVAL_AI_ALLOWED_BASE_URLS).")
    else:
        base_url = ""
    cred = _org_credential(org, provider, credential_id)
    if enabled and cred is None and provider != "openai_compatible":
        raise AISettingsError("Add and select an API key for this provider first.")
    settings = get_settings(org.id) or AISettings(organization_id=org.id)
    settings.enabled = enabled
    settings.provider = provider
    settings.model = model
    settings.base_url = base_url
    settings.credential_id = cred.id if cred else None
    settings.max_findings = max(1, min(int(max_findings or 15), 50))
    db.session.add(settings)
    events.record("ai.settings_changed", organization_id=org.id, target=settings, enabled=enabled,
                  provider=provider, model=model or None)
    db.session.commit()
    return settings


def build_enricher(organization_id):
    """Return an Enricher for the org, None when AI is disabled, or an object reporting a config error."""
    settings = get_settings(organization_id)
    if settings is None or not settings.enabled:
        return None
    try:
        key = crypto.decrypt(settings.credential.encrypted_secret) if settings.credential else ""
        if settings.provider == "openai_compatible" and settings.base_url not in allowed_base_urls():
            raise AIError("The configured base URL is no longer allowed by the operator.")
        provider = build_provider(settings.provider, api_key=key, model=settings.model, base_url=settings.base_url,
                                  timeout=float(current_app.config.get("AI_TIMEOUT_SECONDS", 120)))
    except (AIError, crypto.CredentialDecryptionError) as exc:
        return _BrokenEnricher(str(exc))
    return Enricher(provider, max_findings=settings.max_findings)


class _BrokenEnricher:
    """Surfaces AI misconfiguration in the audit instead of silently skipping AI."""

    def __init__(self, message: str):
        self.message = message

    def enrich(self, **_kwargs) -> dict:
        return {"error": self.message}
