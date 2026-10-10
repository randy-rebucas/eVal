from __future__ import annotations

from urllib.parse import urlsplit

from flask import current_app

from ..extensions import db
from ..models import IntegrationCredential, Organization
from ..security import crypto, events
from .github import GitHubClient, GitHubError

PROVIDERS = {
    "github": "GitHub personal access token (fine-grained: Contents read; Issues / Pull requests write optional)",
    "anthropic": "Anthropic API key",
    "openai": "OpenAI API key",
    "openai_compatible": "OpenAI-compatible endpoint key (e.g. local model gateway)",
}


class CredentialError(Exception):
    pass


def add_credential(org: Organization, provider: str, label: str, secret: str, user_id, verify: bool = True):
    if provider not in PROVIDERS:
        raise CredentialError("Unknown provider.")
    secret = secret.strip()
    label = label.strip()[:120] or provider
    if not 8 <= len(secret) <= 4096 or any(c.isspace() for c in secret):
        raise CredentialError("That does not look like a valid token.")
    if verify and provider == "github":
        try:
            login = github_client_for_token(secret).get_user()["login"]
        except GitHubError as exc:
            raise CredentialError(f"GitHub token check failed: {exc}") from exc
        label = label if label != provider else f"GitHub ({login})"
    cred = IntegrationCredential(
        organization_id=org.id,
        provider=provider,
        label=label,
        encrypted_secret=crypto.encrypt(secret),
        last4=crypto.last4(secret),
        created_by_id=user_id,
    )
    db.session.add(cred)
    db.session.flush()
    events.record("credential.added", organization_id=org.id, target=cred, provider=provider)
    db.session.commit()
    return cred


def delete_credential(org: Organization, cred: IntegrationCredential) -> None:
    events.record("credential.deleted", organization_id=org.id, target=cred, provider=cred.provider)
    db.session.delete(cred)
    db.session.commit()


def reveal(cred: IntegrationCredential) -> str:
    """Decrypt for immediate server-side use only. Never render, log, or return the result to a client."""
    return crypto.decrypt(cred.encrypted_secret)


def github_clone_url(full_name: str) -> str:
    """Clone URL on the same GitHub instance as ``GITHUB_API_URL`` (github.com, or GitHub Enterprise at
    ``https://HOST/api/v3``), so a credential is only ever sent to the host it was issued for."""
    host = urlsplit(current_app.config["GITHUB_API_URL"]).hostname or ""
    if host == "api.github.com":
        host = "github.com"
    return f"https://{host}/{full_name}.git"


def github_web_url() -> str:
    """Web host paired with ``GITHUB_API_URL`` (where OAuth sign-in happens)."""
    return github_clone_url("x/x").removesuffix("/x/x.git")


def github_oauth_enabled() -> bool:
    cfg = current_app.config
    return bool(cfg.get("GITHUB_OAUTH_CLIENT_ID") and cfg.get("GITHUB_OAUTH_CLIENT_SECRET"))


def save_github_oauth_token(org: Organization, token: str, user_id) -> IntegrationCredential:
    """Store a token from "Connect GitHub". Reconnecting the same GitHub account replaces that credential's
    token in place, so repositories already bound to it keep working."""
    try:
        login = github_client_for_token(token).get_user()["login"]
    except GitHubError as exc:
        raise CredentialError(f"GitHub token check failed: {exc}") from exc
    label = f"GitHub ({login})"
    cred = db.session.execute(
        db.select(IntegrationCredential).where(IntegrationCredential.organization_id == org.id,
                                               IntegrationCredential.provider == "github",
                                               IntegrationCredential.label == label)
        .order_by(IntegrationCredential.created_at).limit(1)
    ).scalar_one_or_none()
    if cred is None:
        return add_credential(org, "github", label, token, user_id, verify=False)
    cred.encrypted_secret = crypto.encrypt(token)
    cred.last4 = crypto.last4(token)
    events.record("credential.rotated", organization_id=org.id, target=cred, provider="github")
    db.session.commit()
    return cred


def github_client_for_token(token: str | None) -> GitHubClient:
    return GitHubClient(token, api_url=current_app.config["GITHUB_API_URL"])


def github_client(cred: IntegrationCredential | None) -> GitHubClient:
    if cred is not None and cred.provider != "github":
        raise CredentialError("Credential is not a GitHub token.")
    return github_client_for_token(reveal(cred) if cred else None)


def org_credentials(org: Organization, provider: str | None = None) -> list[IntegrationCredential]:
    q = db.select(IntegrationCredential).where(IntegrationCredential.organization_id == org.id)
    if provider:
        q = q.where(IntegrationCredential.provider == provider)
    return list(db.session.execute(q.order_by(IntegrationCredential.created_at)).scalars())


# ------------------------------------------------------------------------------- repository access
def repo_token(repo) -> str | None:
    """Token for a repository: a fresh GitHub App installation token when the repository is linked to an active
    installation and the App is configured, else its credential's token (or None for public access)."""
    from . import github_app

    inst = repo.installation
    if inst is not None and not inst.suspended and github_app.enabled():
        try:
            return github_app.installation_token(inst.installation_id)
        except GitHubError as exc:
            raise CredentialError(f"GitHub App: {exc}") from exc
    if repo.credential is not None:
        if repo.credential.provider != "github":
            raise CredentialError("Credential is not a GitHub token.")
        return reveal(repo.credential)
    return None


def repo_client(repo) -> GitHubClient:
    return github_client_for_token(repo_token(repo))


def has_write_access(repo) -> bool:
    """Whether eVal holds a credential (or App installation) that may be able to write to ``repo``."""
    return repo.source == "github" and (repo.credential is not None or
                                        (repo.installation is not None and not repo.installation.suspended))
