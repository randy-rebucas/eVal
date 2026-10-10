"""Social sign-in (OAuth 2.0 authorization code flow) with GitHub, Google and LinkedIn.

Each provider turns on when its client id and secret are configured. Only the profile is read: a stable user id,
the email address and whether the provider has verified it. Access tokens are used once and never stored."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode

import requests
from flask import current_app

from ..integrations.services import github_web_url

TIMEOUT = (5, 20)


class SocialAuthError(Exception):
    pass


@dataclass(frozen=True)
class Provider:
    key: str
    label: str
    icon: str
    scope: str


@dataclass
class Profile:
    subject: str
    email: str
    email_verified: bool
    name: str


PROVIDERS = {
    "github": Provider("github", "GitHub", "bi-github", "read:user user:email"),
    "google": Provider("google", "Google", "bi-google", "openid email profile"),
    "linkedin": Provider("linkedin", "LinkedIn", "bi-linkedin", "openid profile email"),
}

GOOGLE_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"  # noqa: S105  # nosec B105 - endpoint, not a secret
GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"
LINKEDIN_AUTHORIZE = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN = "https://www.linkedin.com/oauth/v2/accessToken"  # noqa: S105  # nosec B105
LINKEDIN_USERINFO = "https://api.linkedin.com/v2/userinfo"


def _client(key: str) -> tuple[str, str]:
    cfg = current_app.config
    prefix = f"AUTH_{key.upper()}_"
    cid, secret = cfg.get(prefix + "CLIENT_ID", ""), cfg.get(prefix + "CLIENT_SECRET", "")
    if key == "github" and not (cid and secret):  # the "Connect GitHub" OAuth App can double as the login app
        cid, secret = cfg.get("GITHUB_OAUTH_CLIENT_ID", ""), cfg.get("GITHUB_OAUTH_CLIENT_SECRET", "")
    return cid, secret


def enabled_providers() -> list[Provider]:
    return [p for k, p in PROVIDERS.items() if all(_client(k))]


def get_provider(key: str) -> Provider | None:
    p = PROVIDERS.get(key)
    return p if p and all(_client(key)) else None


def _endpoints(key: str) -> tuple[str, str]:
    if key == "github":
        web = github_web_url()
        return f"{web}/login/oauth/authorize", f"{web}/login/oauth/access_token"
    if key == "google":
        return GOOGLE_AUTHORIZE, GOOGLE_TOKEN
    return LINKEDIN_AUTHORIZE, LINKEDIN_TOKEN


def authorize_url(key: str, redirect_uri: str, state: str) -> str:
    params = {"client_id": _client(key)[0], "redirect_uri": redirect_uri, "scope": PROVIDERS[key].scope,
              "state": state, "response_type": "code"}
    if key == "github":
        params["allow_signup"] = "false"
    elif key == "google":
        params["prompt"] = "select_account"
    return f"{_endpoints(key)[0]}?{urlencode(params)}"


def _json(method: str, url: str, **kwargs) -> dict | list:
    headers = {"Accept": "application/json", "User-Agent": "eVal", **kwargs.pop("headers", {})}
    try:
        resp = requests.request(method, url, headers=headers, timeout=TIMEOUT, **kwargs)
        data = resp.json() if resp.content else {}
    except (requests.RequestException, ValueError) as exc:
        raise SocialAuthError("Could not reach the sign-in provider.") from exc
    if resp.status_code >= 400 or (isinstance(data, dict) and data.get("error")):
        reason = data.get("error_description") or data.get("error") if isinstance(data, dict) else None
        raise SocialAuthError(f"Sign-in failed: {str(reason or resp.status_code)[:200]}.")
    return data


def exchange_code(key: str, code: str, redirect_uri: str) -> str:
    cid, secret = _client(key)
    data = _json("POST", _endpoints(key)[1], data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
        "client_id": cid, "client_secret": secret,
    })
    token = data.get("access_token") if isinstance(data, dict) else None
    if not token:
        raise SocialAuthError("Sign-in failed: the provider returned no access token.")
    return token


def fetch_profile(key: str, token: str) -> Profile:
    auth = {"Authorization": f"Bearer {token}"}
    if key == "github":
        api = current_app.config["GITHUB_API_URL"].rstrip("/")
        user = _json("GET", f"{api}/user", headers=auth)
        emails = _json("GET", f"{api}/user/emails", headers=auth)
        primary = next((e for e in emails if e.get("primary") and e.get("verified")), None) \
            or next((e for e in emails if e.get("verified")), None)
        return Profile(subject=str(user["id"]), email=(primary or {}).get("email", ""),
                       email_verified=primary is not None, name=user.get("name") or user.get("login") or "")
    info = _json("GET", GOOGLE_USERINFO if key == "google" else LINKEDIN_USERINFO, headers=auth)
    verified = info.get("email_verified")
    return Profile(subject=str(info.get("sub") or ""), email=info.get("email") or "",
                   email_verified=verified is True or str(verified).lower() == "true",
                   name=info.get("name") or "")
