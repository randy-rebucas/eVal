"""Per-organization single sign-on with OpenID Connect (authorization code flow + PKCE).

Security properties:
* The ID token's signature is verified against the IdP's published JWKS (RS256, ES256), and ``iss``, ``aud``,
  ``exp``, ``iat`` and the per-login ``nonce`` are checked. ``state`` binds the callback to the browser session.
* The email must be in one of the connection's domains.
* SSO never takes over an account it does not own. An organization's IdP is controlled by that organization's
  admins, so it may only sign in users it is linked to (an ``SsoIdentity``), accounts the organization itself
  provisioned (SCIM or earlier SSO: ``User.managed_by_org_id``), or new accounts it creates (auto-provisioning).
  Anyone else links SSO from a session in which they already signed in themselves.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode, urlsplit

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ..extensions import db
from ..models import Membership, Organization, SsoConnection, SsoIdentity, User, utcnow
from ..security import crypto, events

TIMEOUT = (5, 15)
CACHE_SECONDS = 3600
CLOCK_SKEW = 120
_cache: dict[str, tuple[float, dict]] = {}


class SSOError(Exception):
    pass


def _b64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _get_json(url: str) -> dict:
    if urlsplit(url).scheme != "https":
        raise SSOError("Identity provider endpoints must use https.")
    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"Accept": "application/json"}, allow_redirects=False)
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        raise SSOError("Could not reach the identity provider.") from exc


def _cached(url: str) -> dict:
    hit = _cache.get(url)
    if hit and hit[0] > time.time():
        return hit[1]
    data = _get_json(url)
    _cache[url] = (time.time() + CACHE_SECONDS, data)
    return data


def discovery(issuer: str) -> dict:
    meta = _cached(issuer.rstrip("/") + "/.well-known/openid-configuration")
    if meta.get("issuer", "").rstrip("/") != issuer.rstrip("/"):
        raise SSOError("The identity provider's discovery document names a different issuer.")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not str(meta.get(key, "")).startswith("https://"):
            raise SSOError(f"The identity provider has no https {key}.")
    return meta


def validate_issuer(issuer: str) -> str:
    issuer = (issuer or "").strip().rstrip("/")
    parts = urlsplit(issuer)
    if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment:
        raise SSOError("The issuer must be an https URL, e.g. https://acme.okta.com.")
    return issuer


def connection_for(org: Organization) -> SsoConnection | None:
    return db.session.execute(db.select(SsoConnection).where(SsoConnection.organization_id == org.id)
                              ).scalar_one_or_none()


def connection_for_email(email: str) -> SsoConnection | None:
    domain = email.rpartition("@")[2].lower()
    if not domain:
        return None
    for conn in db.session.execute(db.select(SsoConnection).where(SsoConnection.enabled.is_(True))).scalars():
        if domain in [d.lower() for d in conn.domains or []]:
            return conn
    return None


# ------------------------------------------------------------------------------------------------ flow
def begin(conn: SsoConnection, redirect_uri: str) -> tuple[str, dict]:
    """(authorization URL, values to keep in the session)."""
    meta = discovery(conn.issuer)
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"response_type": "code", "client_id": conn.client_id, "redirect_uri": redirect_uri,
              "scope": "openid email profile", "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    return f"{meta['authorization_endpoint']}?{urlencode(params)}", {
        "conn": str(conn.id), "state": state, "nonce": nonce, "verifier": verifier, "at": int(time.time())}


def exchange(conn: SsoConnection, code: str, redirect_uri: str, verifier: str) -> str:
    meta = discovery(conn.issuer)
    try:
        resp = requests.post(meta["token_endpoint"], timeout=TIMEOUT, allow_redirects=False,
                             headers={"Accept": "application/json"},
                             data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                                   "client_id": conn.client_id,
                                   "client_secret": crypto.decrypt(conn.encrypted_client_secret),
                                   "code_verifier": verifier})
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        raise SSOError("Could not reach the identity provider.") from exc
    if resp.status_code >= 400 or not data.get("id_token"):
        reason = data.get("error_description") or data.get("error") or resp.status_code
        raise SSOError(f"Sign-in failed: {str(reason)[:200]}")
    return data["id_token"]


def _public_key(jwk: dict):
    if jwk.get("kty") == "RSA":
        n, e = int.from_bytes(_b64url(jwk["n"]), "big"), int.from_bytes(_b64url(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x, y = int.from_bytes(_b64url(jwk["x"]), "big"), int.from_bytes(_b64url(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    raise SSOError("Unsupported signing key type.")


def verify_id_token(conn: SsoConnection, token: str, nonce: str, now: float | None = None,
                    jwks: dict | None = None) -> dict:
    try:
        head_b64, body_b64, sig_b64 = token.split(".")
        header, claims = json.loads(_b64url(head_b64)), json.loads(_b64url(body_b64))
        signature = _b64url(sig_b64)
    except (ValueError, TypeError) as exc:
        raise SSOError("Malformed ID token.") from exc
    alg = header.get("alg")
    if alg not in ("RS256", "ES256"):
        raise SSOError(f"ID token algorithm {alg!r} is not accepted.")
    keys = (jwks or _cached(discovery(conn.issuer)["jwks_uri"])).get("keys", [])
    candidates = [k for k in keys if k.get("kid") == header.get("kid")] or (keys if not header.get("kid") else [])
    signed = f"{head_b64}.{body_b64}".encode()
    for jwk in candidates:
        try:
            key = _public_key(jwk)
            if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
                key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
            elif alg == "ES256" and isinstance(key, ec.EllipticCurvePublicKey) and len(signature) == 64:
                der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
                key.verify(der, signed, ec.ECDSA(hashes.SHA256()))
            else:
                continue
            break
        except (InvalidSignature, SSOError, ValueError, KeyError):
            continue
    else:
        raise SSOError("The ID token signature could not be verified.")
    now = now or time.time()
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if str(claims.get("iss", "")).rstrip("/") != conn.issuer.rstrip("/"):
        raise SSOError("The ID token was issued by a different provider.")
    if conn.client_id not in auds or (len(auds) > 1 and claims.get("azp") not in (None, conn.client_id)):
        raise SSOError("The ID token is for a different application.")
    if not isinstance(claims.get("exp"), int | float) or claims["exp"] + CLOCK_SKEW < now:
        raise SSOError("The ID token has expired.")
    if isinstance(claims.get("iat"), int | float) and claims["iat"] - CLOCK_SKEW > now:
        raise SSOError("The ID token is not valid yet.")
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise SSOError("The ID token does not belong to this sign-in.")
    if not claims.get("sub"):
        raise SSOError("The ID token has no subject.")
    return claims


def _email(conn: SsoConnection, claims: dict) -> str:
    email = str(claims.get("email") or claims.get("preferred_username") or "").strip().lower()
    if "@" not in email:
        raise SSOError("The identity provider did not return an email address.")
    if claims.get("email_verified") is False:
        raise SSOError("The identity provider reports this email address as unverified.")
    domains = [d.lower() for d in conn.domains or []]
    if domains and email.rpartition("@")[2] not in domains:
        raise SSOError("Your email domain is not allowed for this organization's SSO.")
    return email


def resolve_user(conn: SsoConnection, claims: dict, linking_user: User | None = None) -> User:
    """The user for these claims, following the linking rules in the module docstring."""
    org = db.session.get(Organization, conn.organization_id)
    sub = str(claims["sub"])[:255]
    ident = db.session.execute(db.select(SsoIdentity).where(SsoIdentity.connection_id == conn.id,
                                                            SsoIdentity.subject == sub)).scalar_one_or_none()
    if linking_user is not None:
        if ident is not None and ident.user_id != linking_user.id:
            raise SSOError("This SSO account is already linked to another eVal account.")
        user = linking_user
    elif ident is not None:
        user = ident.user
    else:
        email = _email(conn, claims)
        user = db.session.execute(db.select(User).where(User.email == email)).scalar_one_or_none()
        if user is not None and user.managed_by_org_id != org.id:
            raise SSOError("An eVal account with this email already exists. Sign in with it, then link SSO from "
                           "your organization's sign-in page while signed in.")
        if user is None:
            if not conn.auto_provision:
                raise SSOError("Your account has not been provisioned for this organization. Ask an admin.")
            user = User(email=email, name=str(claims.get("name") or "")[:120], managed_by_org_id=org.id)
            user.set_unusable_password()
            db.session.add(user)
            db.session.flush()
            events.record("auth.sso_provisioned", organization_id=org.id, target=user, actor_id=user.id)
    if not user.is_active:
        raise SSOError("This account is disabled.")
    if ident is None:
        db.session.add(SsoIdentity(connection_id=conn.id, user_id=user.id, subject=sub, last_login_at=utcnow()))
    else:
        ident.last_login_at = utcnow()
    member = db.session.execute(db.select(Membership).where(Membership.user_id == user.id,
                                                            Membership.organization_id == org.id)).scalar_one_or_none()
    if member is None:
        if linking_user is not None and user.managed_by_org_id != org.id:
            raise SSOError("You are not a member of this organization.")
        db.session.add(Membership(user_id=user.id, organization_id=org.id, role=conn.default_role))
        events.record("member.added", organization_id=org.id, target=user, role=conn.default_role, via="sso")
    return user
