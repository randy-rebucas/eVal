"""Notifications: tell an organization when an audit regresses, a gate fails, or an audit fails.

Channels are Slack or Microsoft Teams incoming webhooks, or a generic HTTPS webhook signed with HMAC-SHA256
(``X-Eval-Signature: sha256=<hex>`` over the raw body). Webhook URLs are validated against SSRF: HTTPS only, the
documented Slack/Teams hosts for those kinds, and for generic webhooks a public address (checked again when sending,
redirects are not followed). Delivery is best-effort and never fails an audit.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
from urllib.parse import urlsplit

from flask import current_app

from .extensions import db
from .models import Audit, NotificationChannel, Organization
from .security import crypto, events

EVENTS = {
    "audit.regressed": "Score dropped or new high/critical findings on a branch",
    "gate.failed": "Policy gate failed on a branch audit",
    "audit.failed": "An audit could not complete",
}
KINDS = {"slack": "Slack incoming webhook", "teams": "Microsoft Teams incoming webhook / workflow",
         "webhook": "Generic HTTPS webhook (signed)"}
SLACK_HOSTS = ("hooks.slack.com",)
TEAMS_SUFFIXES = (".webhook.office.com", ".logic.azure.com", ".powerplatform.com")
REGRESSION_POINTS = 5.0  # score drop that counts as a regression
TIMEOUT = (5, 10)


class NotificationError(ValueError):
    pass


def _public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast \
                or ip.is_unspecified:
            return False
    return bool(infos)


def validate_url(kind: str, url: str) -> str:
    """Return the URL's host, or raise NotificationError."""
    url = (url or "").strip()
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or parts.username or parts.password or len(url) > 2000:
        raise NotificationError("Use an https:// URL without embedded credentials.")
    if parts.port not in (None, 443):
        raise NotificationError("Custom ports are not allowed.")
    if kind == "slack" and host not in SLACK_HOSTS:
        raise NotificationError("Slack webhook URLs start with https://hooks.slack.com/.")
    if kind == "teams" and not host.endswith(TEAMS_SUFFIXES):
        raise NotificationError("Teams webhook URLs are on webhook.office.com, logic.azure.com or powerplatform.com.")
    if kind == "webhook" and not current_app.config.get("TESTING") and not _public(host):
        raise NotificationError("The webhook host must resolve to a public address.")
    return host


def add_channel(org: Organization, kind: str, label: str, url: str, events_: list[str], user_id) -> tuple:
    """Create a channel. Returns (channel, signing secret or None); the secret is shown to the admin once."""
    import secrets as _secrets

    if kind not in KINDS:
        raise NotificationError("Unknown channel type.")
    chosen = [e for e in events_ if e in EVENTS] or list(EVENTS)
    host = validate_url(kind, url)
    secret = _secrets.token_urlsafe(32) if kind == "webhook" else None
    channel = NotificationChannel(organization_id=org.id, kind=kind, label=(label or KINDS[kind]).strip()[:120],
                                  encrypted_url=crypto.encrypt(url.strip()), url_host=host,
                                  encrypted_secret=crypto.encrypt(secret) if secret else None, events=chosen,
                                  created_by_id=user_id)
    db.session.add(channel)
    db.session.flush()
    events.record("notification.channel_added", organization_id=org.id, target=channel, kind=kind, host=host)
    db.session.commit()
    return channel, secret


# ------------------------------------------------------------------------------------------------ messages
def _link(audit: Audit) -> str:
    org = db.session.get(Organization, audit.organization_id)
    base = (current_app.config.get("PUBLIC_URL") or "").rstrip("/")
    return f"{base}/o/{org.slug}/audits/{audit.id}" if base else ""


def regression(audit: Audit) -> dict | None:
    """Drift since the previous audit of the same branch: a score drop or new high/critical findings."""
    if audit.status != "succeeded" or audit.pr_number or not audit.previous_audit_id:
        return None
    prev = db.session.get(Audit, audit.previous_audit_id)
    if prev is None or prev.overall_score is None or audit.overall_score is None:
        return None
    drop = round(prev.overall_score - audit.overall_score, 1)
    severe = [f for f in audit.findings if f.lifecycle in ("new", "recurring") and f.severity in ("critical", "high")
              and f.kind != "ai_observation" and f.triage_status == "open"]
    if drop < REGRESSION_POINTS and not severe:
        return None
    return {"score_before": prev.overall_score, "score_after": audit.overall_score, "drop": drop,
            "new_severe": len(severe), "examples": [f"[{f.severity}] {f.title} ({f.location})" for f in severe[:5]]}


def message(event: str, audit: Audit, details: dict) -> dict:
    repo = audit.repository
    where = f"{repo.full_name or repo.name}" + (f" @ {audit.branch}" if audit.branch else "")
    if event == "audit.regressed":
        head = f"eVal: {where} regressed"
        lines = [f"Score {details['score_before']} → {details['score_after']}"
                 + (f" ({details['new_severe']} new high/critical finding(s))" if details["new_severe"] else "")]
        lines += [f"• {x}" for x in details["examples"]]
    elif event == "gate.failed":
        head = f"eVal: policy gate failed for {where}"
        lines = [f"• {r}" for r in details.get("reasons", [])]
    else:
        head = f"eVal: audit of {where} failed"
        lines = [audit.error[:300] if audit.error else "The audit did not complete."]
    link = _link(audit)
    return {"title": head, "text": "\n".join(lines), "link": link,
            "payload": {"event": event, "audit_id": str(audit.id), "repository": repo.full_name or repo.name,
                        "branch": audit.branch, "commit": audit.commit_sha, "score": audit.overall_score,
                        "risk": audit.risk_level, "details": details, "url": link}}


def _body(channel: NotificationChannel, msg: dict) -> bytes:
    text = f"*{msg['title']}*\n{msg['text']}" + (f"\n<{msg['link']}|Open in eVal>" if msg["link"] else "")
    if channel.kind == "slack":
        return json.dumps({"text": text}).encode()
    if channel.kind == "teams":
        teams = f"**{msg['title']}**\n\n{msg['text']}" + (f"\n\n[Open in eVal]({msg['link']})" if msg["link"] else "")
        return json.dumps({"text": teams}).encode()
    return json.dumps(msg["payload"], sort_keys=True).encode()


def deliver(channel: NotificationChannel, msg: dict, session=None) -> str:
    import requests

    http = session or requests
    url = crypto.decrypt(channel.encrypted_url)
    validate_url(channel.kind, url)  # again at send time (DNS may have changed)
    body = _body(channel, msg)
    headers = {"Content-Type": "application/json", "User-Agent": "eVal-notifier"}
    if channel.kind == "webhook" and channel.encrypted_secret:
        secret = crypto.decrypt(channel.encrypted_secret)
        headers["X-Eval-Signature"] = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Eval-Event"] = msg["payload"]["event"]
    try:
        resp = http.post(url, data=body, headers=headers, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as exc:
        return f"error: {type(exc).__name__}"
    return f"HTTP {resp.status_code}"


def notify(event: str, audit: Audit, details: dict, session=None) -> int:
    """Send ``event`` to the organization's subscribed channels. Returns the number of deliveries attempted."""
    channels = db.session.execute(db.select(NotificationChannel).where(
        NotificationChannel.organization_id == audit.organization_id, NotificationChannel.enabled.is_(True))
    ).scalars().all()
    msg = message(event, audit, details)
    sent = 0
    for channel in channels:
        if event not in (channel.events or []):
            continue
        try:
            status = deliver(channel, msg, session=session)
        except (NotificationError, ValueError) as exc:
            status = f"error: {exc}"
        channel.last_status = status[:200]
        sent += 1
    if sent:
        db.session.commit()
    return sent


def after_audit(audit: Audit, session=None) -> None:
    """Called when an audit finishes: regression, gate and failure events (branch audits only)."""
    if audit.pr_number:
        return  # pull requests report through check runs and PR comments
    if audit.status == "failed":
        notify("audit.failed", audit, {}, session=session)
        return
    if audit.status != "succeeded":
        return
    drift = regression(audit)
    if drift:
        notify("audit.regressed", audit, drift, session=session)
    from . import policies

    gate = policies.evaluate(audit)
    if gate.passed:
        return
    # Only on the transition to failing, so a repository with known debt does not page on every audit.
    prev = db.session.get(Audit, audit.previous_audit_id) if audit.previous_audit_id else None
    if prev is not None and prev.status == "succeeded" and not policies.evaluate(prev).passed:
        return
    notify("gate.failed", audit, gate.to_dict(), session=session)
