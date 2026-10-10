"""GitHub App webhook events: link installations, audit pull requests and default-branch pushes.

Only installations that an organization admin linked through the verified setup flow (``link_installation``) are
acted on; events for unknown installations are acknowledged and ignored. Repositories must already exist in that
organization: a webhook never creates repositories.
"""

from __future__ import annotations

from flask import current_app

from ..audits.services import AuditError, create_audit, create_pr_audit
from ..extensions import db
from ..models import Audit, GitHubInstallation, Organization, Repository
from ..security import events
from . import checks, github_app

PR_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


def link_installation(org: Organization, installation_id: int, user_id) -> GitHubInstallation:
    """Bind an installation to ``org`` (the caller has verified the user can access it)."""
    info = github_app.app_client().get_installation(installation_id)
    inst = db.session.execute(
        db.select(GitHubInstallation).where(GitHubInstallation.installation_id == installation_id)
    ).scalar_one_or_none()
    if inst is not None and inst.organization_id != org.id:
        raise ValueError("This GitHub App installation is already linked to another organization.")
    if inst is None:
        inst = GitHubInstallation(organization_id=org.id, installation_id=installation_id, created_by_id=user_id)
        db.session.add(inst)
    inst.account_login = info["account_login"][:200]
    inst.account_type = info["account_type"][:32]
    inst.suspended = info["suspended"]
    db.session.flush()
    linked = attach_repositories(inst)
    events.record("github_app.linked", organization_id=org.id, target=inst, account=inst.account_login,
                  repositories=linked)
    db.session.commit()
    return inst


def attach_repositories(inst: GitHubInstallation) -> int:
    """Use the installation for the organization's GitHub repositories owned by its account."""
    prefix = inst.account_login.lower() + "/"
    repos = db.session.execute(db.select(Repository).where(
        Repository.organization_id == inst.organization_id, Repository.source == "github",
        Repository.github_installation_id.is_(None))).scalars()
    n = 0
    for repo in repos:
        if repo.full_name.lower().startswith(prefix):
            repo.github_installation_id = inst.id
            n += 1
    return n


def _installation(payload: dict) -> GitHubInstallation | None:
    iid = (payload.get("installation") or {}).get("id")
    if not isinstance(iid, int):
        return None
    return db.session.execute(
        db.select(GitHubInstallation).where(GitHubInstallation.installation_id == iid)
    ).scalar_one_or_none()


def _repositories(inst: GitHubInstallation, full_name: str) -> list[Repository]:
    repos = db.session.execute(db.select(Repository).where(
        Repository.organization_id == inst.organization_id, Repository.source == "github",
        db.func.lower(Repository.full_name) == full_name.lower())).scalars().all()
    for repo in repos:
        if repo.github_installation_id is None:
            repo.github_installation_id = inst.id
    return [r for r in repos if r.auto_audit and r.github_installation_id == inst.id]


def handle(event: str, payload: dict) -> dict:
    """Process one verified delivery. Returns a small JSON-able summary (also useful in tests)."""
    if event == "ping":
        return {"ok": True}
    inst = _installation(payload)
    if inst is None:
        return {"ignored": "installation not linked to an organization"}
    action = payload.get("action", "")
    if event == "installation":
        return _on_installation(inst, action)
    if inst.suspended:
        return {"ignored": "installation suspended"}
    if event == "pull_request" and action in PR_ACTIONS:
        pr = payload.get("pull_request") or {}
        return _audit_pull(inst, (payload.get("repository") or {}).get("full_name", ""), pr.get("number"),
                           (pr.get("head") or {}).get("sha", ""))
    if event == "check_run" and action == "rerequested":
        run = payload.get("check_run") or {}
        prs = run.get("pull_requests") or []
        if prs:
            return _audit_pull(inst, (payload.get("repository") or {}).get("full_name", ""), prs[0].get("number"),
                               run.get("head_sha", ""), force=True)
        return {"ignored": "check run is not for a pull request"}
    if event == "push":
        return _audit_push(inst, payload)
    return {"ignored": f"event {event}/{action}"}


def remove_installation(inst: GitHubInstallation, action: str) -> None:
    """Forget an installation and detach its repositories (they fall back to their credential, if any)."""
    events.record(action, organization_id=inst.organization_id, target=inst, account=inst.account_login)
    github_app.forget_installation(inst.installation_id)
    db.session.execute(db.update(Repository).where(Repository.github_installation_id == inst.id)
                       .values(github_installation_id=None))
    db.session.delete(inst)


def _on_installation(inst: GitHubInstallation, action: str) -> dict:
    if action == "deleted":
        remove_installation(inst, "github_app.uninstalled")
    elif action in ("suspend", "unsuspend"):
        inst.suspended = action == "suspend"
        github_app.forget_installation(inst.installation_id)
    db.session.commit()
    return {"installation": action}


def _already_audited(repo: Repository, sha: str, pr_number: int | None) -> bool:
    q = db.select(Audit.id).where(Audit.repository_id == repo.id, Audit.requested_ref == sha,
                                  Audit.status.in_(("queued", "running", "succeeded")))
    q = q.where(Audit.pr_number == pr_number) if pr_number else q.where(Audit.pr_number.is_(None))
    return db.session.execute(q.limit(1)).first() is not None


def _audit_pull(inst, full_name: str, number, head_sha: str, force: bool = False) -> dict:
    if not isinstance(number, int) or not full_name:
        return {"ignored": "malformed pull request event"}
    org = db.session.get(Organization, inst.organization_id)
    started = []
    for repo in _repositories(inst, full_name):
        if not force and head_sha and _already_audited(repo, head_sha, number):
            continue
        try:
            audit = create_pr_audit(org, repo, None, number, trigger="pull_request")
        except AuditError as exc:
            current_app.logger.warning("webhook PR audit for %s#%s not started: %s", full_name, number, exc)
            continue
        _report_start(audit, head_sha or audit.requested_ref)
        started.append(str(audit.id))
    db.session.commit()
    return {"audits": started}


def _audit_push(inst, payload: dict) -> dict:
    repo_info = payload.get("repository") or {}
    ref, sha = payload.get("ref", ""), payload.get("after", "")
    if payload.get("deleted") or not sha or set(sha) == {"0"}:
        return {"ignored": "branch deleted"}
    org = db.session.get(Organization, inst.organization_id)
    started = []
    for repo in _repositories(inst, repo_info.get("full_name", "")):
        if ref != f"refs/heads/{repo.default_branch}" or _already_audited(repo, sha, None):
            continue
        try:
            # Recorded under the branch name: it becomes the baseline for pull requests into this branch.
            audit = create_audit(org, repo, None, ref=sha, trigger="push", branch=repo.default_branch)
        except AuditError as exc:
            current_app.logger.warning("webhook push audit for %s not started: %s", repo.full_name, exc)
            continue
        started.append(str(audit.id))
    db.session.commit()
    return {"audits": started}


def _report_start(audit: Audit, head_sha: str) -> None:
    """Create the check run; if the audit already finished (eager mode, or a fast worker), report it now."""
    checks.start(audit, head_sha)
    db.session.commit()
    db.session.refresh(audit)
    if audit.status in ("succeeded", "failed", "cancelled"):
        checks.complete(audit)
