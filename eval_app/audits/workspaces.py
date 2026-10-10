from __future__ import annotations

from pathlib import Path

from flask import current_app

from eval_engine.workspace import Limits, WorkspaceError, clone_repo, extract_zip, remove_tree

from ..extensions import db
from ..integrations.services import CredentialError, github_clone_url, repo_token
from ..models import Audit
from ..projects.repositories import upload_path


def fetch_source(audit: Audit, src: Path, limits: Limits, ref: str | None = None) -> tuple[str, list]:
    """Fetch the audit's source into the existing empty directory ``src``. Returns (commit sha, skipped archive
    members). ``ref`` defaults to the requested ref; pass the audited commit to get exactly that tree again."""
    repo = audit.repository
    if repo.source == "upload":
        if audit.upload is None:
            raise WorkspaceError("The uploaded archive is no longer available.")
        stats = extract_zip(upload_path(audit.upload), src, limits)
        return audit.upload.sha256[:12], stats.skipped
    try:
        token = repo_token(repo)
    except CredentialError as exc:
        raise WorkspaceError(str(exc)) from exc
    result = clone_repo(
        github_clone_url(repo.full_name),
        src,
        ref or audit.requested_ref or repo.default_branch,
        token=token,
        allowed_hosts=current_app.config["GIT_ALLOWED_HOSTS"],
        timeout=current_app.config["ANALYZER_TIMEOUT_SECONDS"],
        limits=limits,
    )
    remove_tree(src / ".git")  # analyzers never need git metadata; avoids leaking remote config
    return result.commit_sha, []


def prepare_workspace(audit: Audit, workdir: Path, limits: Limits) -> Path:
    """Materialize the audited source under ``workdir/src``. Never executes repository content."""
    remove_tree(workdir)
    src = workdir / "src"
    src.mkdir(parents=True)
    audit.commit_sha, skipped = fetch_source(audit, src, limits)
    if audit.repository.source == "upload":
        audit.stats = {**(audit.stats or {}), "extract_skipped": skipped[:50]}
    db.session.commit()
    return src


def limits_from_config() -> Limits:
    cfg = current_app.config
    return Limits(
        max_files=cfg["WORKSPACE_MAX_FILES"],
        max_total_bytes=cfg["WORKSPACE_MAX_TOTAL_MB"] * 1024 * 1024,
        max_file_bytes=cfg["WORKSPACE_MAX_FILE_MB"] * 1024 * 1024,
    )
