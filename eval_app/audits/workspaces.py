from __future__ import annotations

from pathlib import Path

from flask import current_app

from eval_engine.workspace import Limits, WorkspaceError, clone_repo, extract_zip, remove_tree

from ..extensions import db
from ..integrations.services import github_clone_url, reveal
from ..models import Audit
from ..projects.repositories import upload_path


def prepare_workspace(audit: Audit, workdir: Path, limits: Limits) -> Path:
    """Materialize the audited source under ``workdir/src``. Never executes repository content."""
    remove_tree(workdir)
    src = workdir / "src"
    src.mkdir(parents=True)
    repo = audit.repository
    if repo.source == "upload":
        if audit.upload is None:
            raise WorkspaceError("The uploaded archive is no longer available.")
        stats = extract_zip(upload_path(audit.upload), src, limits)
        audit.commit_sha = audit.upload.sha256[:12]
        audit.stats = {**(audit.stats or {}), "extract_skipped": stats.skipped[:50]}
    else:
        token = reveal(repo.credential) if repo.credential else None
        result = clone_repo(
            github_clone_url(repo.full_name),
            src,
            audit.requested_ref or repo.default_branch,
            token=token,
            allowed_hosts=current_app.config["GIT_ALLOWED_HOSTS"],
            timeout=current_app.config["ANALYZER_TIMEOUT_SECONDS"],
            limits=limits,
        )
        audit.commit_sha = result.commit_sha
        remove_tree(src / ".git")  # analyzers never need git metadata; avoids leaking remote config
    db.session.commit()
    return src
