"""Repository connection (GitHub) and source uploads (ZIP)."""

from __future__ import annotations

import hashlib
import uuid
import zipfile
from pathlib import Path

from flask import current_app
from sqlalchemy.exc import IntegrityError
from werkzeug.datastructures import FileStorage

from ..extensions import db
from ..integrations.github import GitHubError, validate_full_name
from ..integrations.services import github_client
from ..models import IntegrationCredential, Organization, Project, Repository, Upload
from ..security import events


class RepositoryError(Exception):
    pass


def _credential(org: Organization, credential_id) -> IntegrationCredential | None:
    if not credential_id:
        return None
    try:
        cid = uuid.UUID(str(credential_id))
    except ValueError as exc:
        raise RepositoryError("Unknown credential.") from exc
    cred = db.session.execute(
        db.select(IntegrationCredential).where(
            IntegrationCredential.id == cid,
            IntegrationCredential.organization_id == org.id,
            IntegrationCredential.provider == "github",
        )
    ).scalar_one_or_none()
    if cred is None:
        raise RepositoryError("Unknown credential.")
    return cred


def add_github_repository(org: Organization, project: Project, full_name: str, credential_id=None) -> Repository:
    try:
        full_name = validate_full_name(full_name)
    except GitHubError as exc:
        raise RepositoryError(str(exc)) from exc
    cred = _credential(org, credential_id)
    try:
        info = github_client(cred).get_repo(full_name)
    except GitHubError as exc:
        raise RepositoryError(str(exc)) from exc
    max_kb = current_app.config["WORKSPACE_MAX_TOTAL_MB"] * 1024
    if info.size_kb > max_kb:
        raise RepositoryError(f"Repository is {info.size_kb // 1024} MB; the limit is {max_kb // 1024} MB.")
    exists = db.session.execute(
        db.select(Repository.id).where(
            Repository.project_id == project.id, Repository.source == "github", Repository.full_name == info.full_name
        )
    ).first()
    if exists:
        raise RepositoryError("That repository is already connected to this project.")
    repo = Repository(
        organization_id=org.id,
        project_id=project.id,
        source="github",
        name=info.full_name,
        full_name=info.full_name,
        default_branch=info.default_branch,
        credential_id=cred.id if cred else None,
    )
    db.session.add(repo)
    try:
        db.session.flush()
    except IntegrityError as exc:  # connected by a concurrent request after the check above
        db.session.rollback()
        raise RepositoryError("That repository is already connected to this project.") from exc
    events.record("repository.connected", organization_id=org.id, target=repo, full_name=info.full_name)
    db.session.commit()
    return repo


MAX_BULK_CONNECT = 50


def browse_github_repositories(org: Organization, project: Project, credential_id=None,
                               owner: str = "") -> list[dict]:
    """Repositories visible to the credential (or an owner's public ones), each marked if already connected."""
    owner = owner.strip().removeprefix("https://github.com/").strip("/")
    cred = _credential(org, credential_id)
    if cred is None and not owner:
        raise RepositoryError("Choose a GitHub credential, or enter a user or organization to list.")
    try:
        repos = github_client(cred).list_repos(owner=owner or None)
    except GitHubError as exc:
        raise RepositoryError(str(exc)) from exc
    connected = set(db.session.execute(
        db.select(Repository.full_name).where(Repository.project_id == project.id, Repository.source == "github")
    ).scalars())
    for r in repos:
        r["connected"] = r["full_name"] in connected
    return repos


def add_github_repositories(org: Organization, project: Project, full_names: list[str],
                            credential_id=None) -> tuple[list[Repository], list[str]]:
    """Connect each selected repository (each is re-checked on GitHub). Returns (connected, error messages)."""
    names = list(dict.fromkeys(n.strip() for n in full_names if n.strip()))
    if not names:
        raise RepositoryError("Select at least one repository.")
    if len(names) > MAX_BULK_CONNECT:
        raise RepositoryError(f"Connect at most {MAX_BULK_CONNECT} repositories at a time.")
    added, errors = [], []
    for name in names:
        try:
            added.append(add_github_repository(org, project, name, credential_id))
        except RepositoryError as exc:
            db.session.rollback()
            errors.append(f"{name}: {exc}")
    return added, errors


def create_upload_repository(org: Organization, project: Project, name: str) -> Repository:
    name = name.strip()[:200]
    if len(name) < 2:
        raise RepositoryError("Name must be at least 2 characters.")
    repo = Repository(organization_id=org.id, project_id=project.id, source="upload", name=name, default_branch="")
    db.session.add(repo)
    db.session.flush()
    events.record("repository.created", organization_id=org.id, target=repo, source="upload")
    return repo


def store_upload(org: Organization, repo: Repository, file: FileStorage, user_id) -> Upload:
    """Stream an uploaded ZIP to a server-chosen path, hashing as we go. Client filename is metadata only."""
    if repo.source != "upload":
        raise RepositoryError("Uploads are only allowed for upload-type repositories.")
    original = (file.filename or "upload.zip").replace("\\", "/").rsplit("/", 1)[-1][:255]
    if not original.lower().endswith(".zip"):
        raise RepositoryError("Upload a .zip archive.")
    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]
    rel = Path("uploads") / str(org.id) / f"{uuid.uuid4().hex}.zip"
    dest = current_app.config["DATA_DIR"] / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    try:
        with open(dest, "wb") as out:
            while chunk := file.stream.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise RepositoryError("Upload exceeds the size limit.")
                digest.update(chunk)
                out.write(chunk)
        if size == 0 or not zipfile.is_zipfile(dest):
            raise RepositoryError("Upload is not a valid ZIP archive.")
    except RepositoryError:
        dest.unlink(missing_ok=True)
        raise
    upload = Upload(
        organization_id=org.id,
        repository_id=repo.id,
        original_filename=original,
        stored_path=rel.as_posix(),
        sha256=digest.hexdigest(),
        size_bytes=size,
        uploaded_by_id=user_id,
    )
    db.session.add(upload)
    db.session.flush()
    events.record("upload.stored", organization_id=org.id, target=upload, sha256=upload.sha256, size=size)
    return upload


def upload_path(upload: Upload) -> Path:
    base = current_app.config["DATA_DIR"].resolve()
    path = (base / upload.stored_path).resolve()
    if base not in path.parents:
        raise RepositoryError("Invalid upload path.")
    return path


def latest_upload(repo: Repository) -> Upload | None:
    return db.session.execute(
        db.select(Upload)
        .where(Upload.repository_id == repo.id, Upload.organization_id == repo.organization_id)
        .order_by(Upload.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def set_repository_credential(org: Organization, repo: Repository, credential_id) -> None:
    if repo.source != "github":
        raise RepositoryError("Only GitHub repositories use credentials.")
    cred = _credential(org, credential_id)
    if cred is not None:
        try:
            github_client(cred).get_repo(repo.full_name)
        except GitHubError as exc:
            raise RepositoryError(f"That credential cannot access {repo.full_name}: {exc}") from exc
    repo.credential_id = cred.id if cred else None
    events.record("repository.credential_changed", organization_id=org.id, target=repo,
                  credential=str(cred.id) if cred else None)
    db.session.commit()


def delete_repository(org: Organization, repo: Repository) -> None:
    uploads = db.session.execute(db.select(Upload).where(Upload.repository_id == repo.id)).scalars().all()
    paths = [upload_path(u) for u in uploads]
    events.record("repository.deleted", organization_id=org.id, target=repo, name=repo.name)
    db.session.delete(repo)
    db.session.commit()
    for p in paths:
        p.unlink(missing_ok=True)
