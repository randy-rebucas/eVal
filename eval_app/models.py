"""SQLAlchemy models.

Tenancy rule: every tenant-owned row has a NOT NULL, indexed ``organization_id``. Services must always
filter by it (see ``eval_app.security.tenancy``). This also prepares for PostgreSQL Row Level Security.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

import sqlalchemy as sa
from flask_login import UserMixin
from sqlalchemy.orm import Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def utcnow() -> datetime:
    return datetime.now(UTC)


# Not a valid werkzeug hash, so nothing can match it.
UNUSABLE_PASSWORD = "!unusable"  # noqa: S105  # nosec B105 - a marker, not a credential


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


ROLES = ("viewer", "member", "admin", "owner")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}

AUDIT_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")
TRIAGE_STATUSES = ("open", "accepted_risk", "false_positive", "fixed")
TRIAGE_DISMISSED = ("accepted_risk", "false_positive")  # carried over to later audits; hidden from default views
LIFECYCLES = ("new", "existing", "recurring")


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utcnow, nullable=False)


class User(UserMixin, TimestampMixin, db.Model):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(sa.String(320), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(sa.String(120), nullable=False, default="")
    password_hash: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    is_active_flag: Mapped[bool] = mapped_column("is_active", sa.Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    # TOTP second factor (RFC 6238): encrypted secret, recovery-code hashes, last accepted time step (replay guard).
    mfa_secret_enc: Mapped[bytes | None] = mapped_column(sa.LargeBinary)
    mfa_enabled_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    mfa_recovery: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list, server_default="[]")
    mfa_last_step: Mapped[int | None] = mapped_column(sa.BigInteger)
    # Set when an organization created this account through SCIM or SSO; only that organization's SSO may link it.
    managed_by_org_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("organizations.id", ondelete="SET NULL"), index=True
    )

    memberships: Mapped[list[Membership]] = relationship(back_populates="user", cascade="all, delete-orphan",
                                                         foreign_keys="Membership.user_id")
    identities: Mapped[list[UserIdentity]] = relationship(back_populates="user", cascade="all, delete-orphan")

    @property
    def mfa_enabled(self) -> bool:
        return self.mfa_enabled_at is not None and self.mfa_secret_enc is not None

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="scrypt")

    def set_unusable_password(self) -> None:
        """Accounts created through social sign-in have no password; password login always fails for them."""
        self.password_hash = UNUSABLE_PASSWORD

    @property
    def has_password(self) -> bool:
        return self.password_hash != UNUSABLE_PASSWORD

    def check_password(self, password: str) -> bool:
        if not self.has_password:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self) -> bool:  # Flask-Login hook
        return self.is_active_flag

    def get_id(self) -> str:
        return str(self.id)


class UserIdentity(TimestampMixin, db.Model):
    """A GitHub, Google or LinkedIn account the user signs in with, keyed by the provider's stable user id."""

    __tablename__ = "user_identities"
    __table_args__ = (
        sa.UniqueConstraint("provider", "subject", name="uq_user_identities_provider_subject"),
        sa.UniqueConstraint("user_id", "provider", name="uq_user_identities_user_provider"),
        sa.CheckConstraint("provider IN ('github','google','linkedin')", name="provider_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
                                               index=True)
    provider: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    subject: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    email: Mapped[str] = mapped_column(sa.String(320), nullable=False, default="")
    last_login_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="identities")


class Organization(TimestampMixin, db.Model):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    slug: Mapped[str] = mapped_column(sa.String(64), unique=True, nullable=False, index=True)
    # Default audit policy (TOML, see eval_engine/policy.py) and whether repositories' .eval.toml files apply.
    policy_toml: Mapped[str] = mapped_column(sa.Text, nullable=False, default="", server_default="")
    allow_repo_policy_file: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True,
                                                         server_default=sa.true())
    # Members must have a second factor: TOTP, or a sign-in through this organization's SSO.
    require_mfa: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False, server_default=sa.false())
    # Members may open sandbox terminals that run this organization's code (docs/SANDBOX.md). Admin opt-in.
    allow_sandbox: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False,
                                                server_default=sa.false())

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class Membership(TimestampMixin, db.Model):
    __tablename__ = "memberships"
    __table_args__ = (
        sa.UniqueConstraint("user_id", "organization_id", name="uq_memberships_user_org"),
        sa.CheckConstraint("role IN ('viewer','member','admin','owner')", name="role_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="member")

    user: Mapped[User] = relationship(back_populates="memberships")
    organization: Mapped[Organization] = relationship(back_populates="memberships")


class TenantMixin:
    """Columns shared by all organization-owned tables."""

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=_uuid)


def org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(
        sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )


class Project(TenantMixin, TimestampMixin, db.Model):
    __tablename__ = "projects"
    __table_args__ = (sa.UniqueConstraint("organization_id", "slug", name="uq_projects_org_slug"),)

    organization_id: Mapped[uuid.UUID] = org_fk()
    name: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    slug: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    description: Mapped[str] = mapped_column(sa.Text, default="", nullable=False)

    repositories: Mapped[list[Repository]] = relationship(back_populates="project", cascade="all, delete-orphan")


class IntegrationCredential(TenantMixin, TimestampMixin, db.Model):
    """Encrypted third-party secret (GitHub PAT, AI API key). Plaintext never leaves the service layer."""

    __tablename__ = "integration_credentials"
    __table_args__ = (
        sa.CheckConstraint(
            "provider IN ('github','anthropic','openai','openai_compatible')", name="provider_valid"
        ),
    )

    organization_id: Mapped[uuid.UUID] = org_fk()
    provider: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    label: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    encrypted_secret: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    last4: Mapped[str] = mapped_column(sa.String(4), nullable=False, default="")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )


class SsoConnection(TenantMixin, TimestampMixin, db.Model):
    """An organization's OpenID Connect identity provider (Okta, Entra ID, Google Workspace, Keycloak, ...)."""

    __tablename__ = "sso_connections"
    __table_args__ = (sa.CheckConstraint("default_role IN ('viewer','member','admin')", name="role_valid"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    issuer: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    client_id: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    encrypted_client_secret: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    # Email domains this IdP is authoritative for; SSO users must have an address in one of them.
    domains: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    default_role: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="member")
    auto_provision: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    # Members must sign in through SSO to use this organization (owners keep password access as break-glass).
    enforce: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)


class SsoIdentity(TimestampMixin, db.Model):
    __tablename__ = "sso_identities"
    __table_args__ = (sa.UniqueConstraint("connection_id", "subject", name="uq_sso_identities_connection_subject"),)

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=_uuid)
    connection_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("sso_connections.id", ondelete="CASCADE"),
                                                     nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
                                               index=True)
    subject: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    user: Mapped[User] = relationship()


class ScimToken(TenantMixin, TimestampMixin, db.Model):
    """Bearer token for SCIM 2.0 provisioning (only a SHA-256 hash is stored)."""

    __tablename__ = "scim_tokens"

    organization_id: Mapped[uuid.UUID] = org_fk()
    prefix: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    token_hash: Mapped[str] = mapped_column(sa.String(64), unique=True, nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))


class GitHubInstallation(TenantMixin, TimestampMixin, db.Model):
    """A GitHub App installation linked to an organization. Tokens are minted per use, never stored."""

    __tablename__ = "github_installations"

    organization_id: Mapped[uuid.UUID] = org_fk()
    # GitHub's id; unique, so one installation can never serve two organizations.
    installation_id: Mapped[int] = mapped_column(sa.BigInteger, unique=True, nullable=False)
    account_login: Mapped[str] = mapped_column(sa.String(200), nullable=False, default="")
    account_type: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="")
    suspended: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )


class NotificationChannel(TenantMixin, TimestampMixin, db.Model):
    """Where an organization is told about regressions: a Slack or Teams incoming webhook, or a signed generic
    webhook. The URL is a secret (it authorizes posting) and is stored encrypted."""

    __tablename__ = "notification_channels"
    __table_args__ = (sa.CheckConstraint("kind IN ('slack','teams','webhook')", name="kind_valid"),)

    organization_id: Mapped[uuid.UUID] = org_fk()
    kind: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    label: Mapped[str] = mapped_column(sa.String(120), nullable=False, default="")
    encrypted_url: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    url_host: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="")  # shown instead of the URL
    # Generic webhooks: HMAC-SHA256 signing secret (encrypted); receivers verify X-Eval-Signature.
    encrypted_secret: Mapped[bytes | None] = mapped_column(sa.LargeBinary)
    events: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    last_status: Mapped[str] = mapped_column(sa.String(200), nullable=False, default="")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )


class Repository(TenantMixin, TimestampMixin, db.Model):
    __tablename__ = "repositories"
    __table_args__ = (
        sa.CheckConstraint("source IN ('github','upload')", name="source_valid"),
        # A GitHub repository is connected to a project at most once. Partial: uploads all have full_name "".
        sa.Index("uq_repositories_project_github_full_name", "project_id", "full_name", unique=True,
                 postgresql_where=sa.text("source = 'github'"), sqlite_where=sa.text("source = 'github'")),
    )

    organization_id: Mapped[uuid.UUID] = org_fk()
    project_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    # GitHub "owner/repo"; empty for uploads.
    full_name: Mapped[str] = mapped_column(sa.String(200), nullable=False, default="")
    default_branch: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="main")
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("integration_credentials.id", ondelete="SET NULL"), index=True
    )
    policy_toml: Mapped[str] = mapped_column(sa.Text, nullable=False, default="", server_default="")
    # GitHub App installation that grants access (preferred over ``credential`` when set).
    github_installation_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("github_installations.id", ondelete="SET NULL"), index=True
    )
    # Audit pull requests automatically when the GitHub App reports them (and the default branch on push).
    auto_audit: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True, server_default=sa.true())
    # Periodic re-audit of the default branch (or latest upload): off | daily | weekly. New CVEs appear in code
    # nobody touched, so a quiet repository still needs re-checking.
    schedule: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="off", server_default="off")

    project: Mapped[Project] = relationship(back_populates="repositories")
    credential: Mapped[IntegrationCredential | None] = relationship()
    installation: Mapped[GitHubInstallation | None] = relationship()
    audits: Mapped[list[Audit]] = relationship(
        back_populates="repository", cascade="all, delete-orphan", order_by="Audit.created_at.desc()"
    )


class Upload(TenantMixin, TimestampMixin, db.Model):
    __tablename__ = "uploads"

    organization_id: Mapped[uuid.UUID] = org_fk()
    repository_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    original_filename: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    # Server-generated relative path under DATA_DIR; never derived from the client filename.
    stored_path: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )


class Audit(TenantMixin, TimestampMixin, db.Model):
    __tablename__ = "audits"
    __table_args__ = (
        sa.CheckConstraint(
            "status IN ('queued','running','succeeded','failed','cancelled')", name="status_valid"
        ),
        sa.Index("ix_audits_repo_created", "repository_id", "created_at"),
    )

    organization_id: Mapped[uuid.UUID] = org_fk()
    repository_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("repositories.id", ondelete="CASCADE"))
    upload_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("uploads.id", ondelete="SET NULL"), index=True
    )
    previous_audit_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("audits.id", ondelete="SET NULL"), index=True
    )
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    branch: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="")
    commit_sha: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="")
    requested_ref: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="")
    trigger: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="ui")  # ui | api | pull_request
    pr_number: Mapped[int | None] = mapped_column(sa.Integer)
    pr_base_ref: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="")
    changed_files: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    check_run_id: Mapped[int | None] = mapped_column(sa.BigInteger)  # GitHub check run reporting this audit

    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="queued", index=True)
    stage: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="queued")
    progress: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    error: Mapped[str] = mapped_column(sa.Text, nullable=False, default="")
    celery_task_id: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="")

    overall_score: Mapped[float | None] = mapped_column(sa.Float)
    risk_level: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="")
    scores: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    severity_counts: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    tool_status: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    languages: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    stats: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    ai_summary: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    # Effective policy the audit ran with (eval_engine.policy.Policy.to_dict()); gates are evaluated against it.
    policy: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict, server_default="{}")
    engine_version: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="")

    started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    repository: Mapped[Repository] = relationship(back_populates="audits")
    upload: Mapped[Upload | None] = relationship()
    previous_audit: Mapped[Audit | None] = relationship(remote_side="Audit.id")
    findings: Mapped[list[Finding]] = relationship(back_populates="audit", cascade="all, delete-orphan")
    resolved: Mapped[list[ResolvedFinding]] = relationship(back_populates="audit", cascade="all, delete-orphan")

    @property
    def is_finished(self) -> bool:
        return self.status in ("succeeded", "failed", "cancelled")


class Rule(db.Model):
    """Global rule catalogue (not tenant-owned). Populated on demand as analyzers emit rule IDs."""

    __tablename__ = "rules"

    rule_id: Mapped[str] = mapped_column(sa.String(160), primary_key=True)
    tool: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    title: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    category: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    default_severity: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    references: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)


class FixProposal(TenantMixin, TimestampMixin, db.Model):
    """AI-generated fix for selected findings: a reviewed diff that can become a GitHub pull request."""

    __tablename__ = "fix_proposals"
    __table_args__ = (
        sa.CheckConstraint("status IN ('queued','running','verifying','ready','failed','pr_opened')",
                           name="status_valid"),
    )

    organization_id: Mapped[uuid.UUID] = org_fk()
    audit_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("audits.id", ondelete="CASCADE"), index=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="queued")
    finding_ids: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    # [{"path", "blob_sha", "after"}]: the new content of each changed file, and the blob it replaces.
    files: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    diff: Mapped[str] = mapped_column(sa.Text, nullable=False, default="")
    # {"fixed": [{"id", "summary", "files"}], "failed": [{"id", "reason"}]}
    results: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    ai_model: Mapped[str] = mapped_column(sa.String(160), nullable=False, default="")
    # Re-audit of the patched tree (eval_engine.verify.Verification.to_dict(), or {"verdict": "error", "error"}).
    verification: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict, server_default="{}")
    # Change history once a person edits the AI's files: [{"number", "kind": "ai"|"edit", "author", "at", "diff",
    # "verdict"}]. Empty while the proposal is exactly what the AI generated.
    revisions: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list, server_default="[]")
    error: Mapped[str] = mapped_column(sa.Text, nullable=False, default="")
    branch: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="")
    pr_number: Mapped[int | None] = mapped_column(sa.Integer)
    pr_url: Mapped[str] = mapped_column(sa.String(500), nullable=False, default="")
    finished_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    audit: Mapped[Audit] = relationship()
    created_by: Mapped[User | None] = relationship()

    @property
    def is_finished(self) -> bool:
        return self.status not in ("queued", "running", "verifying")

    @property
    def is_edited(self) -> bool:
        return any(r.get("kind") == "edit" for r in self.revisions or [])


class SandboxSession(TenantMixin, TimestampMixin, db.Model):
    """A terminal in the sandbox service, on the audited commit with a fix applied. The container lives there; this
    row is eVal's record of who opened it, for which fix, and how it ended."""

    __tablename__ = "sandbox_sessions"
    __table_args__ = (
        sa.CheckConstraint("status IN ('preparing','ready','ended','failed')", name="status_valid"),
    )

    organization_id: Mapped[uuid.UUID] = org_fk()
    fix_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("fix_proposals.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id", ondelete="SET NULL"), index=True)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="preparing")
    revision: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)  # fix revision copied in
    runtime: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="")
    network: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="")
    insecure: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    error: Mapped[str] = mapped_column(sa.Text, nullable=False, default="")
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    fix: Mapped[FixProposal] = relationship()
    user: Mapped[User | None] = relationship()

    @property
    def is_open(self) -> bool:
        expires = self.expires_at
        if expires is not None and expires.tzinfo is None:  # SQLite returns naive UTC datetimes
            expires = expires.replace(tzinfo=UTC)
        return self.status in ("preparing", "ready") and (expires is None or expires > utcnow())


class Finding(TenantMixin, TimestampMixin, db.Model):
    __tablename__ = "findings"
    __table_args__ = (
        sa.Index("ix_findings_audit_severity", "audit_id", "severity"),
        sa.Index("ix_findings_org_fingerprint", "organization_id", "fingerprint"),
        sa.Index("ix_findings_org_triage_expiry", "organization_id", "triage_status", "triage_expires_on"),
        sa.CheckConstraint(
            "triage_status IN ('open','accepted_risk','false_positive','fixed')", name="triage_valid"
        ),
    )

    organization_id: Mapped[uuid.UUID] = org_fk()
    audit_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("audits.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(sa.String(160), nullable=False)
    fingerprint: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    category: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    severity: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    kind: Mapped[str] = mapped_column(sa.String(24), nullable=False)
    title: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    description: Mapped[str] = mapped_column(sa.Text, nullable=False, default="")
    remediation: Mapped[str] = mapped_column(sa.Text, nullable=False, default="")
    file_path: Mapped[str] = mapped_column(sa.String(1000), nullable=False, default="")
    line_start: Mapped[int | None] = mapped_column(sa.Integer)
    line_end: Mapped[int | None] = mapped_column(sa.Integer)
    evidence: Mapped[str] = mapped_column(sa.Text, nullable=False, default="")
    sources: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    references: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    lifecycle: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="new")
    triage_status: Mapped[str] = mapped_column(sa.String(24), nullable=False, default="open")
    # Why the finding was accepted / dismissed, who is accountable for the fix (a team or a vendor, e.g. for
    # third-party code), and when the decision lapses. Accepted risks always expire; the finding then reopens.
    triage_reason: Mapped[str] = mapped_column(sa.Text, nullable=False, default="", server_default="")
    triage_owner: Mapped[str] = mapped_column(sa.String(200), nullable=False, default="", server_default="")
    triage_expires_on: Mapped[date | None] = mapped_column(sa.Date)
    triaged_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    triaged_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    ai_explanation: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    # Dependency vulnerabilities: imported | not-imported | transitive (eval_engine.reachability); "" otherwise.
    reachability: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="", server_default="")

    audit: Mapped[Audit] = relationship(back_populates="findings")
    triaged_by: Mapped[User | None] = relationship()

    @property
    def location(self) -> str:
        if not self.file_path:
            return "(repository)"
        if self.line_start:
            return f"{self.file_path}:{self.line_start}"
        return self.file_path


class ResolvedFinding(TenantMixin, db.Model):
    """A fingerprint present in the previous audit and absent from this one."""

    __tablename__ = "resolved_findings"

    organization_id: Mapped[uuid.UUID] = org_fk()
    audit_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("audits.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(sa.String(160), nullable=False)
    title: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    severity: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    category: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    file_path: Mapped[str] = mapped_column(sa.String(1000), nullable=False, default="")

    audit: Mapped[Audit] = relationship(back_populates="resolved")


class GitHubIssueLink(TenantMixin, TimestampMixin, db.Model):
    __tablename__ = "github_issue_links"
    __table_args__ = (
        sa.UniqueConstraint("repository_id", "fingerprint", name="uq_issue_links_repo_fingerprint"),
    )

    organization_id: Mapped[uuid.UUID] = org_fk()
    repository_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("repositories.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    issue_number: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    issue_url: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )


class AISettings(TenantMixin, TimestampMixin, db.Model):
    __tablename__ = "ai_settings"
    __table_args__ = (sa.UniqueConstraint("organization_id", name="uq_ai_settings_org"),)

    organization_id: Mapped[uuid.UUID] = org_fk()
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    provider: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="disabled")
    model: Mapped[str] = mapped_column(sa.String(120), nullable=False, default="")
    base_url: Mapped[str] = mapped_column(sa.String(300), nullable=False, default="")
    max_findings: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=15)
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("integration_credentials.id", ondelete="SET NULL"), index=True
    )

    credential: Mapped[IntegrationCredential | None] = relationship()


class ApiToken(TenantMixin, TimestampMixin, db.Model):
    __tablename__ = "api_tokens"

    organization_id: Mapped[uuid.UUID] = org_fk()
    user_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    prefix: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    token_hash: Mapped[str] = mapped_column(sa.String(64), unique=True, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    user: Mapped[User] = relationship()


class AuditEvent(TenantMixin, db.Model):
    """Security audit log of who did what. Never stores secrets."""

    __tablename__ = "audit_events"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(sa.String(40), nullable=False, default="")
    target_id: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="")
    ip: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="")
    details: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utcnow, nullable=False)
