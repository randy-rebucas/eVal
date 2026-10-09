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

    memberships: Mapped[list[Membership]] = relationship(back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self) -> bool:  # Flask-Login hook
        return self.is_active_flag

    def get_id(self) -> str:
        return str(self.id)


class Organization(TimestampMixin, db.Model):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    slug: Mapped[str] = mapped_column(sa.String(64), unique=True, nullable=False, index=True)

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
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id", ondelete="SET NULL"))


class Repository(TenantMixin, TimestampMixin, db.Model):
    __tablename__ = "repositories"
    __table_args__ = (sa.CheckConstraint("source IN ('github','upload')", name="source_valid"),)

    organization_id: Mapped[uuid.UUID] = org_fk()
    project_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    # GitHub "owner/repo"; empty for uploads.
    full_name: Mapped[str] = mapped_column(sa.String(200), nullable=False, default="")
    default_branch: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="main")
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("integration_credentials.id", ondelete="SET NULL")
    )

    project: Mapped[Project] = relationship(back_populates="repositories")
    credential: Mapped[IntegrationCredential | None] = relationship()
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
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id", ondelete="SET NULL"))


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
    upload_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("uploads.id", ondelete="SET NULL"))
    previous_audit_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("audits.id", ondelete="SET NULL"))
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id", ondelete="SET NULL"))

    branch: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="")
    commit_sha: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="")
    requested_ref: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="")
    trigger: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="ui")  # ui | api | pull_request
    pr_number: Mapped[int | None] = mapped_column(sa.Integer)
    pr_base_ref: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="")
    changed_files: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)

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
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id", ondelete="SET NULL"))


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
        sa.ForeignKey("integration_credentials.id", ondelete="SET NULL")
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
    actor_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(sa.String(40), nullable=False, default="")
    target_id: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="")
    ip: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="")
    details: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=utcnow, nullable=False)
