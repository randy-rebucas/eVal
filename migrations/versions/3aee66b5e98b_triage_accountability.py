"""triage accountability: reason, owner, expiry, who/when

Revision ID: 3aee66b5e98b
Revises: aa6215ee0d0a
Create Date: 2026-10-09 17:53:12.666028

"""
from datetime import UTC, datetime, timedelta

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3aee66b5e98b'
down_revision = 'aa6215ee0d0a'
branch_labels = None
depends_on = None

LEGACY_REVIEW_DAYS = 90


def upgrade():
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('triage_reason', sa.Text(), server_default='', nullable=False))
        batch_op.add_column(sa.Column('triage_owner', sa.String(length=200), server_default='', nullable=False))
        batch_op.add_column(sa.Column('triage_expires_on', sa.Date(), nullable=True))
        batch_op.add_column(sa.Column('triaged_by_id', sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column('triaged_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index('ix_findings_org_triage_expiry', ['organization_id', 'triage_status', 'triage_expires_on'], unique=False)
        batch_op.create_index(batch_op.f('ix_findings_triaged_by_id'), ['triaged_by_id'], unique=False)
        batch_op.create_foreign_key(batch_op.f('fk_findings_triaged_by_id_users'), 'users', ['triaged_by_id'], ['id'], ondelete='SET NULL')

    # Accepted risks recorded before this change have no reason or expiry. Give them a review date instead of
    # leaving them accepted forever; they reopen then unless someone re-accepts them with a reason and owner.
    review = (datetime.now(UTC) + timedelta(days=LEGACY_REVIEW_DAYS)).date()
    findings = sa.table('findings', sa.column('triage_status', sa.String), sa.column('triage_reason', sa.Text),
                        sa.column('triage_expires_on', sa.Date))
    op.execute(
        findings.update()
        .where(findings.c.triage_status == 'accepted_risk')
        .values(triage_expires_on=review,
                triage_reason='Accepted before reasons were required; review and re-accept with a reason and owner.')
    )


def downgrade():
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_findings_triaged_by_id_users'), type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_findings_triaged_by_id'))
        batch_op.drop_index('ix_findings_org_triage_expiry')
        batch_op.drop_column('triaged_at')
        batch_op.drop_column('triaged_by_id')
        batch_op.drop_column('triage_expires_on')
        batch_op.drop_column('triage_owner')
        batch_op.drop_column('triage_reason')
