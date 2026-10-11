"""fix proposal revisions (hand edits) and the verifying status

Revision ID: a4f8c2e6b1d9
Revises: e7b4c2d9a1f5
Create Date: 2026-10-11 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a4f8c2e6b1d9'
down_revision = 'e7b4c2d9a1f5'
branch_labels = None
depends_on = None

OLD = "status IN ('queued','running','ready','failed','pr_opened')"
NEW = "status IN ('queued','running','verifying','ready','failed','pr_opened')"


def upgrade():
    with op.batch_alter_table('fix_proposals', schema=None) as batch_op:
        batch_op.add_column(sa.Column('revisions', sa.JSON(), nullable=False, server_default='[]'))
        batch_op.drop_constraint(batch_op.f('ck_fix_proposals_status_valid'), type_='check')
        batch_op.create_check_constraint(batch_op.f('ck_fix_proposals_status_valid'), NEW)


def downgrade():
    op.execute("UPDATE fix_proposals SET status = 'ready' WHERE status = 'verifying'")
    with op.batch_alter_table('fix_proposals', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('ck_fix_proposals_status_valid'), type_='check')
        batch_op.create_check_constraint(batch_op.f('ck_fix_proposals_status_valid'), OLD)
        batch_op.drop_column('revisions')
