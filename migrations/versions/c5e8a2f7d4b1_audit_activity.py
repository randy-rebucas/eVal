"""audit running log

Revision ID: c5e8a2f7d4b1
Revises: b3d9e1a7c5f2
Create Date: 2026-10-11 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c5e8a2f7d4b1'
down_revision = 'b3d9e1a7c5f2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('audits', schema=None) as batch_op:
        batch_op.add_column(sa.Column('activity', sa.JSON(), nullable=False, server_default='[]'))


def downgrade():
    with op.batch_alter_table('audits', schema=None) as batch_op:
        batch_op.drop_column('activity')
