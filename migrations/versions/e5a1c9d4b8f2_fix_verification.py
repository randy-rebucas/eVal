"""fix proposal verification

Revision ID: e5a1c9d4b8f2
Revises: d2e9b5a7c3f1
Create Date: 2026-10-10 16:02:11.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e5a1c9d4b8f2'
down_revision = 'd2e9b5a7c3f1'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('fix_proposals', schema=None) as batch_op:
        batch_op.add_column(sa.Column('verification', sa.JSON(), nullable=False, server_default='{}'))


def downgrade():
    with op.batch_alter_table('fix_proposals', schema=None) as batch_op:
        batch_op.drop_column('verification')
