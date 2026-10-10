"""finding reachability

Revision ID: d8f3b1c6e9a4
Revises: c7e2a9f4b6d1
Create Date: 2026-10-10 22:40:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd8f3b1c6e9a4'
down_revision = 'c7e2a9f4b6d1'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reachability', sa.String(length=16), nullable=False, server_default=''))


def downgrade():
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_column('reachability')
