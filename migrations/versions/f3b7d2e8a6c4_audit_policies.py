"""audit policies

Revision ID: f3b7d2e8a6c4
Revises: e5a1c9d4b8f2
Create Date: 2026-10-10 17:20:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f3b7d2e8a6c4'
down_revision = 'e5a1c9d4b8f2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('policy_toml', sa.Text(), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('allow_repo_policy_file', sa.Boolean(), nullable=False,
                                      server_default=sa.true()))
    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.add_column(sa.Column('policy_toml', sa.Text(), nullable=False, server_default=''))
    with op.batch_alter_table('audits', schema=None) as batch_op:
        batch_op.add_column(sa.Column('policy', sa.JSON(), nullable=False, server_default='{}'))


def downgrade():
    with op.batch_alter_table('audits', schema=None) as batch_op:
        batch_op.drop_column('policy')
    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.drop_column('policy_toml')
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('allow_repo_policy_file')
        batch_op.drop_column('policy_toml')
