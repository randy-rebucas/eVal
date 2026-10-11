"""sandbox terminal sessions and the per-organization opt-in

Revision ID: b3d9e1a7c5f2
Revises: a4f8c2e6b1d9
Create Date: 2026-10-11 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b3d9e1a7c5f2'
down_revision = 'a4f8c2e6b1d9'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('allow_sandbox', sa.Boolean(), nullable=False, server_default=sa.false()))

    op.create_table('sandbox_sessions',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('fix_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('revision', sa.Integer(), nullable=False),
    sa.Column('runtime', sa.String(length=32), nullable=False),
    sa.Column('network', sa.String(length=64), nullable=False),
    sa.Column('insecure', sa.Boolean(), nullable=False),
    sa.Column('error', sa.Text(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("status IN ('preparing','ready','ended','failed')", name=op.f('ck_sandbox_sessions_status_valid')),
    sa.ForeignKeyConstraint(['fix_id'], ['fix_proposals.id'], name=op.f('fk_sandbox_sessions_fix_id_fix_proposals'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_sandbox_sessions_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_sandbox_sessions_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sandbox_sessions'))
    )
    with op.batch_alter_table('sandbox_sessions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_sandbox_sessions_fix_id'), ['fix_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_sandbox_sessions_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_sandbox_sessions_user_id'), ['user_id'], unique=False)


def downgrade():
    with op.batch_alter_table('sandbox_sessions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_sandbox_sessions_user_id'))
        batch_op.drop_index(batch_op.f('ix_sandbox_sessions_organization_id'))
        batch_op.drop_index(batch_op.f('ix_sandbox_sessions_fix_id'))
    op.drop_table('sandbox_sessions')

    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('allow_sandbox')
