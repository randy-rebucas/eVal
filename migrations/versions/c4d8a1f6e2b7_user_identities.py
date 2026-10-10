"""social sign-in identities (GitHub, Google, LinkedIn)

Revision ID: c4d8a1f6e2b7
Revises: b7c1e4f2a9d3
Create Date: 2026-10-10 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c4d8a1f6e2b7'
down_revision = 'b7c1e4f2a9d3'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('user_identities',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('provider', sa.String(length=16), nullable=False),
    sa.Column('subject', sa.String(length=255), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("provider IN ('github','google','linkedin')", name=op.f('ck_user_identities_provider_valid')),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_user_identities_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_user_identities')),
    sa.UniqueConstraint('provider', 'subject', name='uq_user_identities_provider_subject'),
    sa.UniqueConstraint('user_id', 'provider', name='uq_user_identities_user_provider')
    )
    with op.batch_alter_table('user_identities', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_identities_user_id'), ['user_id'], unique=False)


def downgrade():
    with op.batch_alter_table('user_identities', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_identities_user_id'))
    op.drop_table('user_identities')
