"""scheduled audits and notification channels

Revision ID: b9d4f2a7c1e3
Revises: a8c3e1f5d9b2
Create Date: 2026-10-10 20:05:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b9d4f2a7c1e3'
down_revision = 'a8c3e1f5d9b2'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('notification_channels',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('label', sa.String(length=120), nullable=False),
    sa.Column('encrypted_url', sa.LargeBinary(), nullable=False),
    sa.Column('url_host', sa.String(length=255), nullable=False),
    sa.Column('encrypted_secret', sa.LargeBinary(), nullable=True),
    sa.Column('events', sa.JSON(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('last_status', sa.String(length=200), nullable=False),
    sa.Column('created_by_id', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("kind IN ('slack','teams','webhook')", name=op.f('ck_notification_channels_kind_valid')),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_notification_channels_created_by_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_notification_channels_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_notification_channels'))
    )
    with op.batch_alter_table('notification_channels', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_notification_channels_created_by_id'), ['created_by_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_notification_channels_organization_id'), ['organization_id'], unique=False)

    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.add_column(sa.Column('schedule', sa.String(length=16), nullable=False, server_default='off'))


def downgrade():
    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.drop_column('schedule')

    with op.batch_alter_table('notification_channels', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_notification_channels_organization_id'))
        batch_op.drop_index(batch_op.f('ix_notification_channels_created_by_id'))

    op.drop_table('notification_channels')
