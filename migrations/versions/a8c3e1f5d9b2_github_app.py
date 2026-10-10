"""github app installations and check runs

Revision ID: a8c3e1f5d9b2
Revises: f3b7d2e8a6c4
Create Date: 2026-10-10 18:40:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a8c3e1f5d9b2'
down_revision = 'f3b7d2e8a6c4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('github_installations',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('installation_id', sa.BigInteger(), nullable=False),
    sa.Column('account_login', sa.String(length=200), nullable=False),
    sa.Column('account_type', sa.String(length=32), nullable=False),
    sa.Column('suspended', sa.Boolean(), nullable=False),
    sa.Column('created_by_id', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_github_installations_created_by_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_github_installations_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_github_installations')),
    sa.UniqueConstraint('installation_id', name=op.f('uq_github_installations_installation_id'))
    )
    with op.batch_alter_table('github_installations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_github_installations_created_by_id'), ['created_by_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_github_installations_organization_id'), ['organization_id'], unique=False)

    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.add_column(sa.Column('github_installation_id', sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column('auto_audit', sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.create_index(batch_op.f('ix_repositories_github_installation_id'), ['github_installation_id'], unique=False)
        batch_op.create_foreign_key(batch_op.f('fk_repositories_github_installation_id_github_installations'), 'github_installations', ['github_installation_id'], ['id'], ondelete='SET NULL')

    with op.batch_alter_table('audits', schema=None) as batch_op:
        batch_op.add_column(sa.Column('check_run_id', sa.BigInteger(), nullable=True))


def downgrade():
    with op.batch_alter_table('audits', schema=None) as batch_op:
        batch_op.drop_column('check_run_id')

    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_repositories_github_installation_id_github_installations'), type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_repositories_github_installation_id'))
        batch_op.drop_column('auto_audit')
        batch_op.drop_column('github_installation_id')

    with op.batch_alter_table('github_installations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_github_installations_organization_id'))
        batch_op.drop_index(batch_op.f('ix_github_installations_created_by_id'))

    op.drop_table('github_installations')
