"""mfa, sso connections and scim tokens

Revision ID: c7e2a9f4b6d1
Revises: b9d4f2a7c1e3
Create Date: 2026-10-10 21:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c7e2a9f4b6d1'
down_revision = 'b9d4f2a7c1e3'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('mfa_secret_enc', sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column('mfa_enabled_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('mfa_recovery', sa.JSON(), nullable=False, server_default='[]'))
        batch_op.add_column(sa.Column('mfa_last_step', sa.BigInteger(), nullable=True))
        batch_op.add_column(sa.Column('managed_by_org_id', sa.Uuid(), nullable=True))
        batch_op.create_index(batch_op.f('ix_users_managed_by_org_id'), ['managed_by_org_id'], unique=False)
        batch_op.create_foreign_key(batch_op.f('fk_users_managed_by_org_id_organizations'), 'organizations',
                                    ['managed_by_org_id'], ['id'], ondelete='SET NULL')

    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('require_mfa', sa.Boolean(), nullable=False, server_default=sa.false()))

    op.create_table('sso_connections',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('issuer', sa.String(length=500), nullable=False),
    sa.Column('client_id', sa.String(length=255), nullable=False),
    sa.Column('encrypted_client_secret', sa.LargeBinary(), nullable=False),
    sa.Column('domains', sa.JSON(), nullable=False),
    sa.Column('default_role', sa.String(length=16), nullable=False),
    sa.Column('auto_provision', sa.Boolean(), nullable=False),
    sa.Column('enforce', sa.Boolean(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("default_role IN ('viewer','member','admin')", name=op.f('ck_sso_connections_role_valid')),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_sso_connections_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sso_connections')),
    sa.UniqueConstraint('organization_id', name=op.f('uq_sso_connections_organization_id'))
    )
    op.create_table('sso_identities',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('connection_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('subject', sa.String(length=255), nullable=False),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['connection_id'], ['sso_connections.id'], name=op.f('fk_sso_identities_connection_id_sso_connections'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_sso_identities_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sso_identities')),
    sa.UniqueConstraint('connection_id', 'subject', name='uq_sso_identities_connection_subject')
    )
    with op.batch_alter_table('sso_identities', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_sso_identities_connection_id'), ['connection_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_sso_identities_user_id'), ['user_id'], unique=False)

    op.create_table('scim_tokens',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('prefix', sa.String(length=16), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('created_by_id', sa.Uuid(), nullable=True),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_scim_tokens_created_by_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_scim_tokens_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scim_tokens')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_scim_tokens_token_hash'))
    )
    with op.batch_alter_table('scim_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_scim_tokens_created_by_id'), ['created_by_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_scim_tokens_organization_id'), ['organization_id'], unique=False)


def downgrade():
    with op.batch_alter_table('scim_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_scim_tokens_organization_id'))
        batch_op.drop_index(batch_op.f('ix_scim_tokens_created_by_id'))
    op.drop_table('scim_tokens')
    with op.batch_alter_table('sso_identities', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_sso_identities_user_id'))
        batch_op.drop_index(batch_op.f('ix_sso_identities_connection_id'))
    op.drop_table('sso_identities')
    op.drop_table('sso_connections')
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('require_mfa')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_users_managed_by_org_id_organizations'), type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_users_managed_by_org_id'))
        batch_op.drop_column('managed_by_org_id')
        batch_op.drop_column('mfa_last_step')
        batch_op.drop_column('mfa_recovery')
        batch_op.drop_column('mfa_enabled_at')
        batch_op.drop_column('mfa_secret_enc')
