"""index foreign key columns

Revision ID: b7c1e4f2a9d3
Revises: 3aee66b5e98b
Create Date: 2026-10-10 12:00:00.000000

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'b7c1e4f2a9d3'
down_revision = '3aee66b5e98b'
branch_labels = None
depends_on = None

# PostgreSQL and SQLite do not index foreign keys automatically; joins and ON DELETE cascades need these.
INDEXES = [
    ('integration_credentials', 'created_by_id'),
    ('repositories', 'credential_id'),
    ('uploads', 'uploaded_by_id'),
    ('audits', 'upload_id'),
    ('audits', 'previous_audit_id'),
    ('audits', 'requested_by_id'),
    ('github_issue_links', 'created_by_id'),
    ('ai_settings', 'credential_id'),
    ('audit_events', 'actor_id'),
]


def upgrade():
    for table, column in INDEXES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.create_index(batch_op.f(f'ix_{table}_{column}'), [column], unique=False)


def downgrade():
    for table, column in reversed(INDEXES):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_index(batch_op.f(f'ix_{table}_{column}'))
