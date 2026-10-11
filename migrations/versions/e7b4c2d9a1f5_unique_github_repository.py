"""unique github repository per project

Revision ID: e7b4c2d9a1f5
Revises: d8f3b1c6e9a4
Create Date: 2026-10-11 10:00:00.000000

Connecting a repository checked for an existing row and then inserted, so two concurrent requests could both
insert. The partial unique index makes the database enforce it (uploads are excluded: they all have an empty
full_name). Duplicates already in the table must be resolved by hand first, because each one may own audits.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e7b4c2d9a1f5'
down_revision = 'd8f3b1c6e9a4'
branch_labels = None
depends_on = None

INDEX = 'uq_repositories_project_github_full_name'
WHERE = "source = 'github'"


def upgrade():
    bind = op.get_bind()
    duplicates = bind.execute(sa.text(
        "SELECT project_id, full_name, COUNT(*) FROM repositories WHERE source = 'github' "
        "GROUP BY project_id, full_name HAVING COUNT(*) > 1"
    )).fetchall()
    if duplicates:
        listed = ", ".join(f"{name} (project {pid}, {n} rows)" for pid, name, n in duplicates[:10])
        raise RuntimeError(
            f"Cannot add {INDEX}: {len(duplicates)} GitHub repositories are connected more than once to the same "
            f"project: {listed}. Delete or merge the extra rows (they may own audits), then run the upgrade again."
        )
    if bind.dialect.name == "postgresql":
        # CONCURRENTLY does not block writes while the index builds; it cannot run inside a transaction.
        with op.get_context().autocommit_block():
            op.create_index(INDEX, 'repositories', ['project_id', 'full_name'], unique=True,
                            postgresql_where=sa.text(WHERE), postgresql_concurrently=True)
    else:
        op.create_index(INDEX, 'repositories', ['project_id', 'full_name'], unique=True,
                        sqlite_where=sa.text(WHERE))


def downgrade():
    op.drop_index(INDEX, table_name='repositories')
