"""add composite index for document sync queries

Revision ID: b5e7a2c3d4f1
Revises: a4d2f6b9c1e7
Create Date: 2026-05-12 10:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "b5e7a2c3d4f1"
down_revision = "a4d2f6b9c1e7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_document_needs_sync",
        "document",
        ["last_modified", "last_synced"],
        postgresql_where="last_synced IS NULL OR last_modified > last_synced",
    )


def downgrade() -> None:
    op.drop_index("ix_document_needs_sync", table_name="document")
