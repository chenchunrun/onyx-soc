"""add_memory_layers

Add layer / importance / last_accessed_at / distilled_from_ids columns to the
memory table to support two-tier (raw + distilled) memory with periodic
distillation.

Revision ID: d1a2b3c4e5f6
Revises: c9f3b7e2a6d4
Create Date: 2026-07-02 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "d1a2b3c4e5f6"
down_revision = "c9f3b7e2a6d4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # layer: "raw" (original memories) or "distilled" (consolidated by the
    # distillation task). Existing rows default to "raw".
    op.add_column(
        "memory",
        sa.Column("layer", sa.String(), nullable=False, server_default="raw"),
    )
    # importance: 0.0–1.0 score assigned during distillation.
    op.add_column(
        "memory",
        sa.Column("importance", sa.Float(), nullable=False, server_default="0.5"),
    )
    # last_accessed_at: when the memory was last injected into a prompt
    # (used for recency-based decay).
    op.add_column(
        "memory",
        sa.Column("last_accessed_at", sa.DateTime(timezone=True), nullable=True),
    )
    # distilled_from_ids: list of raw memory ids that were merged into this
    # distilled memory (provenance). Only set on distilled-layer rows.
    op.add_column(
        "memory",
        sa.Column("distilled_from_ids", sa.JSON(), nullable=True),
    )

    # Index for efficient per-user, per-layer queries.
    op.create_index(
        "ix_memory_user_id_layer",
        "memory",
        ["user_id", "layer"],
    )


def downgrade() -> None:
    op.drop_index("ix_memory_user_id_layer", table_name="memory")
    op.drop_column("memory", "distilled_from_ids")
    op.drop_column("memory", "last_accessed_at")
    op.drop_column("memory", "importance")
    op.drop_column("memory", "layer")
