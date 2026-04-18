"""add persona skill metadata

Revision ID: a4d2f6b9c1e7
Revises: 503883791c39
Create Date: 2026-04-16 21:46:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "a4d2f6b9c1e7"
down_revision = "503883791c39"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "persona",
        sa.Column(
            "skill_keys",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "persona",
        sa.Column("prompt_preset_id", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("persona", "prompt_preset_id")
    op.drop_column("persona", "skill_keys")
