"""seed_skill_tool

Revision ID: c9f3b7e2a6d4
Revises: b5e7a2c3d4f1
Create Date: 2026-07-02 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "c9f3b7e2a6d4"
down_revision = "b5e7a2c3d4f1"
branch_labels = None
depends_on = None


SKILL_TOOL = {
    "name": "load_skill",
    "display_name": "Skill Loader",
    "description": (
        "Load skill instructions and reference files on demand. "
        "Use action='list' to see available skills, "
        "action='load' to get full skill instructions, "
        "action='read_file' to read reference documents."
    ),
    "in_code_tool_id": "SkillTool",
    "enabled": True,
}


def upgrade() -> None:
    conn = op.get_bind()

    existing = conn.execute(
        sa.text("SELECT id FROM tool WHERE in_code_tool_id = :in_code_tool_id"),
        {"in_code_tool_id": SKILL_TOOL["in_code_tool_id"]},
    ).fetchone()

    if existing:
        conn.execute(
            sa.text(
                """
                UPDATE tool
                SET name = :name,
                    display_name = :display_name,
                    description = :description
                WHERE in_code_tool_id = :in_code_tool_id
                """
            ),
            SKILL_TOOL,
        )
    else:
        conn.execute(
            sa.text(
                """
                INSERT INTO tool (name, display_name, description, in_code_tool_id, enabled)
                VALUES (:name, :display_name, :description, :in_code_tool_id, :enabled)
                """
            ),
            SKILL_TOOL,
        )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM tool WHERE in_code_tool_id = :in_code_tool_id"),
        {"in_code_tool_id": SKILL_TOOL["in_code_tool_id"]},
    )
