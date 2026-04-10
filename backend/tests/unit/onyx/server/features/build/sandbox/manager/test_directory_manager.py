from pathlib import Path

from onyx.server.features.build.sandbox.manager.directory_manager import (
    DirectoryManager,
)


def test_setup_skills_only_copies_allowed_skills(tmp_path: Path) -> None:
    outputs_template = tmp_path / "templates" / "outputs"
    outputs_template.mkdir(parents=True, exist_ok=True)
    venv_template = tmp_path / "templates" / "venv"
    venv_template.mkdir(parents=True, exist_ok=True)
    skills_root = tmp_path / "skills"
    (skills_root / "safe-skill").mkdir(parents=True, exist_ok=True)
    (skills_root / "safe-skill" / "SKILL.md").write_text("# Safe", encoding="utf-8")
    (skills_root / "restricted-skill").mkdir(parents=True, exist_ok=True)
    (skills_root / "restricted-skill" / "SKILL.md").write_text(
        "# Restricted", encoding="utf-8"
    )
    agent_template = tmp_path / "AGENTS.template.md"
    agent_template.write_text("# Template", encoding="utf-8")

    manager = DirectoryManager(
        base_path=tmp_path / "sandboxes",
        outputs_template_path=outputs_template,
        venv_template_path=venv_template,
        skills_path=skills_root,
        agent_instructions_template_path=agent_template,
    )

    sandbox_path = tmp_path / "sandboxes" / "sandbox-1"
    sandbox_path.mkdir(parents=True, exist_ok=True)

    manager.setup_skills(
        sandbox_path=sandbox_path,
        allowed_skill_names={"safe-skill"},
    )

    skills_dest = sandbox_path / ".opencode" / "skills"
    assert (skills_dest / "safe-skill" / "SKILL.md").exists()
    assert not (skills_dest / "restricted-skill").exists()
