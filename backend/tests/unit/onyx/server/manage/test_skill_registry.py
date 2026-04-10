from pathlib import Path
from types import SimpleNamespace

from onyx.auth.schemas import UserRole
from onyx.server.manage.skills import registry
from onyx.server.manage.skills.registry import ManagedSkill
from onyx.server.manage.skills.registry import SkillAccessScope
from onyx.server.manage.skills.registry import SkillRiskLevel
from onyx.server.manage.skills.registry import build_skill_registry_summary
from onyx.server.manage.skills.registry import SkillRegistryImportRequest


def _write_skill(skill_dir: Path, description: str) -> None:
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\ndescription: {description}\nbuiltin: false\n---\n\n# Skill\n",
        encoding="utf-8",
    )


def test_sync_skill_registry_discovers_new_skills(tmp_path: Path, monkeypatch) -> None:
    skills_root = tmp_path / "skills"
    _write_skill(skills_root / "safe-skill", "Safe skill")
    registry_path = tmp_path / "registry.yaml"

    monkeypatch.setattr(registry, "SKILLS_ROOT", skills_root)
    monkeypatch.setattr(registry, "REGISTRY_PATH", registry_path)

    summary = registry.sync_skill_registry()
    managed = registry.list_managed_skills()

    assert summary.discovered_count == 1
    assert summary.added_count == 1
    assert summary.managed_count == 1
    assert managed[0].key == "safe-skill"
    assert managed[0].enabled is False
    assert managed[0].access_scope == SkillAccessScope.QUARANTINED


def test_get_allowed_skill_names_for_user_respects_scope_and_enabled(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        registry,
        "list_managed_skills",
        lambda: [
            ManagedSkill(
                key="all-users-skill",
                name="all-users-skill",
                description="",
                path="skills/all-users-skill",
                risk_level=SkillRiskLevel.LOW,
                access_scope=SkillAccessScope.ALL_USERS,
                enabled=True,
                builtin=False,
                has_scripts=False,
                has_references=False,
                has_tools=False,
                has_requirements=False,
                notes=None,
            ),
            ManagedSkill(
                key="security-only-skill",
                name="security-only-skill",
                description="",
                path="skills/security-only-skill",
                risk_level=SkillRiskLevel.MEDIUM,
                access_scope=SkillAccessScope.SECURITY_TEAM,
                enabled=True,
                builtin=False,
                has_scripts=False,
                has_references=False,
                has_tools=False,
                has_requirements=False,
                notes=None,
            ),
            ManagedSkill(
                key="disabled-skill",
                name="disabled-skill",
                description="",
                path="skills/disabled-skill",
                risk_level=SkillRiskLevel.HIGH,
                access_scope=SkillAccessScope.ALL_USERS,
                enabled=False,
                builtin=False,
                has_scripts=False,
                has_references=False,
                has_tools=False,
                has_requirements=False,
                notes=None,
            ),
            ManagedSkill(
                key="quarantined-skill",
                name="quarantined-skill",
                description="",
                path="skills/quarantined-skill",
                risk_level=SkillRiskLevel.CRITICAL,
                access_scope=SkillAccessScope.QUARANTINED,
                enabled=True,
                builtin=False,
                has_scripts=False,
                has_references=False,
                has_tools=False,
                has_requirements=False,
                notes=None,
            ),
        ],
    )

    basic_user = SimpleNamespace(role=UserRole.BASIC, email="user@example.com")
    security_user = SimpleNamespace(
        role=UserRole.BASIC, email="hunter@security.local"
    )

    assert registry.get_allowed_skill_names_for_user(basic_user) == {"all-users-skill"}
    assert registry.get_allowed_skill_names_for_user(security_user) == {
        "all-users-skill",
        "security-only-skill",
    }


def test_build_skill_registry_summary_exposes_role_previews(monkeypatch) -> None:
    monkeypatch.setattr(
        registry,
        "scan_skill_directories",
        lambda skills_root=None: {
            "all-users-skill": ManagedSkill(
                key="all-users-skill",
                name="all-users-skill",
                description="",
                path="skills/all-users-skill",
                risk_level=SkillRiskLevel.LOW,
                access_scope=SkillAccessScope.ALL_USERS,
                enabled=True,
                builtin=False,
                has_scripts=False,
                has_references=False,
                has_tools=False,
                has_requirements=False,
                notes=None,
            ),
            "security-only-skill": ManagedSkill(
                key="security-only-skill",
                name="security-only-skill",
                description="",
                path="skills/security-only-skill",
                risk_level=SkillRiskLevel.MEDIUM,
                access_scope=SkillAccessScope.SECURITY_TEAM,
                enabled=True,
                builtin=False,
                has_scripts=False,
                has_references=False,
                has_tools=False,
                has_requirements=False,
                notes=None,
            ),
            "quarantined-skill": ManagedSkill(
                key="quarantined-skill",
                name="quarantined-skill",
                description="",
                path="skills/quarantined-skill",
                risk_level=SkillRiskLevel.CRITICAL,
                access_scope=SkillAccessScope.QUARANTINED,
                enabled=False,
                builtin=False,
                has_scripts=False,
                has_references=False,
                has_tools=False,
                has_requirements=False,
                notes=None,
            ),
        },
    )
    monkeypatch.setattr(
        registry,
        "list_managed_skills",
        lambda: list(registry.scan_skill_directories().values()),
    )

    summary = build_skill_registry_summary()

    assert summary.discovered_count == 3
    assert summary.managed_count == 3
    assert summary.enabled_count == 2
    assert summary.quarantined_count == 1
    assert summary.critical_count == 1
    preview_map = {preview.role: preview for preview in summary.role_previews}
    assert preview_map["basic_user"].allowed_skill_keys == ["all-users-skill"]
    assert preview_map["security_team"].allowed_skill_keys == [
        "all-users-skill",
        "security-only-skill",
    ]
    assert preview_map["admin"].allowed_skill_keys == [
        "all-users-skill",
        "security-only-skill",
    ]


def test_import_and_export_skill_registry_round_trip(
    tmp_path: Path, monkeypatch
) -> None:
    registry_path = tmp_path / "registry.yaml"
    monkeypatch.setattr(registry, "REGISTRY_PATH", registry_path)

    summary = registry.import_skill_registry(
        SkillRegistryImportRequest(
            yaml_content="""
skills:
  custom-skill:
    enabled: true
    risk_level: high
    access_scope: security_team
    notes: Imported for testing
""".strip()
        )
    )

    assert summary.imported_count == 1
    assert summary.managed_count == 1

    exported = registry.export_skill_registry_yaml()
    assert "custom-skill" in exported
    assert "security_team" in exported


def test_list_managed_skills_supports_query_filters(monkeypatch) -> None:
    skills = [
        ManagedSkill(
            key="code-audit",
            name="code-audit",
            description="Audit application code",
            path="skills/code-audit",
            risk_level=SkillRiskLevel.LOW,
            access_scope=SkillAccessScope.ALL_USERS,
            enabled=True,
            builtin=False,
            has_scripts=False,
            has_references=False,
            has_tools=False,
            has_requirements=False,
            notes="safe",
        ),
        ManagedSkill(
            key="redteam-recon-enterprise",
            name="redteam-recon-enterprise",
            description="External reconnaissance",
            path="skills/redteam-recon-enterprise",
            risk_level=SkillRiskLevel.CRITICAL,
            access_scope=SkillAccessScope.QUARANTINED,
            enabled=False,
            builtin=False,
            has_scripts=True,
            has_references=False,
            has_tools=False,
            has_requirements=False,
            notes="blocked",
        ),
    ]
    monkeypatch.setattr(
        registry,
        "scan_skill_directories",
        lambda skills_root=None: {skill.key: skill for skill in skills},
    )
    monkeypatch.setattr(
        registry,
        "_load_registry_payload",
        lambda: {
            "skills": {
                skill.key: {
                    "enabled": skill.enabled,
                    "risk_level": skill.risk_level.value,
                    "access_scope": skill.access_scope.value,
                    "notes": skill.notes,
                }
                for skill in skills
            }
        },
    )

    queried = registry.list_managed_skills(query="audit")
    assert [skill.key for skill in queried] == ["code-audit"]

    filtered = registry.list_managed_skills(
        risk_level=SkillRiskLevel.CRITICAL,
        access_scope=SkillAccessScope.QUARANTINED,
        enabled=False,
    )
    assert [skill.key for skill in filtered] == ["redteam-recon-enterprise"]
