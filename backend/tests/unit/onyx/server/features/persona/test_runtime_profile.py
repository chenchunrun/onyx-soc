from unittest.mock import MagicMock
from unittest.mock import patch

from onyx.auth.schemas import UserRole
from onyx.server.features.persona.runtime_profile import (
    build_persona_runtime_profile,
)


def _make_skill(
    *,
    key: str,
    enabled: bool = True,
    access_scope: str = "all_users",
    execution_scope: str = "standard",
    requires_approval: bool = False,
    requires_network_gateway: bool = False,
    allowed_target_types: list[str] | None = None,
    notes: str | None = None,
) -> MagicMock:
    skill = MagicMock()
    skill.key = key
    skill.name = key
    skill.description = f"description for {key}"
    skill.risk_level = MagicMock(value="medium")
    skill.access_scope = MagicMock(value=access_scope)
    skill.execution_scope = MagicMock(value=execution_scope)
    skill.requires_approval = requires_approval
    skill.requires_network_gateway = requires_network_gateway
    skill.allowed_target_types = [
        MagicMock(value=value) for value in (allowed_target_types or [])
    ]
    skill.notes = notes
    skill.enabled = enabled
    return skill


@patch("onyx.server.features.persona.runtime_profile.build_skill_runtime_profile")
@patch("onyx.server.features.persona.runtime_profile.resolve_bound_skill_runtime_state")
@patch("onyx.server.features.persona.runtime_profile.user_can_access_skill")
@patch("onyx.server.features.persona.runtime_profile.list_authorized_scan_targets")
@patch("onyx.server.features.persona.runtime_profile.list_managed_skills")
@patch("onyx.server.features.persona.runtime_profile.scan_prompt_presets")
def test_build_persona_runtime_profile_filters_accessible_and_inaccessible_skills(
    mock_scan_prompt_presets: MagicMock,
    mock_list_managed_skills: MagicMock,
    mock_list_authorized_scan_targets: MagicMock,
    mock_user_can_access_skill: MagicMock,
    mock_resolve_bound_skill_runtime_state: MagicMock,
    mock_build_skill_runtime_profile: MagicMock,
) -> None:
    prompt_preset = MagicMock()
    prompt_preset.id = "domain_dga_detect"
    prompt_preset.name = "DGA 域名检测"
    prompt_preset.description = "检测域名"
    prompt_preset.content = "Preset content"
    prompt_preset.category = "detection"
    prompt_preset.agent_type = "domainAnalysis"
    prompt_preset.source_file = "prompts/domain_analysis_presets.json"
    mock_scan_prompt_presets.return_value = [prompt_preset]

    code_audit = _make_skill(
        key="code-audit",
        access_scope="all_users",
        execution_scope="standard",
    )
    redteam = _make_skill(
        key="redteam",
        access_scope="security_team",
        execution_scope="authorized_scan",
        requires_approval=True,
        requires_network_gateway=True,
        allowed_target_types=["domain", "url"],
        notes="Requires explicit approval.",
    )
    mock_list_managed_skills.return_value = [code_audit, redteam]
    authorized_target = MagicMock()
    authorized_target.target = "example.com"
    authorized_target.target_type = MagicMock(value="domain")
    authorized_target.owner = "security-team"
    authorized_target.approval_reference = "CHG-1001"
    authorized_target.enabled = True
    authorized_target.expires_at = None
    authorized_target.notes = "Approved corp scope"
    mock_list_authorized_scan_targets.return_value = [authorized_target]
    mock_user_can_access_skill.side_effect = lambda skill, user, db: skill.key == "code-audit"

    runtime_profile = MagicMock()
    runtime_profile.policy_entries = [
        MagicMock(
            key="code-audit",
            execution_scope=MagicMock(value="standard"),
            requires_approval=False,
            gateway_required=False,
            allowed_target_types=[],
            notes=None,
        )
    ]
    mock_build_skill_runtime_profile.return_value = runtime_profile
    mock_resolve_bound_skill_runtime_state.return_value = MagicMock(
        active_skill_keys=["code-audit"],
        inactive_skill_keys=["redteam"],
        activation_required_skill_keys=["redteam"],
        blocked_skill_reasons={"redteam": ["Explicit runtime activation is required"]},
    )

    persona = MagicMock()
    persona.id = 12
    persona.name = "Security Agent"
    persona.system_prompt = "Base prompt"
    persona.prompt_preset_id = "domain_dga_detect"
    persona.skill_keys = ["code-audit", "redteam"]

    user = MagicMock()
    user.role = UserRole.BASIC

    db_session = MagicMock()

    with patch(
        "onyx.chat.chat_utils.get_persona_runtime_instruction_block",
        return_value="runtime block",
    ):
        profile = build_persona_runtime_profile(
            persona=persona,
            user=user,
            db_session=db_session,
        )

    assert profile.persona_id == 12
    assert profile.prompt_preset is not None
    assert profile.prompt_preset.id == "domain_dga_detect"
    assert profile.accessible_skill_keys == ["code-audit"]
    assert profile.inaccessible_skill_keys == ["redteam"]
    assert profile.active_skill_keys == ["code-audit"]
    assert profile.inactive_skill_keys == ["redteam"]
    assert profile.activation_required_skill_keys == ["redteam"]
    assert profile.blocked_skill_reasons == {
        "redteam": ["Explicit runtime activation is required"]
    }
    assert profile.authorized_target_suggestions == []
    assert profile.approval_reference_suggestions == []
    assert profile.runtime_instruction_block == "runtime block"
    assert [skill.key for skill in profile.bound_skills] == ["code-audit", "redteam"]
    assert any(skill.accessible for skill in profile.bound_skills if skill.key == "code-audit")
    assert any((not skill.accessible) for skill in profile.bound_skills if skill.key == "redteam")


@patch("onyx.server.features.persona.runtime_profile.build_skill_runtime_profile")
@patch("onyx.server.features.persona.runtime_profile.resolve_bound_skill_runtime_state")
@patch("onyx.server.features.persona.runtime_profile.user_can_access_skill")
@patch("onyx.server.features.persona.runtime_profile.list_authorized_scan_targets")
@patch("onyx.server.features.persona.runtime_profile.list_managed_skills")
@patch("onyx.server.features.persona.runtime_profile.scan_prompt_presets")
def test_build_persona_runtime_profile_handles_no_accessible_bound_skills(
    mock_scan_prompt_presets: MagicMock,
    mock_list_managed_skills: MagicMock,
    mock_list_authorized_scan_targets: MagicMock,
    mock_user_can_access_skill: MagicMock,
    mock_resolve_bound_skill_runtime_state: MagicMock,
    mock_build_skill_runtime_profile: MagicMock,
) -> None:
    mock_scan_prompt_presets.return_value = []
    mock_list_authorized_scan_targets.return_value = []
    quarantined = _make_skill(key="redteam", access_scope="security_team")
    mock_list_managed_skills.return_value = [quarantined]
    mock_user_can_access_skill.return_value = False

    runtime_profile = MagicMock()
    runtime_profile.policy_entries = []
    mock_build_skill_runtime_profile.return_value = runtime_profile
    mock_resolve_bound_skill_runtime_state.return_value = MagicMock(
        active_skill_keys=[],
        inactive_skill_keys=["redteam"],
        activation_required_skill_keys=[],
        blocked_skill_reasons={"redteam": ["Skill is not accessible to the current user"]},
    )

    persona = MagicMock()
    persona.id = 7
    persona.name = "Restricted Agent"
    persona.system_prompt = None
    persona.prompt_preset_id = None
    persona.skill_keys = ["redteam"]

    user = MagicMock()
    user.role = UserRole.BASIC

    with patch(
        "onyx.chat.chat_utils.get_persona_runtime_instruction_block",
        return_value="runtime block",
    ):
        profile = build_persona_runtime_profile(
            persona=persona,
            user=user,
            db_session=MagicMock(),
        )

    assert profile.prompt_preset is None
    assert profile.accessible_skill_keys == []
    assert profile.inaccessible_skill_keys == ["redteam"]
    assert profile.active_skill_keys == []
    assert profile.inactive_skill_keys == ["redteam"]
    assert profile.blocked_skill_reasons == {
        "redteam": ["Skill is not accessible to the current user"]
    }
    assert profile.authorized_target_suggestions == []
    assert profile.approval_reference_suggestions == []
    assert profile.policy_markdown == "No bound skills are currently accessible to the current user."


@patch("onyx.server.features.persona.runtime_profile.build_skill_runtime_profile")
@patch("onyx.server.features.persona.runtime_profile.resolve_bound_skill_runtime_state")
@patch("onyx.server.features.persona.runtime_profile.user_can_access_skill")
@patch("onyx.server.features.persona.runtime_profile.list_authorized_scan_targets")
@patch("onyx.server.features.persona.runtime_profile.list_managed_skills")
@patch("onyx.server.features.persona.runtime_profile.scan_prompt_presets")
def test_build_persona_runtime_profile_includes_authorized_target_suggestions(
    mock_scan_prompt_presets: MagicMock,
    mock_list_managed_skills: MagicMock,
    mock_list_authorized_scan_targets: MagicMock,
    mock_user_can_access_skill: MagicMock,
    mock_resolve_bound_skill_runtime_state: MagicMock,
    mock_build_skill_runtime_profile: MagicMock,
) -> None:
    mock_scan_prompt_presets.return_value = []
    asset_discovery = _make_skill(
        key="asset-discovery",
        access_scope="admin_only",
        execution_scope="authorized_scan",
        requires_approval=True,
        requires_network_gateway=True,
        allowed_target_types=["domain"],
        notes="Approved corp-only scans.",
    )
    mock_list_managed_skills.return_value = [asset_discovery]
    mock_user_can_access_skill.return_value = True

    authorized_target = MagicMock()
    authorized_target.target = "example.com"
    authorized_target.target_type = MagicMock(value="domain")
    authorized_target.owner = "security-team"
    authorized_target.approval_reference = "CHG-1001"
    authorized_target.enabled = True
    authorized_target.expires_at = None
    authorized_target.notes = "Primary corp domain"
    mock_list_authorized_scan_targets.return_value = [authorized_target]

    runtime_profile = MagicMock()
    runtime_profile.policy_entries = []
    mock_build_skill_runtime_profile.return_value = runtime_profile
    mock_resolve_bound_skill_runtime_state.return_value = MagicMock(
        active_skill_keys=[],
        inactive_skill_keys=["asset-discovery"],
        activation_required_skill_keys=["asset-discovery"],
        blocked_skill_reasons={"asset-discovery": ["Explicit runtime activation is required"]},
    )

    persona = MagicMock()
    persona.id = 8
    persona.name = "Admin Scan Agent"
    persona.system_prompt = None
    persona.prompt_preset_id = None
    persona.skill_keys = ["asset-discovery"]

    user = MagicMock()
    user.role = UserRole.ADMIN

    with patch(
        "onyx.chat.chat_utils.get_persona_runtime_instruction_block",
        return_value=None,
    ):
        profile = build_persona_runtime_profile(
            persona=persona,
            user=user,
            db_session=MagicMock(),
        )

    assert profile.authorized_target_suggestions[0].target == "example.com"
    assert profile.authorized_target_suggestions[0].approval_reference == "CHG-1001"
    assert profile.approval_reference_suggestions == ["CHG-1001"]
