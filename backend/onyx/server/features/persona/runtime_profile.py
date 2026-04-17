from __future__ import annotations

from datetime import datetime
from datetime import timezone

from pydantic import BaseModel
from sqlalchemy.orm import Session

from onyx.db.models import Persona
from onyx.db.models import User
from onyx.server.manage.prompt_presets.registry import scan_prompt_presets
from onyx.server.manage.skills.registry import BoundSkillRuntimeResolution
from onyx.server.manage.skills.registry import ManagedSkill
from onyx.server.manage.skills.registry import build_skill_runtime_profile
from onyx.server.manage.skills.registry import list_authorized_scan_targets
from onyx.server.manage.skills.registry import list_managed_skills
from onyx.server.manage.skills.registry import resolve_bound_skill_runtime_state
from onyx.server.manage.skills.registry import user_can_access_skill


class PromptPresetRuntimeBinding(BaseModel):
    id: str
    name: str
    description: str
    content: str
    category: str
    agent_type: str
    source_file: str


class AgentSkillRuntimeBinding(BaseModel):
    key: str
    name: str
    description: str
    risk_level: str
    access_scope: str
    execution_scope: str
    requires_approval: bool
    gateway_required: bool
    allowed_target_types: list[str]
    notes: str | None = None
    enabled: bool
    accessible: bool


class AuthorizedTargetSuggestion(BaseModel):
    target: str
    target_type: str
    owner: str
    approval_reference: str
    notes: str | None = None


class AgentRuntimeProfile(BaseModel):
    persona_id: int
    persona_name: str
    prompt_preset: PromptPresetRuntimeBinding | None
    bound_skills: list[AgentSkillRuntimeBinding]
    accessible_skill_keys: list[str]
    inaccessible_skill_keys: list[str]
    active_skill_keys: list[str]
    inactive_skill_keys: list[str]
    activation_required_skill_keys: list[str]
    blocked_skill_reasons: dict[str, list[str]]
    authorized_target_suggestions: list[AuthorizedTargetSuggestion]
    approval_reference_suggestions: list[str]
    runtime_instruction_block: str | None
    policy_markdown: str


def _build_prompt_preset_binding(persona: Persona) -> PromptPresetRuntimeBinding | None:
    if not persona.prompt_preset_id:
        return None

    preset = next(
        (
            candidate
            for candidate in scan_prompt_presets()
            if candidate.id == persona.prompt_preset_id
        ),
        None,
    )
    if not preset:
        return None

    return PromptPresetRuntimeBinding(
        id=preset.id,
        name=preset.name,
        description=preset.description,
        content=preset.content,
        category=preset.category,
        agent_type=preset.agent_type,
        source_file=preset.source_file,
    )


def _build_skill_binding(
    skill: ManagedSkill,
    user: User,
    db_session: Session,
) -> AgentSkillRuntimeBinding:
    return AgentSkillRuntimeBinding(
        key=skill.key,
        name=skill.name,
        description=skill.description,
        risk_level=skill.risk_level.value,
        access_scope=skill.access_scope.value,
        execution_scope=skill.execution_scope.value,
        requires_approval=skill.requires_approval,
        gateway_required=skill.requires_network_gateway,
        allowed_target_types=[
            target_type.value for target_type in skill.allowed_target_types
        ],
        notes=skill.notes,
        enabled=skill.enabled,
        accessible=user_can_access_skill(skill, user, db_session),
    )


def _is_authorized_target_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return False
    try:
        return (
            datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            < datetime.now(timezone.utc)
        )
    except Exception:
        return False


def _build_authorized_target_suggestions(
    bound_skills: list[AgentSkillRuntimeBinding],
) -> list[AuthorizedTargetSuggestion]:
    allowed_target_types = {
        target_type
        for skill in bound_skills
        if skill.execution_scope == "authorized_scan" and skill.accessible and skill.enabled
        for target_type in skill.allowed_target_types
    }
    if not allowed_target_types:
        return []

    suggestions: list[AuthorizedTargetSuggestion] = []
    seen_targets: set[tuple[str, str, str]] = set()
    for target in list_authorized_scan_targets():
        if (
            not target.enabled
            or _is_authorized_target_expired(target.expires_at)
            or target.target_type.value not in allowed_target_types
        ):
            continue

        dedupe_key = (
            target.target,
            target.target_type.value,
            target.approval_reference,
        )
        if dedupe_key in seen_targets:
            continue
        seen_targets.add(dedupe_key)
        suggestions.append(
            AuthorizedTargetSuggestion(
                target=target.target,
                target_type=target.target_type.value,
                owner=target.owner,
                approval_reference=target.approval_reference,
                notes=target.notes,
            )
        )

    suggestions.sort(key=lambda item: (item.target_type, item.target))
    return suggestions


def build_persona_runtime_profile(
    persona: Persona,
    user: User,
    db_session: Session,
) -> AgentRuntimeProfile:
    runtime_skill_resolution: BoundSkillRuntimeResolution = (
        resolve_bound_skill_runtime_state(
            bound_skill_keys=persona.skill_keys,
            user=user,
            db_session=db_session,
        )
    )
    runtime_instruction_block: str | None = None
    if persona.system_prompt or persona.prompt_preset_id or persona.skill_keys:
        from onyx.chat.chat_utils import get_persona_runtime_instruction_block

        runtime_instruction_block = get_persona_runtime_instruction_block(
            persona, active_skill_keys=runtime_skill_resolution.active_skill_keys
        )

    all_skills = {skill.key: skill for skill in list_managed_skills()}
    bound_skills = [
        _build_skill_binding(skill, user, db_session)
        for skill_key in persona.skill_keys
        if (skill := all_skills.get(skill_key)) is not None
    ]
    accessible_skill_keys = sorted(
        skill.key for skill in bound_skills if skill.accessible and skill.enabled
    )
    inaccessible_skill_keys = sorted(
        skill.key for skill in bound_skills if not skill.accessible or not skill.enabled
    )
    authorized_target_suggestions = _build_authorized_target_suggestions(bound_skills)
    approval_reference_suggestions = sorted(
        {
            suggestion.approval_reference
            for suggestion in authorized_target_suggestions
            if suggestion.approval_reference
        }
    )

    user_runtime_profile = build_skill_runtime_profile(user, db_session)
    bound_policy_entries = [
        entry
        for entry in user_runtime_profile.policy_entries
        if entry.key in accessible_skill_keys
    ]
    if bound_policy_entries:
        policy_lines = [
            "Runtime restrictions apply to the bound skills below. Do not use them outside the stated policy:",
        ]
        for entry in bound_policy_entries:
            parts = [
                f"scope={entry.execution_scope.value}",
                f"approval={'required' if entry.requires_approval else 'not-required'}",
                f"gateway={'required' if entry.gateway_required else 'not-required'}",
            ]
            if entry.allowed_target_types:
                parts.append(
                    "targets="
                    + ",".join(
                        target_type.value for target_type in entry.allowed_target_types
                    )
                )
            policy_lines.append(f"- `{entry.key}`: " + "; ".join(parts))
            if entry.notes:
                policy_lines.append(f"  Notes: {entry.notes}")
        policy_markdown = "\n".join(policy_lines)
    elif accessible_skill_keys:
        policy_markdown = (
            "Bound skills are accessible to the current user and have no additional runtime policy restrictions."
        )
    else:
        policy_markdown = "No bound skills are currently accessible to the current user."

    return AgentRuntimeProfile(
        persona_id=persona.id,
        persona_name=persona.name,
        prompt_preset=_build_prompt_preset_binding(persona),
        bound_skills=bound_skills,
        accessible_skill_keys=accessible_skill_keys,
        inaccessible_skill_keys=inaccessible_skill_keys,
        active_skill_keys=runtime_skill_resolution.active_skill_keys,
        inactive_skill_keys=runtime_skill_resolution.inactive_skill_keys,
        activation_required_skill_keys=runtime_skill_resolution.activation_required_skill_keys,
        blocked_skill_reasons=runtime_skill_resolution.blocked_skill_reasons,
        authorized_target_suggestions=authorized_target_suggestions,
        approval_reference_suggestions=approval_reference_suggestions,
        runtime_instruction_block=runtime_instruction_block,
        policy_markdown=policy_markdown,
    )
