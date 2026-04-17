from __future__ import annotations

from enum import Enum
import ipaddress
import json
import os
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Any
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
import yaml

from onyx.auth.users import is_user_admin
from onyx.auth.schemas import UserRole
from onyx.db.models import User
from onyx.db.models import User__UserGroup
from onyx.db.models import UserGroup
from onyx.server.features.build.sandbox.util.agent_instructions import (
    extract_skill_description,
)

_FILE_PATH = Path(__file__).resolve()
_ROOT_CANDIDATES = (
    _FILE_PATH.parents[5],
    _FILE_PATH.parents[4],
    Path("/app"),
)


def _detect_root_path() -> Path:
    for candidate in _ROOT_CANDIDATES:
        if (candidate / "skills").exists():
            return candidate
    return _ROOT_CANDIDATES[0]


ROOT_PATH = _detect_root_path()
SKILLS_ROOT = ROOT_PATH / "skills"
REGISTRY_PATH = Path(__file__).resolve().parent / "registry.yaml"
AUTHORIZED_SCAN_TARGETS_PATH = (
    Path(__file__).resolve().parent / "authorized_scan_targets.yaml"
)
AUTHORIZED_SCAN_AUDIT_PATH = Path(__file__).resolve().parent / "authorized_scan_audit.jsonl"

SECURITY_TEAM_EMAILS = {
    "commander@security.local",
    "analyst@security.local",
    "vuln_expert@security.local",
    "auditor@security.local",
    "hunter@security.local",
    "malware@security.local",
    "detection@security.local",
}
SECURITY_TEAM_GROUP_NAMES = {
    "security team",
    "security operations",
    "security engineering",
    "secops",
    "soc",
}


class SkillRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SkillAccessScope(str, Enum):
    ALL_USERS = "all_users"
    SECURITY_TEAM = "security_team"
    ADMIN_ONLY = "admin_only"
    QUARANTINED = "quarantined"


class SkillExecutionScope(str, Enum):
    STANDARD = "standard"
    AUTHORIZED_SCAN = "authorized_scan"


class AuthorizedTargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"


class ManagedSkill(BaseModel):
    key: str
    name: str
    description: str
    path: str
    risk_level: SkillRiskLevel
    access_scope: SkillAccessScope
    enabled: bool
    builtin: bool
    has_scripts: bool
    has_references: bool
    has_tools: bool
    has_requirements: bool
    execution_scope: SkillExecutionScope = SkillExecutionScope.STANDARD
    requires_approval: bool = False
    requires_network_gateway: bool = False
    allowed_target_types: list[AuthorizedTargetType] = []
    notes: str | None = None


class SkillRegistryUpdateRequest(BaseModel):
    enabled: bool | None = None
    risk_level: SkillRiskLevel | None = None
    access_scope: SkillAccessScope | None = None
    execution_scope: SkillExecutionScope | None = None
    requires_approval: bool | None = None
    requires_network_gateway: bool | None = None
    allowed_target_types: list[AuthorizedTargetType] | None = None
    notes: str | None = None


class SkillRegistrySyncSummary(BaseModel):
    discovered_count: int
    added_count: int
    managed_count: int


class SkillRegistryImportRequest(BaseModel):
    yaml_content: str
    mode: Literal["merge", "replace"] = "merge"


class SkillRegistryImportSummary(BaseModel):
    imported_count: int
    managed_count: int
    mode: Literal["merge", "replace"]


class AuthorizedScanTarget(BaseModel):
    target: str
    target_type: AuthorizedTargetType
    owner: str
    approval_reference: str
    enabled: bool = True
    expires_at: str | None = None
    notes: str | None = None


class AuthorizedScanTargetsImportRequest(BaseModel):
    yaml_content: str
    mode: Literal["merge", "replace"] = "merge"


class AuthorizedScanTargetsImportSummary(BaseModel):
    imported_count: int
    managed_count: int
    mode: Literal["merge", "replace"]


class SkillRolePreview(BaseModel):
    role: str
    allowed_count: int
    allowed_skill_keys: list[str]


class SkillRegistrySummary(BaseModel):
    discovered_count: int
    managed_count: int
    enabled_count: int
    quarantined_count: int
    all_users_count: int
    security_team_count: int
    admin_only_count: int
    critical_count: int
    authorized_scan_count: int
    approval_required_count: int
    gateway_enforced_count: int
    role_previews: list[SkillRolePreview]


class AuthorizedScanPolicySummary(BaseModel):
    managed_target_count: int
    enabled_target_count: int
    expired_target_count: int
    authorized_scan_skill_count: int
    approval_required_skill_count: int
    gateway_enforced_skill_count: int


class AuthorizedScanAuthorizationRequest(BaseModel):
    skill_key: str
    targets: list[str]
    approval_reference: str | None = None


class AuthorizedScanAuthorizationResult(BaseModel):
    allowed: bool
    skill_key: str
    execution_scope: SkillExecutionScope
    gateway_required: bool
    allowed_targets: list[str]
    denied_targets: list[str]
    reasons: list[str]


class SkillRuntimePolicyEntry(BaseModel):
    key: str
    execution_scope: SkillExecutionScope
    requires_approval: bool
    gateway_required: bool
    allowed_target_types: list[AuthorizedTargetType]
    notes: str | None = None


class SkillRuntimeProfile(BaseModel):
    allowed_skill_names: list[str]
    policy_markdown: str
    policy_entries: list[SkillRuntimePolicyEntry]


class BoundSkillRuntimeResolution(BaseModel):
    active_skill_keys: list[str]
    inactive_skill_keys: list[str]
    activation_required_skill_keys: list[str]
    blocked_skill_reasons: dict[str, list[str]]


def _load_registry_payload() -> dict[str, Any]:
    if not REGISTRY_PATH.exists():
        return {"skills": {}}

    with open(REGISTRY_PATH, "r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}

    skills_payload = payload.get("skills", {})
    if not isinstance(skills_payload, dict):
        raise ValueError(f"Invalid skill registry at {REGISTRY_PATH}")

    return {"skills": skills_payload}


def _write_registry_payload(payload: dict[str, Any]) -> None:
    with open(REGISTRY_PATH, "w", encoding="utf-8") as handle:
        yaml.safe_dump(
            payload,
            handle,
            allow_unicode=True,
            sort_keys=True,
            default_flow_style=False,
        )


def _load_authorized_targets_payload() -> dict[str, Any]:
    if not AUTHORIZED_SCAN_TARGETS_PATH.exists():
        return {"targets": []}

    with open(AUTHORIZED_SCAN_TARGETS_PATH, "r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}

    targets_payload = payload.get("targets", [])
    if not isinstance(targets_payload, list):
        raise ValueError(f"Invalid authorized scan target registry at {AUTHORIZED_SCAN_TARGETS_PATH}")

    return {"targets": targets_payload}


def _write_authorized_targets_payload(payload: dict[str, Any]) -> None:
    with open(AUTHORIZED_SCAN_TARGETS_PATH, "w", encoding="utf-8") as handle:
        yaml.safe_dump(
            payload,
            handle,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def _read_frontmatter_fields(skill_md_path: Path) -> tuple[str | None, bool]:
    try:
        content = skill_md_path.read_text(encoding="utf-8")
    except Exception:
        return None, False

    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, False

    description: str | None = None
    builtin = False
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if line.startswith("description:"):
            description = line.split(":", 1)[1].strip().strip('"').strip("'")
        elif line.startswith("builtin:"):
            builtin = line.split(":", 1)[1].strip().lower() == "true"
    return description, builtin


def scan_skill_directories(
    skills_root: Path | None = None,
) -> dict[str, ManagedSkill]:
    skills_root = skills_root or SKILLS_ROOT
    scanned: dict[str, ManagedSkill] = {}
    if not skills_root.exists():
        return scanned

    for skill_dir in sorted(skills_root.iterdir()):
        if not skill_dir.is_dir():
            continue

        skill_md_path = skill_dir / "SKILL.md"
        if not skill_md_path.exists():
            continue

        frontmatter_description, builtin = _read_frontmatter_fields(skill_md_path)
        description = frontmatter_description or extract_skill_description(skill_md_path)
        try:
            relative_path = str(skill_dir.relative_to(ROOT_PATH))
        except ValueError:
            relative_path = str(skill_dir)

        scanned[skill_dir.name] = ManagedSkill(
            key=skill_dir.name,
            name=skill_dir.name,
            description=description,
            path=relative_path,
            risk_level=SkillRiskLevel.MEDIUM,
            access_scope=SkillAccessScope.QUARANTINED,
            enabled=False,
            builtin=builtin,
            has_scripts=(skill_dir / "scripts").exists(),
            has_references=(skill_dir / "references").exists(),
            has_tools=(skill_dir / "tools").exists(),
            has_requirements=(skill_dir / "requirements.txt").exists(),
            execution_scope=SkillExecutionScope.STANDARD,
            requires_approval=False,
            requires_network_gateway=False,
            allowed_target_types=[],
            notes=None,
        )

    return scanned


def list_managed_skills(
    query: str | None = None,
    risk_level: SkillRiskLevel | None = None,
    access_scope: SkillAccessScope | None = None,
    enabled: bool | None = None,
) -> list[ManagedSkill]:
    payload = _load_registry_payload()
    scanned = scan_skill_directories()

    managed: list[ManagedSkill] = []
    for key, scanned_skill in scanned.items():
        registry_entry = payload["skills"].get(key, {})
        managed.append(
            scanned_skill.model_copy(
                update={
                    "risk_level": SkillRiskLevel(
                        registry_entry.get("risk_level", scanned_skill.risk_level)
                    ),
                    "access_scope": SkillAccessScope(
                        registry_entry.get(
                            "access_scope", scanned_skill.access_scope
                        )
                    ),
                    "enabled": bool(
                        registry_entry.get("enabled", scanned_skill.enabled)
                    ),
                    "execution_scope": SkillExecutionScope(
                        registry_entry.get(
                            "execution_scope", scanned_skill.execution_scope
                        )
                    ),
                    "requires_approval": bool(
                        registry_entry.get(
                            "requires_approval", scanned_skill.requires_approval
                        )
                    ),
                    "requires_network_gateway": bool(
                        registry_entry.get(
                            "requires_network_gateway",
                            scanned_skill.requires_network_gateway,
                        )
                    ),
                    "allowed_target_types": [
                        AuthorizedTargetType(target_type)
                        for target_type in registry_entry.get(
                            "allowed_target_types",
                            [target_type.value for target_type in scanned_skill.allowed_target_types],
                        )
                    ],
                    "notes": registry_entry.get("notes"),
                }
            )
        )

    if query:
        lowered_query = query.strip().lower()
        managed = [
            skill
            for skill in managed
            if lowered_query in skill.key.lower()
            or lowered_query in skill.name.lower()
            or lowered_query in skill.description.lower()
            or lowered_query in skill.path.lower()
            or lowered_query in (skill.notes or "").lower()
        ]

    if risk_level is not None:
        managed = [skill for skill in managed if skill.risk_level == risk_level]

    if access_scope is not None:
        managed = [skill for skill in managed if skill.access_scope == access_scope]

    if enabled is not None:
        managed = [skill for skill in managed if skill.enabled == enabled]

    return sorted(
        managed,
        key=lambda skill: (
            skill.access_scope.value,
            skill.risk_level.value,
            skill.key,
        ),
    )


def sync_skill_registry() -> SkillRegistrySyncSummary:
    payload = _load_registry_payload()
    scanned = scan_skill_directories()

    added_count = 0
    for key in scanned:
        if key not in payload["skills"]:
            payload["skills"][key] = {
                "enabled": False,
                "risk_level": SkillRiskLevel.MEDIUM.value,
                "access_scope": SkillAccessScope.QUARANTINED.value,
                "execution_scope": SkillExecutionScope.STANDARD.value,
                "requires_approval": False,
                "requires_network_gateway": False,
                "allowed_target_types": [],
                "notes": "Discovered automatically; review before enabling.",
            }
            added_count += 1

    _write_registry_payload(payload)
    return SkillRegistrySyncSummary(
        discovered_count=len(scanned),
        added_count=added_count,
        managed_count=len(payload["skills"]),
    )


def export_skill_registry_yaml() -> str:
    if not REGISTRY_PATH.exists():
        return yaml.safe_dump({"skills": {}}, allow_unicode=True, sort_keys=True)
    return REGISTRY_PATH.read_text(encoding="utf-8")


def import_skill_registry(
    request: SkillRegistryImportRequest,
) -> SkillRegistryImportSummary:
    loaded_payload = yaml.safe_load(request.yaml_content) or {}
    skills_payload = loaded_payload.get("skills", {})
    if not isinstance(skills_payload, dict):
        raise ValueError("Imported registry must contain a top-level 'skills' mapping")

    normalized_skills: dict[str, dict[str, Any]] = {}
    for key, entry in skills_payload.items():
        if not isinstance(key, str):
            raise ValueError("Skill keys must be strings")
        if not isinstance(entry, dict):
            raise ValueError(f"Skill entry for '{key}' must be an object")

        normalized_skills[key] = {
            "enabled": bool(entry.get("enabled", False)),
            "risk_level": SkillRiskLevel(
                entry.get("risk_level", SkillRiskLevel.MEDIUM.value)
            ).value,
            "access_scope": SkillAccessScope(
                entry.get("access_scope", SkillAccessScope.QUARANTINED.value)
            ).value,
            "execution_scope": SkillExecutionScope(
                entry.get("execution_scope", SkillExecutionScope.STANDARD.value)
            ).value,
            "requires_approval": bool(entry.get("requires_approval", False)),
            "requires_network_gateway": bool(
                entry.get("requires_network_gateway", False)
            ),
            "allowed_target_types": [
                AuthorizedTargetType(target_type).value
                for target_type in entry.get("allowed_target_types", [])
            ],
            "notes": entry.get("notes"),
        }

    if request.mode == "replace":
        next_payload = {"skills": normalized_skills}
    else:
        next_payload = _load_registry_payload()
        next_payload["skills"].update(normalized_skills)

    _write_registry_payload(next_payload)

    return SkillRegistryImportSummary(
        imported_count=len(normalized_skills),
        managed_count=len(next_payload["skills"]),
        mode=request.mode,
    )


def update_skill_registry_entry(
    skill_key: str, request: SkillRegistryUpdateRequest
) -> ManagedSkill | None:
    payload = _load_registry_payload()
    scanned = scan_skill_directories()
    if skill_key not in scanned:
        return None

    entry = payload["skills"].setdefault(
        skill_key,
        {
            "enabled": False,
            "risk_level": SkillRiskLevel.MEDIUM.value,
            "access_scope": SkillAccessScope.QUARANTINED.value,
            "execution_scope": SkillExecutionScope.STANDARD.value,
            "requires_approval": False,
            "requires_network_gateway": False,
            "allowed_target_types": [],
            "notes": "Created automatically.",
        },
    )

    if request.enabled is not None:
        entry["enabled"] = request.enabled
    if request.risk_level is not None:
        entry["risk_level"] = request.risk_level.value
    if request.access_scope is not None:
        entry["access_scope"] = request.access_scope.value
    if request.execution_scope is not None:
        entry["execution_scope"] = request.execution_scope.value
    if request.requires_approval is not None:
        entry["requires_approval"] = request.requires_approval
    if request.requires_network_gateway is not None:
        entry["requires_network_gateway"] = request.requires_network_gateway
    if request.allowed_target_types is not None:
        entry["allowed_target_types"] = [
            target_type.value for target_type in request.allowed_target_types
        ]
    if request.notes is not None:
        entry["notes"] = request.notes

    _write_registry_payload(payload)

    for skill in list_managed_skills():
        if skill.key == skill_key:
            return skill
    return None


def _normalize_group_name(name: str) -> str:
    return " ".join(name.strip().lower().replace("-", " ").replace("_", " ").split())


def _extract_user_group_names(user: User) -> set[str]:
    explicit_names = getattr(user, "skill_group_names", None)
    if explicit_names:
        return {_normalize_group_name(name) for name in explicit_names if name}

    groups = getattr(user, "groups", None)
    if groups:
        return {
            _normalize_group_name(group.name)
            for group in groups
            if getattr(group, "name", None)
        }

    return set()


def _load_user_group_names(user: User, db_session: Session | None = None) -> set[str]:
    group_names = _extract_user_group_names(user)
    if group_names or db_session is None or getattr(user, "id", None) is None:
        return group_names

    rows = db_session.execute(
        select(UserGroup.name)
        .select_from(UserGroup)
        .join(User__UserGroup, User__UserGroup.user_group_id == UserGroup.id)
        .where(User__UserGroup.user_id == user.id)
    ).all()
    return {_normalize_group_name(row[0]) for row in rows if row[0]}


def is_security_team_user(user: User, db_session: Session | None = None) -> bool:
    if user.role == UserRole.ADMIN:
        return True
    user_group_names = _load_user_group_names(user, db_session)
    if user_group_names & SECURITY_TEAM_GROUP_NAMES:
        return True
    return bool(user.email and user.email.lower() in SECURITY_TEAM_EMAILS)


def user_can_access_skill(
    skill: ManagedSkill, user: User, db_session: Session | None = None
) -> bool:
    if not skill.enabled:
        return False

    if skill.access_scope == SkillAccessScope.ALL_USERS:
        return True
    if skill.access_scope == SkillAccessScope.ADMIN_ONLY:
        return user.role == UserRole.ADMIN
    if skill.access_scope == SkillAccessScope.SECURITY_TEAM:
        return is_security_team_user(user, db_session)
    return False


def get_allowed_skill_names_for_user(
    user: User, db_session: Session | None = None
) -> set[str]:
    return {
        skill.key
        for skill in list_managed_skills()
        if user_can_access_skill(skill, user, db_session)
    }


def build_skill_runtime_profile(
    user: User, db_session: Session | None = None
) -> SkillRuntimeProfile:
    allowed_skills = [
        skill
        for skill in list_managed_skills()
        if user_can_access_skill(skill, user, db_session)
    ]
    policy_entries = [
        SkillRuntimePolicyEntry(
            key=skill.key,
            execution_scope=skill.execution_scope,
            requires_approval=skill.requires_approval,
            gateway_required=skill.requires_network_gateway,
            allowed_target_types=skill.allowed_target_types,
            notes=skill.notes,
        )
        for skill in allowed_skills
        if skill.execution_scope == SkillExecutionScope.AUTHORIZED_SCAN
        or skill.requires_approval
        or skill.requires_network_gateway
    ]

    if not policy_entries:
        policy_markdown = "No additional runtime skill restrictions are configured."
    else:
        lines = [
            "Runtime restrictions apply to the following skills. Do not use them outside the stated policy:",
        ]
        for entry in policy_entries:
            constraint_parts = [
                f"scope={entry.execution_scope.value}",
                f"approval={'required' if entry.requires_approval else 'not-required'}",
                f"gateway={'required' if entry.gateway_required else 'not-required'}",
            ]
            if entry.allowed_target_types:
                constraint_parts.append(
                    "targets="
                    + ",".join(target_type.value for target_type in entry.allowed_target_types)
                )
            lines.append(f"- `{entry.key}`: " + "; ".join(constraint_parts))
            if entry.notes:
                lines.append(f"  Notes: {entry.notes}")
        policy_markdown = "\n".join(lines)

    return SkillRuntimeProfile(
        allowed_skill_names=sorted(skill.key for skill in allowed_skills),
        policy_markdown=policy_markdown,
        policy_entries=policy_entries,
    )


def skill_requires_explicit_runtime_activation(skill: ManagedSkill) -> bool:
    return (
        skill.execution_scope == SkillExecutionScope.AUTHORIZED_SCAN
        or skill.requires_approval
        or skill.requires_network_gateway
    )


def is_skill_gateway_configured() -> bool:
    return bool(str(os.environ.get("SECURITY_TOOLS_GATEWAY_URL", "")).strip())


def resolve_bound_skill_runtime_state(
    *,
    bound_skill_keys: list[str],
    user: User,
    db_session: Session | None = None,
    requested_skill_keys: list[str] | None = None,
    targets: list[str] | None = None,
    approval_reference: str | None = None,
) -> BoundSkillRuntimeResolution:
    skills_by_key = {skill.key: skill for skill in list_managed_skills()}
    requested_key_set = set(requested_skill_keys or [])
    targets = targets or []

    active_skill_keys: list[str] = []
    activation_required_skill_keys: list[str] = []
    blocked_skill_reasons: dict[str, list[str]] = {}

    for skill_key in bound_skill_keys:
        skill = skills_by_key.get(skill_key)
        reasons: list[str] = []
        explicit_activation_required = False

        if skill is None:
            reasons.append("Skill is not registered")
        else:
            explicit_activation_required = skill_requires_explicit_runtime_activation(
                skill
            )
            if explicit_activation_required:
                activation_required_skill_keys.append(skill.key)

            if not skill.enabled:
                reasons.append("Skill is disabled")
            elif not user_can_access_skill(skill, user, db_session):
                reasons.append("Skill is not accessible to the current user")
            elif explicit_activation_required:
                if skill.key not in requested_key_set:
                    reasons.append("Explicit runtime activation is required")
                else:
                    if skill.requires_network_gateway and not is_skill_gateway_configured():
                        reasons.append("Security tools gateway is not configured")
                    if (
                        skill.requires_approval
                        and skill.execution_scope != SkillExecutionScope.AUTHORIZED_SCAN
                        and not approval_reference
                    ):
                        reasons.append("Approval reference is required")
                    if skill.execution_scope == SkillExecutionScope.AUTHORIZED_SCAN:
                        if not targets:
                            reasons.append("Authorized scan targets are required")
                        else:
                            authorization_result = authorize_skill_scan_execution(
                                AuthorizedScanAuthorizationRequest(
                                    skill_key=skill.key,
                                    targets=targets,
                                    approval_reference=approval_reference,
                                ),
                                user,
                            )
                            if not authorization_result.allowed:
                                reasons.extend(authorization_result.reasons)
            elif requested_skill_keys is None or skill.key in requested_key_set:
                active_skill_keys.append(skill.key)

        if reasons:
            blocked_skill_reasons[skill_key] = list(dict.fromkeys(reasons))
            continue

        if skill is not None and skill.key not in active_skill_keys:
            active_skill_keys.append(skill.key)

    active_key_set = set(active_skill_keys)
    inactive_skill_keys = [skill_key for skill_key in bound_skill_keys if skill_key not in active_key_set]

    return BoundSkillRuntimeResolution(
        active_skill_keys=active_skill_keys,
        inactive_skill_keys=inactive_skill_keys,
        activation_required_skill_keys=sorted(set(activation_required_skill_keys)),
        blocked_skill_reasons=blocked_skill_reasons,
    )


def build_skill_registry_summary(
    managed_skills: list[ManagedSkill] | None = None,
) -> SkillRegistrySummary:
    skills = managed_skills or list_managed_skills()

    admin_user = User()
    admin_user.role = UserRole.ADMIN
    admin_user.email = "admin@example.com"

    security_user = User()
    security_user.role = UserRole.BASIC
    security_user.email = "hunter@security.local"

    basic_user = User()
    basic_user.role = UserRole.BASIC
    basic_user.email = "user@example.com"

    return SkillRegistrySummary(
        discovered_count=len(scan_skill_directories()),
        managed_count=len(skills),
        enabled_count=sum(1 for skill in skills if skill.enabled),
        quarantined_count=sum(
            1
            for skill in skills
            if skill.access_scope == SkillAccessScope.QUARANTINED
        ),
        all_users_count=sum(
            1 for skill in skills if skill.access_scope == SkillAccessScope.ALL_USERS
        ),
        security_team_count=sum(
            1
            for skill in skills
            if skill.access_scope == SkillAccessScope.SECURITY_TEAM
        ),
        admin_only_count=sum(
            1 for skill in skills if skill.access_scope == SkillAccessScope.ADMIN_ONLY
        ),
        critical_count=sum(
            1 for skill in skills if skill.risk_level == SkillRiskLevel.CRITICAL
        ),
        authorized_scan_count=sum(
            1
            for skill in skills
            if skill.execution_scope == SkillExecutionScope.AUTHORIZED_SCAN
        ),
        approval_required_count=sum(1 for skill in skills if skill.requires_approval),
        gateway_enforced_count=sum(
            1 for skill in skills if skill.requires_network_gateway
        ),
        role_previews=[
            SkillRolePreview(
                role="basic_user",
                allowed_count=len(get_allowed_skill_names_for_user(basic_user)),
                allowed_skill_keys=sorted(get_allowed_skill_names_for_user(basic_user)),
            ),
            SkillRolePreview(
                role="security_team",
                allowed_count=len(get_allowed_skill_names_for_user(security_user)),
                allowed_skill_keys=sorted(
                    get_allowed_skill_names_for_user(security_user)
                ),
            ),
            SkillRolePreview(
                role="admin",
                allowed_count=len(get_allowed_skill_names_for_user(admin_user)),
                allowed_skill_keys=sorted(get_allowed_skill_names_for_user(admin_user)),
            ),
        ],
    )


def list_authorized_scan_targets() -> list[AuthorizedScanTarget]:
    payload = _load_authorized_targets_payload()
    targets: list[AuthorizedScanTarget] = []
    for entry in payload["targets"]:
        if not isinstance(entry, dict):
            continue
        targets.append(
            AuthorizedScanTarget(
                target=str(entry.get("target", "")).strip(),
                target_type=AuthorizedTargetType(entry.get("target_type", "domain")),
                owner=str(entry.get("owner", "")).strip(),
                approval_reference=str(entry.get("approval_reference", "")).strip(),
                enabled=bool(entry.get("enabled", True)),
                expires_at=entry.get("expires_at"),
                notes=entry.get("notes"),
            )
        )
    return targets


def export_authorized_scan_targets_yaml() -> str:
    if not AUTHORIZED_SCAN_TARGETS_PATH.exists():
        return yaml.safe_dump({"targets": []}, allow_unicode=True, sort_keys=False)
    return AUTHORIZED_SCAN_TARGETS_PATH.read_text(encoding="utf-8")


def import_authorized_scan_targets(
    request: AuthorizedScanTargetsImportRequest,
) -> AuthorizedScanTargetsImportSummary:
    loaded_payload = yaml.safe_load(request.yaml_content) or {}
    targets_payload = loaded_payload.get("targets", [])
    if not isinstance(targets_payload, list):
        raise ValueError("Imported authorized scan targets must contain a top-level 'targets' list")

    normalized_targets: list[dict[str, Any]] = []
    for entry in targets_payload:
        if not isinstance(entry, dict):
            raise ValueError("Each authorized scan target must be an object")
        normalized_targets.append(
            {
                "target": str(entry.get("target", "")).strip(),
                "target_type": AuthorizedTargetType(entry.get("target_type", "domain")).value,
                "owner": str(entry.get("owner", "")).strip(),
                "approval_reference": str(entry.get("approval_reference", "")).strip(),
                "enabled": bool(entry.get("enabled", True)),
                "expires_at": entry.get("expires_at"),
                "notes": entry.get("notes"),
            }
        )

    if request.mode == "replace":
        next_payload = {"targets": normalized_targets}
    else:
        existing = _load_authorized_targets_payload()["targets"]
        merged_targets: dict[tuple[str, str], dict[str, Any]] = {}
        for entry in existing:
            if not isinstance(entry, dict):
                continue
            merged_targets[
                (str(entry.get("target", "")).strip(), str(entry.get("target_type", "")).strip())
            ] = entry
        for entry in normalized_targets:
            merged_targets[(entry["target"], entry["target_type"])] = entry
        next_payload = {"targets": list(merged_targets.values())}

    _write_authorized_targets_payload(next_payload)

    return AuthorizedScanTargetsImportSummary(
        imported_count=len(normalized_targets),
        managed_count=len(next_payload["targets"]),
        mode=request.mode,
    )


def _detect_target_type(target: str) -> AuthorizedTargetType | None:
    stripped = target.strip()
    if not stripped:
        return None
    try:
        ipaddress.ip_address(stripped)
        return AuthorizedTargetType.IP
    except ValueError:
        pass
    try:
        ipaddress.ip_network(stripped, strict=False)
        return AuthorizedTargetType.CIDR
    except ValueError:
        pass
    parsed = urlparse(stripped)
    if parsed.scheme and parsed.netloc:
        return AuthorizedTargetType.URL
    if "." in stripped and " " not in stripped and "/" not in stripped:
        return AuthorizedTargetType.DOMAIN
    return None


def _is_target_entry_expired(entry: AuthorizedScanTarget) -> bool:
    if not entry.expires_at:
        return False
    try:
        return datetime.fromisoformat(entry.expires_at.replace("Z", "+00:00")) < datetime.now(timezone.utc)
    except Exception:
        return False


def _target_matches_entry(target: str, target_type: AuthorizedTargetType, entry: AuthorizedScanTarget) -> bool:
    if not entry.enabled or _is_target_entry_expired(entry):
        return False

    if target_type == AuthorizedTargetType.IP:
        if entry.target_type == AuthorizedTargetType.IP:
            return target == entry.target
        if entry.target_type == AuthorizedTargetType.CIDR:
            try:
                return ipaddress.ip_address(target) in ipaddress.ip_network(entry.target, strict=False)
            except ValueError:
                return False

    if target_type == AuthorizedTargetType.DOMAIN:
        if entry.target_type == AuthorizedTargetType.DOMAIN:
            return target == entry.target or target.endswith(f".{entry.target}")

    if target_type == AuthorizedTargetType.URL:
        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        if entry.target_type == AuthorizedTargetType.URL:
            return target == entry.target
        if entry.target_type == AuthorizedTargetType.DOMAIN:
            return hostname == entry.target or hostname.endswith(f".{entry.target}")

    if target_type == AuthorizedTargetType.CIDR and entry.target_type == AuthorizedTargetType.CIDR:
        return target == entry.target

    return False


def _append_authorized_scan_audit(record: dict[str, Any]) -> None:
    with open(AUTHORIZED_SCAN_AUDIT_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def list_authorized_scan_audit(limit: int = 20) -> list[dict[str, Any]]:
    if not AUTHORIZED_SCAN_AUDIT_PATH.exists():
        return []
    with open(AUTHORIZED_SCAN_AUDIT_PATH, "r", encoding="utf-8") as handle:
        lines = handle.readlines()[-limit:]
    records: list[dict[str, Any]] = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(records))


def build_authorized_scan_policy_summary(
    managed_skills: list[ManagedSkill] | None = None,
    authorized_targets: list[AuthorizedScanTarget] | None = None,
) -> AuthorizedScanPolicySummary:
    skills = managed_skills or list_managed_skills()
    targets = authorized_targets or list_authorized_scan_targets()
    return AuthorizedScanPolicySummary(
        managed_target_count=len(targets),
        enabled_target_count=sum(1 for target in targets if target.enabled),
        expired_target_count=sum(1 for target in targets if _is_target_entry_expired(target)),
        authorized_scan_skill_count=sum(
            1
            for skill in skills
            if skill.execution_scope == SkillExecutionScope.AUTHORIZED_SCAN
        ),
        approval_required_skill_count=sum(1 for skill in skills if skill.requires_approval),
        gateway_enforced_skill_count=sum(
            1 for skill in skills if skill.requires_network_gateway
        ),
    )


def authorize_skill_scan_execution(
    request: AuthorizedScanAuthorizationRequest,
    user: User,
) -> AuthorizedScanAuthorizationResult:
    skill = next((item for item in list_managed_skills() if item.key == request.skill_key), None)
    if skill is None:
        raise ValueError(f"Managed skill '{request.skill_key}' not found")

    reasons: list[str] = []
    allowed_targets: list[str] = []
    denied_targets: list[str] = []

    if not skill.enabled:
        reasons.append("Skill is disabled")
    if skill.execution_scope != SkillExecutionScope.AUTHORIZED_SCAN:
        reasons.append("Skill is not configured for authorized scan mode")
    if skill.requires_approval and not request.approval_reference:
        reasons.append("Approval reference is required")
    if skill.access_scope == SkillAccessScope.QUARANTINED:
        reasons.append("Skill is quarantined")
    elif skill.access_scope == SkillAccessScope.ADMIN_ONLY and not is_user_admin(user):
        reasons.append("Skill is restricted to admin users")
    elif skill.access_scope == SkillAccessScope.SECURITY_TEAM and not is_security_team_user(user):
        reasons.append("Skill is restricted to the security team")

    authorized_targets = list_authorized_scan_targets()
    for target in request.targets:
        target_type = _detect_target_type(target)
        if target_type is None:
            denied_targets.append(target)
            reasons.append(f"Unsupported target format: {target}")
            continue
        if skill.allowed_target_types and target_type not in skill.allowed_target_types:
            denied_targets.append(target)
            reasons.append(f"Target type '{target_type.value}' is not allowed for {skill.key}")
            continue
        if any(
            _target_matches_entry(target, target_type, entry)
            for entry in authorized_targets
        ):
            allowed_targets.append(target)
        else:
            denied_targets.append(target)
            reasons.append(f"Target not on authorized allowlist: {target}")

    allowed = not reasons and bool(allowed_targets) and not denied_targets
    result = AuthorizedScanAuthorizationResult(
        allowed=allowed,
        skill_key=skill.key,
        execution_scope=skill.execution_scope,
        gateway_required=skill.requires_network_gateway,
        allowed_targets=allowed_targets,
        denied_targets=denied_targets,
        reasons=list(dict.fromkeys(reasons)),
    )

    _append_authorized_scan_audit(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_email": getattr(user, "email", None),
            "skill_key": skill.key,
            "approval_reference": request.approval_reference,
            "requested_targets": request.targets,
            "allowed": result.allowed,
            "allowed_targets": allowed_targets,
            "denied_targets": denied_targets,
            "reasons": result.reasons,
        }
    )
    return result
