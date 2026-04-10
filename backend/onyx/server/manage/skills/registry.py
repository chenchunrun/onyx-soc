from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any
from typing import Literal

from pydantic import BaseModel
import yaml

from onyx.auth.schemas import UserRole
from onyx.db.models import User
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

SECURITY_TEAM_EMAILS = {
    "commander@security.local",
    "analyst@security.local",
    "vuln_expert@security.local",
    "auditor@security.local",
    "hunter@security.local",
    "malware@security.local",
    "detection@security.local",
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
    notes: str | None = None


class SkillRegistryUpdateRequest(BaseModel):
    enabled: bool | None = None
    risk_level: SkillRiskLevel | None = None
    access_scope: SkillAccessScope | None = None
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
    role_previews: list[SkillRolePreview]


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
            "notes": "Created automatically.",
        },
    )

    if request.enabled is not None:
        entry["enabled"] = request.enabled
    if request.risk_level is not None:
        entry["risk_level"] = request.risk_level.value
    if request.access_scope is not None:
        entry["access_scope"] = request.access_scope.value
    if request.notes is not None:
        entry["notes"] = request.notes

    _write_registry_payload(payload)

    for skill in list_managed_skills():
        if skill.key == skill_key:
            return skill
    return None


def is_security_team_user(user: User) -> bool:
    if user.role == UserRole.ADMIN:
        return True
    return bool(user.email and user.email.lower() in SECURITY_TEAM_EMAILS)


def user_can_access_skill(skill: ManagedSkill, user: User) -> bool:
    if not skill.enabled:
        return False

    if skill.access_scope == SkillAccessScope.ALL_USERS:
        return True
    if skill.access_scope == SkillAccessScope.ADMIN_ONLY:
        return user.role == UserRole.ADMIN
    if skill.access_scope == SkillAccessScope.SECURITY_TEAM:
        return is_security_team_user(user)
    return False


def get_allowed_skill_names_for_user(user: User) -> set[str]:
    return {
        skill.key
        for skill in list_managed_skills()
        if user_can_access_skill(skill, user)
    }


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
