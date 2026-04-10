from __future__ import annotations

from fastapi import APIRouter
from fastapi import Depends

from onyx.auth.users import current_admin_user
from onyx.configs.constants import PUBLIC_API_TAGS
from onyx.db.models import User
from onyx.error_handling.error_codes import OnyxErrorCode
from onyx.error_handling.exceptions import OnyxError
from onyx.server.manage.skills.registry import list_managed_skills
from onyx.server.manage.skills.registry import build_skill_registry_summary
from onyx.server.manage.skills.registry import ManagedSkill
from onyx.server.manage.skills.registry import SkillRegistrySummary
from onyx.server.manage.skills.registry import SkillRegistrySyncSummary
from onyx.server.manage.skills.registry import SkillRegistryUpdateRequest
from onyx.server.manage.skills.registry import sync_skill_registry
from onyx.server.manage.skills.registry import update_skill_registry_entry

router = APIRouter(prefix="/manage/admin/skills", tags=PUBLIC_API_TAGS)


@router.get("")
def list_skills(_user: User = Depends(current_admin_user)) -> list[ManagedSkill]:
    return list_managed_skills()


@router.get("/summary")
def get_skill_summary(
    _user: User = Depends(current_admin_user),
) -> SkillRegistrySummary:
    return build_skill_registry_summary()


@router.post("/sync")
def sync_skills(
    _user: User = Depends(current_admin_user),
) -> SkillRegistrySyncSummary:
    return sync_skill_registry()


@router.put("/{skill_key}")
def update_skill(
    skill_key: str,
    request: SkillRegistryUpdateRequest,
    _user: User = Depends(current_admin_user),
) -> ManagedSkill:
    skill = update_skill_registry_entry(skill_key, request)
    if skill is None:
        raise OnyxError(
            OnyxErrorCode.NOT_FOUND, f"Managed skill '{skill_key}' not found"
        )
    return skill
