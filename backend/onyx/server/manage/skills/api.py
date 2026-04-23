from __future__ import annotations

from fastapi import APIRouter
from fastapi import Depends
from fastapi.responses import PlainTextResponse

from onyx.auth.users import current_user
from onyx.auth.users import current_admin_user
from onyx.configs.constants import PUBLIC_API_TAGS
from onyx.db.models import User
from onyx.error_handling.error_codes import OnyxErrorCode
from onyx.error_handling.exceptions import OnyxError
from onyx.server.manage.skills.registry import list_managed_skills
from onyx.server.manage.skills.registry import AuthorizedScanAuthorizationRequest
from onyx.server.manage.skills.registry import AuthorizedScanAuthorizationResult
from onyx.server.manage.skills.registry import AuthorizedScanPolicySummary
from onyx.server.manage.skills.registry import AuthorizedScanTarget
from onyx.server.manage.skills.registry import AuthorizedScanTargetsImportRequest
from onyx.server.manage.skills.registry import AuthorizedScanTargetsImportSummary
from onyx.server.manage.skills.registry import authorize_skill_scan_execution
from onyx.server.manage.skills.registry import build_authorized_scan_policy_summary
from onyx.server.manage.skills.registry import build_skill_registry_summary
from onyx.server.manage.skills.registry import export_authorized_scan_targets_yaml
from onyx.server.manage.skills.registry import export_skill_registry_yaml
from onyx.server.manage.skills.registry import (
    import_authorized_scan_targets as import_authorized_scan_targets_payload,
)
from onyx.server.manage.skills.registry import import_skill_registry
from onyx.server.manage.skills.registry import list_authorized_scan_audit
from onyx.server.manage.skills.registry import list_authorized_scan_targets
from onyx.server.manage.skills.registry import list_runtime_skill_audit
from onyx.server.manage.skills.registry import ManagedSkill
from onyx.server.manage.skills.registry import SkillAccessScope
from onyx.server.manage.skills.registry import SkillRegistryImportRequest
from onyx.server.manage.skills.registry import SkillRegistryImportSummary
from onyx.server.manage.skills.registry import SkillRiskLevel
from onyx.server.manage.skills.registry import SkillRegistrySummary
from onyx.server.manage.skills.registry import SkillRegistrySyncSummary
from onyx.server.manage.skills.registry import SkillRegistryUpdateRequest
from onyx.server.manage.skills.registry import sync_skill_registry
from onyx.server.manage.skills.registry import update_skill_registry_entry

router = APIRouter(prefix="/manage/admin/skills", tags=PUBLIC_API_TAGS)


@router.get("")
def list_skills(
    query: str | None = None,
    risk_level: SkillRiskLevel | None = None,
    access_scope: SkillAccessScope | None = None,
    enabled: bool | None = None,
    _user: User = Depends(current_admin_user),
) -> list[ManagedSkill]:
    return list_managed_skills(
        query=query,
        risk_level=risk_level,
        access_scope=access_scope,
        enabled=enabled,
    )


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


@router.get("/export")
def export_skills(
    _user: User = Depends(current_admin_user),
) -> PlainTextResponse:
    return PlainTextResponse(
        export_skill_registry_yaml(),
        media_type="application/x-yaml",
        headers={
            "Content-Disposition": 'attachment; filename="skills-registry.yaml"'
        },
    )


@router.post("/import")
def import_skills(
    request: SkillRegistryImportRequest,
    _user: User = Depends(current_admin_user),
) -> SkillRegistryImportSummary:
    try:
        return import_skill_registry(request)
    except ValueError as e:
        raise OnyxError(OnyxErrorCode.BAD_REQUEST, str(e))


@router.get("/scan-policy/summary")
def get_authorized_scan_policy_summary(
    _user: User = Depends(current_admin_user),
) -> AuthorizedScanPolicySummary:
    return build_authorized_scan_policy_summary()


@router.get("/scan-policy/targets")
def get_authorized_scan_targets(
    _user: User = Depends(current_admin_user),
) -> list[AuthorizedScanTarget]:
    return list_authorized_scan_targets()


@router.get("/scan-policy/targets/export")
def export_authorized_targets(
    _user: User = Depends(current_admin_user),
) -> PlainTextResponse:
    return PlainTextResponse(
        export_authorized_scan_targets_yaml(),
        media_type="application/x-yaml",
        headers={
            "Content-Disposition": 'attachment; filename="authorized-scan-targets.yaml"'
        },
    )


@router.post("/scan-policy/targets/import")
def import_authorized_targets(
    request: AuthorizedScanTargetsImportRequest,
    _user: User = Depends(current_admin_user),
) -> AuthorizedScanTargetsImportSummary:
    try:
        return import_authorized_scan_targets_payload(request)
    except ValueError as e:
        raise OnyxError(OnyxErrorCode.BAD_REQUEST, str(e))


@router.post("/scan-policy/authorize")
def authorize_scan(
    request: AuthorizedScanAuthorizationRequest,
    user: User = Depends(current_user),
) -> AuthorizedScanAuthorizationResult:
    try:
        return authorize_skill_scan_execution(request, user)
    except ValueError as e:
        raise OnyxError(OnyxErrorCode.BAD_REQUEST, str(e))


@router.get("/scan-policy/audit")
def get_authorized_scan_audit(
    limit: int = 20,
    _user: User = Depends(current_admin_user),
) -> list[dict[str, object]]:
    return list_authorized_scan_audit(limit=limit)


@router.get("/runtime-policy/audit")
def get_runtime_skill_audit(
    limit: int = 20,
    _user: User = Depends(current_admin_user),
) -> list[dict[str, object]]:
    return list_runtime_skill_audit(limit=limit)


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
