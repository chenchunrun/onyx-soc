from fastapi import APIRouter
from fastapi import Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from onyx.auth.users import current_admin_user
from onyx.configs.constants import PUBLIC_API_TAGS
from onyx.db.engine.sql_engine import get_session
from onyx.db.models import User
from onyx.server.manage.prompt_presets.registry import (
    ManagedPromptPreset,
    PromptPresetSummary,
    PromptPresetSyncSummary,
    build_prompt_preset_summary,
    export_prompt_presets_yaml,
    list_prompt_presets,
    sync_prompt_presets_to_public_prompts,
)

router = APIRouter(prefix="/manage/admin/prompt-presets", tags=PUBLIC_API_TAGS)


@router.get("")
def list_prompt_presets_api(
    query: str | None = None,
    category: str | None = None,
    agent_type: str | None = None,
    imported: bool | None = None,
    active: bool | None = None,
    _user: User = Depends(current_admin_user),
    db_session: Session = Depends(get_session),
) -> list[ManagedPromptPreset]:
    return list_prompt_presets(
        db_session=db_session,
        query=query,
        category=category,
        agent_type=agent_type,
        imported=imported,
        active=active,
    )


@router.get("/summary")
def get_prompt_preset_summary(
    _user: User = Depends(current_admin_user),
    db_session: Session = Depends(get_session),
) -> PromptPresetSummary:
    return build_prompt_preset_summary(db_session=db_session)


@router.get("/export")
def export_prompt_presets(
    _user: User = Depends(current_admin_user),
    db_session: Session = Depends(get_session),
) -> PlainTextResponse:
    return PlainTextResponse(
        export_prompt_presets_yaml(db_session=db_session),
        media_type="application/x-yaml",
        headers={
            "Content-Disposition": 'attachment; filename="prompt-presets.yaml"'
        },
    )


@router.post("/sync")
def sync_prompt_presets(
    _user: User = Depends(current_admin_user),
    db_session: Session = Depends(get_session),
) -> PromptPresetSyncSummary:
    return sync_prompt_presets_to_public_prompts(db_session=db_session)
