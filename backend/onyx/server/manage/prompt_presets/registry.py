from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from time import monotonic

import yaml
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from onyx.db.models import InputPrompt

def _detect_root_path() -> Path:
    current = Path(__file__).resolve()
    candidates = [current.parents[4], current.parents[5]]
    for candidate in candidates:
        if (candidate / "prompts").exists():
            return candidate
    return candidates[0]


ROOT_PATH = _detect_root_path()
PROMPTS_ROOT = ROOT_PATH / "prompts"
SCAN_CACHE_TTL_SECONDS = 10
_PROMPT_PRESET_CACHE: dict[str, tuple[float, list["PromptPreset"]]] = {}


def _camel_case_to_label(value: str) -> str:
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value).strip()
    return words.title() if words else value


class PromptPreset(BaseModel):
    id: str
    name: str
    description: str
    content: str
    category: str
    agent_type: str
    author: str | None = None
    is_preset: bool = True
    source_file: str

    @property
    def shortcut_name(self) -> str:
        return f"样板 · {_camel_case_to_label(self.agent_type)} · {self.name}"


class ManagedPromptPreset(PromptPreset):
    imported: bool
    input_prompt_id: int | None
    active: bool


class PromptPresetSummary(BaseModel):
    discovered_count: int
    imported_count: int
    active_count: int
    agent_type_counts: dict[str, int]
    category_counts: dict[str, int]


class PromptPresetSyncSummary(BaseModel):
    discovered_count: int
    created_count: int
    updated_count: int
    imported_count: int


def _parse_prompt_preset_file(path: Path) -> list[PromptPreset]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"Prompt preset file must contain a list: {path}")

    presets: list[PromptPreset] = []
    for item in payload:
        presets.append(
            PromptPreset(
                id=item["id"],
                name=item["name"],
                description=item["description"],
                content=item["content"],
                category=item["category"],
                agent_type=item["agentType"],
                author=item.get("author"),
                is_preset=bool(item.get("isPreset", True)),
                source_file=str(path.relative_to(ROOT_PATH)),
            )
        )
    return presets


def scan_prompt_presets(prompts_root: Path | None = None) -> list[PromptPreset]:
    root = prompts_root or PROMPTS_ROOT
    cache_key = str(root.resolve())
    now = monotonic()
    cached_entry = _PROMPT_PRESET_CACHE.get(cache_key)
    if cached_entry and now - cached_entry[0] < SCAN_CACHE_TTL_SECONDS:
        return [preset.model_copy(deep=True) for preset in cached_entry[1]]

    presets: list[PromptPreset] = []

    if not root.exists():
        _PROMPT_PRESET_CACHE[cache_key] = (now, presets)
        return presets

    for json_path in sorted(root.glob("*.json")):
        presets.extend(_parse_prompt_preset_file(json_path))

    sorted_presets = sorted(presets, key=lambda preset: (preset.agent_type, preset.name))
    _PROMPT_PRESET_CACHE[cache_key] = (now, sorted_presets)
    return [preset.model_copy(deep=True) for preset in sorted_presets]


def _fetch_public_prompt_map(
    shortcut_names: list[str], db_session: Session
) -> dict[str, InputPrompt]:
    if not shortcut_names:
        return {}

    prompts = list(
        db_session.scalars(
            select(InputPrompt).where(
                InputPrompt.is_public.is_(True),
                InputPrompt.user_id.is_(None),
                InputPrompt.prompt.in_(shortcut_names),
            )
        ).all()
    )
    return {prompt.prompt: prompt for prompt in prompts}


def list_prompt_presets(
    db_session: Session,
    query: str | None = None,
    category: str | None = None,
    agent_type: str | None = None,
    imported: bool | None = None,
    active: bool | None = None,
) -> list[ManagedPromptPreset]:
    presets = scan_prompt_presets()
    imported_map = _fetch_public_prompt_map(
        [preset.shortcut_name for preset in presets],
        db_session,
    )

    results: list[ManagedPromptPreset] = []
    normalized_query = query.lower().strip() if query else None
    for preset in presets:
        existing_prompt = imported_map.get(preset.shortcut_name)
        managed = ManagedPromptPreset(
            **preset.model_dump(),
            imported=existing_prompt is not None,
            input_prompt_id=existing_prompt.id if existing_prompt else None,
            active=existing_prompt.active if existing_prompt else False,
        )

        if normalized_query:
            haystack = " ".join(
                [
                    managed.id,
                    managed.name,
                    managed.description,
                    managed.category,
                    managed.agent_type,
                    managed.source_file,
                ]
            ).lower()
            if normalized_query not in haystack:
                continue
        if category and managed.category != category:
            continue
        if agent_type and managed.agent_type != agent_type:
            continue
        if imported is not None and managed.imported != imported:
            continue
        if active is not None and managed.active != active:
            continue

        results.append(managed)

    return results


def build_prompt_preset_summary(db_session: Session) -> PromptPresetSummary:
    presets = list_prompt_presets(db_session=db_session)
    return PromptPresetSummary(
        discovered_count=len(presets),
        imported_count=sum(1 for preset in presets if preset.imported),
        active_count=sum(1 for preset in presets if preset.active),
        agent_type_counts=dict(Counter(preset.agent_type for preset in presets)),
        category_counts=dict(Counter(preset.category for preset in presets)),
    )


def export_prompt_presets_yaml(db_session: Session) -> str:
    presets = list_prompt_presets(db_session=db_session)
    payload = {
        "presets": [
            {
                "id": preset.id,
                "name": preset.name,
                "description": preset.description,
                "category": preset.category,
                "agent_type": preset.agent_type,
                "shortcut_name": preset.shortcut_name,
                "imported": preset.imported,
                "active": preset.active,
                "source_file": preset.source_file,
            }
            for preset in presets
        ]
    }
    return yaml.safe_dump(payload, allow_unicode=True, sort_keys=False)


def sync_prompt_presets_to_public_prompts(db_session: Session) -> PromptPresetSyncSummary:
    presets = scan_prompt_presets()
    imported_map = _fetch_public_prompt_map(
        [preset.shortcut_name for preset in presets],
        db_session,
    )

    created_count = 0
    updated_count = 0

    for preset in presets:
        existing_prompt = imported_map.get(preset.shortcut_name)
        if existing_prompt is None:
            db_session.add(
                InputPrompt(
                    prompt=preset.shortcut_name,
                    content=preset.content,
                    active=True,
                    is_public=True,
                    user_id=None,
                )
            )
            created_count += 1
            continue

        if existing_prompt.content != preset.content or not existing_prompt.active:
            existing_prompt.content = preset.content
            existing_prompt.active = True
            updated_count += 1

    db_session.commit()

    return PromptPresetSyncSummary(
        discovered_count=len(presets),
        created_count=created_count,
        updated_count=updated_count,
        imported_count=len(presets),
    )
