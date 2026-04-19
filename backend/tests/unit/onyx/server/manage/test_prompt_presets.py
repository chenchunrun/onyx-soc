from types import SimpleNamespace

from onyx.server.manage.prompt_presets import registry
from onyx.server.manage.prompt_presets.registry import PromptPreset


def test_list_prompt_presets_marks_imported_and_filters(monkeypatch) -> None:
    preset = PromptPreset(
        id="security_report_mode",
        name="汇报模式",
        description="管理层摘要",
        content="请用汇报模式回复",
        category="quickStart",
        agent_type="securityCheck",
        source_file="prompts/security_check_presets.json",
    )

    monkeypatch.setattr(registry, "scan_prompt_presets", lambda prompts_root=None: [preset])
    monkeypatch.setattr(
        registry,
        "_fetch_public_prompt_map",
        lambda shortcut_names, db_session: {
            preset.shortcut_name: SimpleNamespace(id=7, active=True)
        },
    )

    results = registry.list_prompt_presets(
        db_session=SimpleNamespace(),
        query="securitycheck",
        imported=True,
        active=True,
    )

    assert len(results) == 1
    assert results[0].shortcut_name == "样板 · Security Check · 汇报模式"
    assert results[0].imported is True
    assert results[0].input_prompt_id == 7


def test_sync_prompt_presets_creates_and_updates_public_prompts(monkeypatch) -> None:
    new_preset = PromptPreset(
        id="general_concise_mode",
        name="简洁模式",
        description="简洁回答",
        content="请简洁回答",
        category="quickStart",
        agent_type="generalAssistant",
        source_file="prompts/general_assistant_presets.json",
    )
    existing_preset = PromptPreset(
        id="security_report_mode",
        name="汇报模式",
        description="管理层摘要",
        content="新内容",
        category="quickStart",
        agent_type="securityCheck",
        source_file="prompts/security_check_presets.json",
    )

    existing_prompt = SimpleNamespace(
        id=9,
        prompt=existing_preset.shortcut_name,
        content="旧内容",
        active=False,
    )

    class FakeSession:
        def __init__(self) -> None:
            self.added = []
            self.committed = False

        def add(self, prompt) -> None:
            self.added.append(prompt)

        def commit(self) -> None:
            self.committed = True

    fake_session = FakeSession()

    monkeypatch.setattr(
        registry,
        "scan_prompt_presets",
        lambda prompts_root=None: [new_preset, existing_preset],
    )
    monkeypatch.setattr(
        registry,
        "_fetch_public_prompt_map",
        lambda shortcut_names, db_session: {
            existing_preset.shortcut_name: existing_prompt,
        },
    )

    summary = registry.sync_prompt_presets_to_public_prompts(db_session=fake_session)

    assert summary.discovered_count == 2
    assert summary.created_count == 1
    assert summary.updated_count == 1
    assert fake_session.committed is True
    assert fake_session.added[0].prompt == new_preset.shortcut_name
    assert existing_prompt.content == "新内容"
    assert existing_prompt.active is True


def test_scan_prompt_presets_respects_ttl_cache(tmp_path, monkeypatch) -> None:
    prompts_root = tmp_path / "prompts"
    prompts_root.mkdir(parents=True, exist_ok=True)
    preset_file = prompts_root / "presets.json"
    preset_file.write_text(
        """
[
  {
    "id": "cached_preset",
    "name": "缓存样板",
    "description": "缓存命中",
    "content": "内容A",
    "category": "quickStart",
    "agentType": "generalAssistant"
  }
]
""".strip(),
        encoding="utf-8",
    )

    monotonic_values = iter([200.0, 205.0, 211.0])
    monkeypatch.setattr(registry, "_PROMPT_PRESET_CACHE", {})
    monkeypatch.setattr(registry, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(registry, "ROOT_PATH", tmp_path)

    first_scan = registry.scan_prompt_presets(prompts_root=prompts_root)
    assert [preset.id for preset in first_scan] == ["cached_preset"]

    # Modify file contents; second scan should still return cached data within TTL.
    preset_file.write_text(
        """
[
  {
    "id": "cached_preset_updated",
    "name": "缓存样板",
    "description": "缓存未过期",
    "content": "内容B",
    "category": "quickStart",
    "agentType": "generalAssistant"
  }
]
""".strip(),
        encoding="utf-8",
    )
    second_scan = registry.scan_prompt_presets(prompts_root=prompts_root)
    assert [preset.id for preset in second_scan] == ["cached_preset"]

    # After TTL expiration, cache should refresh and expose latest file contents.
    third_scan = registry.scan_prompt_presets(prompts_root=prompts_root)
    assert [preset.id for preset in third_scan] == ["cached_preset_updated"]
