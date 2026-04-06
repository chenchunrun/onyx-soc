from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = (
    REPO_ROOT / "knowledge-base" / "security-automation" / "setup_security_tools.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "setup_security_tools", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_merge_tool_ids_preserves_existing_order() -> None:
    module = _load_module()

    merged = module.merge_tool_ids([1, 3, 4], [4, 12, 13])

    assert merged == [1, 3, 4, 12, 13]


def test_apply_tool_definitions_updates_persona_via_api_without_db(
    monkeypatch,
) -> None:
    module = _load_module()
    updated: list[tuple[int, list[int]]] = []

    monkeypatch.setattr(module, "load_template", lambda template_name: {"servers": []})
    monkeypatch.setattr(module, "get_tool_id", lambda base_url, cookie, tool_name: None)
    monkeypatch.setattr(
        module,
        "create_tool",
        lambda base_url, cookie, name, description, definition, custom_headers=None, passthrough_auth=False: {  # noqa: E501
            "id": {
                "send_security_alert": 11,
                "create_security_ticket": 12,
                "threat_intel_lookup": 13,
            }[name]
        },
    )
    monkeypatch.setattr(
        module,
        "get_persona_id_by_name",
        lambda base_url, cookie, persona_name: {
            "安全事件分析师": 2,
            "应急响应指挥官": 3,
            "漏洞评估专家": 4,
            "合规审计员": 5,
        }[persona_name],
    )
    monkeypatch.setattr(
        module,
        "get_persona_tool_ids",
        lambda base_url, cookie, persona_id: {
            2: [1, 3, 4],
            3: [1, 3, 4, 6],
            4: [1, 3, 4, 6],
            5: [1, 3, 4],
        }[persona_id],
    )
    monkeypatch.setattr(
        module,
        "update_persona_tools",
        lambda base_url, cookie, persona_id, tool_ids: updated.append(
            (persona_id, tool_ids)
        )
        or True,
    )

    result = module.apply_tool_definitions(
        "http://example.com",
        "cookie",
        dry_run=False,
    )

    assert result["errors"] == []
    assert updated == [
        (2, [1, 3, 4, 13, 12]),
        (3, [1, 3, 4, 6, 11, 12]),
        (4, [1, 3, 4, 6, 13, 12]),
        (5, [1, 3, 4, 12]),
    ]


def test_build_persona_update_payload_normalizes_embedded_references() -> None:
    module = _load_module()

    payload = module.build_persona_update_payload(
        {
            "name": "安全事件分析师",
            "description": "desc",
            "document_sets": [{"id": 1, "name": "安全知识库"}],
            "is_public": False,
            "llm_model_provider_override": None,
            "llm_model_version_override": None,
            "starter_messages": None,
            "users": [{"id": "user-1", "email": "u@example.com"}],
            "groups": [{"id": 5, "name": "soc"}],
            "uploaded_image_id": None,
            "icon_name": None,
            "search_start_date": None,
            "labels": [{"id": 7, "name": "security"}],
            "is_featured": False,
            "user_file_ids": ["file-1"],
            "hierarchy_nodes": [{"id": 8}],
            "attached_documents": [{"id": "doc-1"}],
            "system_prompt": "system",
            "task_prompt": "task",
            "datetime_aware": True,
        },
        [1, 3, 15],
    )

    assert payload["document_set_ids"] == [1]
    assert payload["users"] == ["user-1"]
    assert payload["groups"] == [5]
    assert payload["label_ids"] == [7]
    assert payload["hierarchy_node_ids"] == [8]
    assert payload["document_ids"] == ["doc-1"]
    assert payload["tool_ids"] == [1, 3, 15]


def test_apply_tool_definitions_skips_update_when_persona_already_has_tools(
    monkeypatch,
) -> None:
    module = _load_module()
    updated: list[tuple[int, list[int]]] = []

    monkeypatch.setattr(module, "load_template", lambda template_name: {"servers": []})
    monkeypatch.setattr(
        module,
        "get_tool_id",
        lambda base_url, cookie, tool_name: {
            "send_security_alert": 11,
            "create_security_ticket": 12,
            "threat_intel_lookup": 13,
        }[tool_name],
    )
    monkeypatch.setattr(
        module,
        "get_persona_id_by_name",
        lambda base_url, cookie, persona_name: 2 if persona_name == "安全事件分析师" else None,
    )
    monkeypatch.setattr(
        module,
        "get_persona_tool_ids",
        lambda base_url, cookie, persona_id: [1, 3, 4, 12, 13],
    )
    monkeypatch.setattr(
        module,
        "update_persona_tools",
        lambda base_url, cookie, persona_id, tool_ids: updated.append(
            (persona_id, tool_ids)
        )
        or True,
    )

    result = module.apply_tool_definitions("http://example.com", "cookie", dry_run=False)

    assert "Persona not found: 应急响应指挥官" in result["errors"]
    assert updated == []
