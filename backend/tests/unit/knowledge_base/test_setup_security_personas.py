from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "setup_security_personas.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "setup_security_personas", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_persona_payload_includes_security_defaults() -> None:
    module = _load_module()
    config = module.SECURITY_PERSONAS[0]

    payload = module.build_persona_payload(
        persona_config=config,
        document_set_id=17,
        tool_ids=[1, 2, 3],
    )

    assert payload["name"] == config["name"]
    assert payload["description"] == config["description"]
    assert payload["document_set_ids"] == [17]
    assert payload["tool_ids"] == [1, 2, 3]
    assert payload["is_public"] is False
    assert payload["display_priority"] == config["display_priority"]
    assert payload["datetime_aware"] is True
    assert payload["replace_base_system_prompt"] is False
    assert payload["label_ids"] == []
    assert payload["groups"] == []


def test_verify_personas_returns_zero_when_all_personas_exist(
    monkeypatch, capsys
) -> None:
    module = _load_module()

    monkeypatch.setattr(
        module,
        "list_personas",
        lambda base_url, cookie: [
            {"name": config["name"]} for config in module.SECURITY_PERSONAS
        ],
    )

    result = module.verify_personas("http://example.com", "cookie")
    output = capsys.readouterr().out

    assert result == 0
    assert "Configured personas found: 4/4" in output


def test_verify_personas_returns_one_when_personas_missing(
    monkeypatch, capsys
) -> None:
    module = _load_module()

    monkeypatch.setattr(
        module,
        "list_personas",
        lambda base_url, cookie: [{"name": module.SECURITY_PERSONAS[0]["name"]}],
    )

    result = module.verify_personas("http://example.com", "cookie")
    output = capsys.readouterr().out

    assert result == 1
    assert "Configured personas found: 1/4" in output
    assert f"{module.SECURITY_PERSONAS[1]['name']}: MISSING" in output


def test_apply_personas_dry_run_fails_when_security_document_set_missing(
    monkeypatch, capsys
) -> None:
    module = _load_module()

    monkeypatch.setattr(module, "list_personas", lambda base_url, cookie: [])
    monkeypatch.setattr(module, "list_document_sets", lambda base_url, cookie: [])
    monkeypatch.setattr(module, "list_tools", lambda base_url, cookie: [])

    result = module.apply_personas("http://example.com", "cookie", dry_run=True)
    output = capsys.readouterr().out

    assert result == 1
    assert "Missing document set: 安全知识库" in output


def test_apply_personas_dry_run_reports_create_and_update_actions(
    monkeypatch, capsys
) -> None:
    module = _load_module()

    monkeypatch.setattr(
        module,
        "list_personas",
        lambda base_url, cookie: [{"id": 9, "name": module.SECURITY_PERSONAS[0]["name"]}],
    )
    monkeypatch.setattr(
        module,
        "list_document_sets",
        lambda base_url, cookie: [{"id": 3, "name": "安全知识库"}],
    )
    monkeypatch.setattr(
        module,
        "list_tools",
        lambda base_url, cookie: [
            {"id": 1, "display_name": "Internal Search"},
            {"id": 2, "display_name": "Web Search"},
            {"id": 3, "display_name": "Open URL"},
            {"id": 4, "display_name": "Code Interpreter"},
        ],
    )

    result = module.apply_personas("http://example.com", "cookie", dry_run=True)
    output = capsys.readouterr().out

    assert result == 0
    assert f"Would update persona: {module.SECURITY_PERSONAS[0]['name']}" in output
    assert f"Would create persona: {module.SECURITY_PERSONAS[1]['name']}" in output
    assert "document_set_id=3" in output


def test_apply_personas_dry_run_falls_back_to_db_for_missing_builtin_tools(
    monkeypatch, capsys
) -> None:
    module = _load_module()

    monkeypatch.setattr(module, "list_personas", lambda base_url, cookie: [])
    monkeypatch.setattr(
        module,
        "list_document_sets",
        lambda base_url, cookie: [{"id": 3, "name": "安全知识库"}],
    )
    monkeypatch.setattr(
        module,
        "list_tools",
        lambda base_url, cookie: [
            {"id": 1, "display_name": "Internal Search"},
            {"id": 3, "display_name": "Open URL"},
            {"id": 4, "display_name": "Code Interpreter"},
        ],
    )
    monkeypatch.setattr(
        module,
        "get_builtin_tool_id_from_db",
        lambda tool_code_id, db_password=None: 9
        if tool_code_id == "WebSearchTool"
        else None,
    )

    result = module.apply_personas("http://example.com", "cookie", dry_run=True)
    output = capsys.readouterr().out

    assert result == 0
    assert "missing_tools=['Web Search']" not in output
    assert "tool_ids=[1, 9, 3]" in output


def test_apply_personas_apply_uses_api_tools_and_restores_db_only_tools(
    monkeypatch,
) -> None:
    module = _load_module()
    captured_payloads: list[dict] = []
    restored: list[tuple[int, list[int], str | None]] = []

    monkeypatch.setattr(
        module,
        "list_personas",
        lambda base_url, cookie: [{"id": 9, "name": module.SECURITY_PERSONAS[0]["name"]}],
    )
    monkeypatch.setattr(
        module,
        "list_document_sets",
        lambda base_url, cookie: [{"id": 3, "name": "安全知识库"}],
    )
    monkeypatch.setattr(
        module,
        "list_tools",
        lambda base_url, cookie: [
            {"id": 1, "display_name": "Internal Search"},
            {"id": 3, "display_name": "Open URL"},
        ],
    )
    monkeypatch.setattr(
        module,
        "get_builtin_tool_id_from_db",
        lambda tool_code_id, db_password=None: 9
        if tool_code_id == "WebSearchTool"
        else None,
    )
    monkeypatch.setattr(
        module,
        "get_persona",
        lambda base_url, cookie, persona_id: {
            "users": ["user-1"],
            "groups": [5],
            "tools": [{"id": 12, "name": "create_security_ticket"}],
        },
    )

    def _update_persona(base_url, cookie, persona_id, payload):
        captured_payloads.append(payload)
        return {"id": persona_id}

    monkeypatch.setattr(module, "update_persona", _update_persona)
    monkeypatch.setattr(module, "create_persona", lambda *args, **kwargs: {"id": 10})
    monkeypatch.setattr(
        module,
        "attach_tools_to_persona_db",
        lambda persona_id, tool_ids, db_password=None: restored.append(
            (persona_id, tool_ids, db_password)
        ),
    )

    result = module.apply_personas(
        "http://example.com", "cookie", dry_run=False, db_password="secret"
    )

    assert result == 0
    assert captured_payloads[0]["tool_ids"] == [12, 1, 3]
    assert captured_payloads[0]["users"] == ["user-1"]
    assert captured_payloads[0]["groups"] == [5]
    assert restored[0] == (9, [9], "secret")


def test_apply_personas_apply_normalizes_users_groups_and_preserves_existing_builtin_tools(
    monkeypatch,
) -> None:
    module = _load_module()
    captured_payloads: list[dict] = []

    monkeypatch.setattr(
        module,
        "list_personas",
        lambda base_url, cookie: [{"id": 9, "name": module.SECURITY_PERSONAS[1]["name"]}],
    )
    monkeypatch.setattr(
        module,
        "list_document_sets",
        lambda base_url, cookie: [{"id": 3, "name": "安全知识库"}],
    )
    monkeypatch.setattr(
        module,
        "list_tools",
        lambda base_url, cookie: [
            {"id": 1, "display_name": "Internal Search"},
            {"id": 3, "display_name": "Open URL"},
        ],
    )
    monkeypatch.setattr(
        module,
        "get_builtin_tool_id_from_db",
        lambda tool_code_id, db_password=None: (_ for _ in ()).throw(
            RuntimeError("db unavailable")
        ),
    )
    monkeypatch.setattr(
        module,
        "get_persona",
        lambda base_url, cookie, persona_id: {
            "users": [{"id": "user-1", "email": "u@example.com"}],
            "groups": [{"id": 5, "name": "soc"}],
            "tools": [
                {"id": 1, "name": "internal_search", "in_code_tool_id": "SearchTool"},
                {"id": 3, "name": "open_url", "in_code_tool_id": "OpenURLTool"},
                {"id": 4, "name": "web_search", "in_code_tool_id": "WebSearchTool"},
                {"id": 6, "name": "python", "in_code_tool_id": "PythonTool"},
                {"id": 12, "name": "create_security_ticket"},
            ],
        },
    )

    def _update_persona(base_url, cookie, persona_id, payload):
        captured_payloads.append(payload)
        return {"id": persona_id}

    monkeypatch.setattr(module, "update_persona", _update_persona)
    monkeypatch.setattr(module, "create_persona", lambda *args, **kwargs: {"id": 10})
    monkeypatch.setattr(module, "attach_tools_to_persona_db", lambda *args, **kwargs: None)

    result = module.apply_personas("http://example.com", "cookie", dry_run=False)

    assert result == 0
    assert captured_payloads[0]["tool_ids"] == [1, 3, 4, 6, 12]
    assert captured_payloads[0]["users"] == ["user-1"]
    assert captured_payloads[0]["groups"] == [5]
