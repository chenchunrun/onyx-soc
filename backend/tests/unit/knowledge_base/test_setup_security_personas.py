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
