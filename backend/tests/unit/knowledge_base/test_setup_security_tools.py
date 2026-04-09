from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import sys
from contextlib import redirect_stdout


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


def test_build_persona_bindings_groups_tools_by_persona() -> None:
    module = _load_module()

    result = module.build_persona_bindings(
        [
            {
                "name": "send_security_alert",
                "persona_bindings": ["应急响应指挥官"],
            },
            {
                "name": "create_security_ticket",
                "persona_bindings": ["安全事件分析师", "应急响应指挥官"],
            },
        ]
    )

    assert result == {
        "应急响应指挥官": ["send_security_alert", "create_security_ticket"],
        "安全事件分析师": ["create_security_ticket"],
    }


def test_validate_integration_config_requires_template_specific_fields() -> None:
    module = _load_module()

    try:
        module.validate_integration_config(
            {
                "name": "send_security_alert",
                "template": "security_alert_webhook",
                "description": "desc",
                "persona_bindings": ["应急响应指挥官"],
            },
            Path("/tmp/security-alert.yaml"),
        )
    except ValueError as exc:
        assert "webhook_url_env" in str(exc)
    else:
        raise AssertionError("Expected validate_integration_config() to fail")


def test_validate_integration_config_rejects_unknown_persona() -> None:
    module = _load_module()

    try:
        module.validate_integration_config(
            {
                "name": "send_security_alert",
                "template": "security_alert_webhook",
                "description": "desc",
                "webhook_url_env": "SECURITY_ALERT_WEBHOOK_URL",
                "persona_bindings": ["未知角色"],
            },
            Path("/tmp/security-alert.yaml"),
        )
    except ValueError as exc:
        assert "unsupported personas" in str(exc)
    else:
        raise AssertionError("Expected validate_integration_config() to fail")


def test_custom_headers_for_template_supports_new_templates() -> None:
    module = _load_module()

    assert module.custom_headers_for_template("siem_search_api", "token-1") == [
        {"key": "Authorization", "value": "Bearer token-1"}
    ]
    assert module.custom_headers_for_template("edr_response_api", "token-2") == [
        {"key": "Authorization", "value": "Bearer token-2"}
    ]
    assert module.custom_headers_for_template("asset_inventory_api", "token-3") == [
        {"key": "Authorization", "value": "Bearer token-3"}
    ]


def test_load_integration_configs_reads_yaml_directory(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    config_dir = tmp_path / "5-integrations"
    config_dir.mkdir()
    (config_dir / "security-alert.yaml").write_text(
        "\n".join(
            [
                "name: send_security_alert",
                "template: security_alert_webhook",
                "description: desc",
                "webhook_url_env: SECURITY_ALERT_WEBHOOK_URL",
                "persona_bindings:",
                "  - 应急响应指挥官",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "INTEGRATIONS_DIR", config_dir)

    configs = module.load_integration_configs()

    assert len(configs) == 1
    assert configs[0]["name"] == "send_security_alert"
    assert configs[0]["_config_path"].endswith("security-alert.yaml")


def test_resolve_profile_env_name_uses_mock_override(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "load_integration_profiles",
        lambda: {
            "profiles": {
                "live": {"env_overrides": {}},
                "mock": {
                    "env_overrides": {
                        "THREAT_INTEL_API_URL": "SECURITY_TOOLS_MOCK_SERVER_URL"
                    }
                },
            }
        },
    )

    result = module.resolve_profile_env_name(
        "THREAT_INTEL_API_URL",
        module.argparse.Namespace(profile="mock"),
    )

    assert result == "SECURITY_TOOLS_MOCK_SERVER_URL"


def test_resolve_profile_env_name_uses_gateway_override(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "load_integration_profiles",
        lambda: {
            "profiles": {
                "live": {"env_overrides": {}},
                "gateway": {
                    "env_overrides": {
                        "THREAT_INTEL_API_URL": "SECURITY_TOOLS_GATEWAY_URL"
                    }
                },
            }
        },
    )

    result = module.resolve_profile_env_name(
        "THREAT_INTEL_API_URL",
        module.argparse.Namespace(profile="gateway"),
    )

    assert result == "SECURITY_TOOLS_GATEWAY_URL"


def test_list_templates_does_not_require_login(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "get_cookie", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("get_cookie should not be called for --list-templates")
    ))
    monkeypatch.setattr(sys, "argv", ["setup_security_tools.py", "--list-templates"])

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        module.main()

    output = stdout.getvalue()
    assert "Available templates:" in output
    assert "Integration configs are located at:" in output
    assert "Supported personas:" in output


def test_validate_configs_does_not_require_login(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "get_cookie", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("get_cookie should not be called for --validate-configs")
    ))
    monkeypatch.setattr(
        module,
        "load_integration_configs",
        lambda: [
            {
                "name": "send_security_alert",
                "template": "security_alert_webhook",
                "persona_bindings": ["应急响应指挥官"],
            }
        ],
    )
    monkeypatch.setattr(
        module,
        "load_integration_profiles",
        lambda: {"profiles": {"live": {"env_overrides": {}}, "mock": {"env_overrides": {}}}},
    )
    monkeypatch.setattr(sys, "argv", ["setup_security_tools.py", "--validate-configs"])

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        module.main()

    output = stdout.getvalue()
    assert "Integration profile: live" in output
    assert "Integration configs: 1" in output
    assert "send_security_alert" in output


def test_apply_tool_definitions_updates_persona_via_api_without_db(
    monkeypatch,
) -> None:
    module = _load_module()
    updated: list[tuple[int, list[int]]] = []
    monkeypatch.setattr(
        module,
        "load_integration_configs",
        lambda: [
            {
                "name": "send_security_alert",
                "template": "security_alert_webhook",
                "description": "desc",
                "webhook_url_env": "SECURITY_ALERT_WEBHOOK_URL",
                "persona_bindings": ["应急响应指挥官"],
            },
            {
                "name": "create_security_ticket",
                "template": "security_ticket_api",
                "description": "desc",
                "api_url_env": "SECURITY_TICKET_API_URL",
                "api_key_env": "SECURITY_TICKET_API_KEY",
                "persona_bindings": ["安全事件分析师", "应急响应指挥官", "漏洞评估专家", "合规审计员"],
            },
            {
                "name": "threat_intel_lookup",
                "template": "threat_intel_api",
                "description": "desc",
                "api_url_env": "THREAT_INTEL_API_URL",
                "api_key_env": "THREAT_INTEL_API_KEY",
                "persona_bindings": ["安全事件分析师", "漏洞评估专家"],
            },
        ],
    )
    monkeypatch.setattr(
        module,
        "load_integration_profiles",
        lambda: {"profiles": {"live": {"env_overrides": {}}, "mock": {"env_overrides": {}}}},
    )

    monkeypatch.setattr(module, "load_template", lambda template_name: {"servers": []})
    monkeypatch.setattr(module, "get_tool_id", lambda base_url, cookie, tool_name: None)
    monkeypatch.setattr(module, "get_tool_by_name", lambda *args, **kwargs: None)
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
        "get_persona",
        lambda base_url, cookie, persona_id: {
            "tools": {
                2: [
                    {"id": 1, "display_name": "Internal Search", "in_code_tool_id": "SearchTool"},
                    {"id": 3, "display_name": "Web Search", "in_code_tool_id": "WebSearchTool"},
                    {"id": 4, "display_name": "Open URL", "in_code_tool_id": "OpenURLTool"},
                ],
                3: [
                    {"id": 1, "display_name": "Internal Search", "in_code_tool_id": "SearchTool"},
                    {"id": 3, "display_name": "Web Search", "in_code_tool_id": "WebSearchTool"},
                    {"id": 4, "display_name": "Open URL", "in_code_tool_id": "OpenURLTool"},
                    {"id": 6, "display_name": "Code Interpreter", "in_code_tool_id": "PythonTool"},
                ],
                4: [
                    {"id": 1, "display_name": "Internal Search", "in_code_tool_id": "SearchTool"},
                    {"id": 3, "display_name": "Web Search", "in_code_tool_id": "WebSearchTool"},
                    {"id": 4, "display_name": "Open URL", "in_code_tool_id": "OpenURLTool"},
                    {"id": 6, "display_name": "Code Interpreter", "in_code_tool_id": "PythonTool"},
                ],
                5: [
                    {"id": 1, "display_name": "Internal Search", "in_code_tool_id": "SearchTool"},
                    {"id": 3, "display_name": "Web Search", "in_code_tool_id": "WebSearchTool"},
                    {"id": 4, "display_name": "Open URL", "in_code_tool_id": "OpenURLTool"},
                ],
            }[persona_id]
        },
    )
    monkeypatch.setattr(module, "attach_tools_to_persona_db", lambda *args, **kwargs: None)
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
        profile_name="live",
    )

    assert result["errors"] == []
    assert updated == [
        (3, [11, 12]),
        (2, [12, 13]),
        (4, [12, 13]),
        (5, [12]),
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


def test_apply_tool_definitions_uses_profile_overrides_for_mock(
    monkeypatch,
) -> None:
    module = _load_module()
    captured: list[dict] = []
    monkeypatch.setattr(
        module,
        "load_integration_configs",
        lambda: [
            {
                "name": "threat_intel_lookup",
                "template": "threat_intel_api",
                "description": "desc",
                "api_url_env": "THREAT_INTEL_API_URL",
                "api_key_env": "THREAT_INTEL_API_KEY",
                "persona_bindings": ["安全事件分析师"],
            },
        ],
    )
    monkeypatch.setattr(
        module,
        "load_integration_profiles",
        lambda: {
            "profiles": {
                "live": {"env_overrides": {}},
                "mock": {
                    "env_overrides": {
                        "THREAT_INTEL_API_URL": "SECURITY_TOOLS_MOCK_SERVER_URL",
                        "THREAT_INTEL_API_KEY": "SECURITY_TOOLS_MOCK_API_KEY",
                    }
                },
            }
        },
    )
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_SERVER_URL", "http://localhost:9999")
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_API_KEY", "mock-api-key")
    monkeypatch.setattr(module, "load_template", lambda template_name: {"servers": [{"url": "{API_BASE_URL}"}]})
    monkeypatch.setattr(module, "get_tool_id", lambda base_url, cookie, tool_name: None)
    monkeypatch.setattr(
        module,
        "create_tool",
        lambda **kwargs: captured.append(kwargs) or {"id": 13},
    )
    monkeypatch.setattr(module, "get_persona_id_by_name", lambda *args, **kwargs: 2)
    monkeypatch.setattr(
        module,
        "get_persona",
        lambda *args, **kwargs: {
            "tools": [
                {"id": 1, "display_name": "Internal Search", "in_code_tool_id": "SearchTool"},
                {"id": 3, "display_name": "Web Search", "in_code_tool_id": "WebSearchTool"},
                {"id": 4, "display_name": "Open URL", "in_code_tool_id": "OpenURLTool"},
            ]
        },
    )
    monkeypatch.setattr(module, "attach_tools_to_persona_db", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "update_persona_tools", lambda *args, **kwargs: True)

    result = module.apply_tool_definitions(
        "http://example.com",
        "cookie",
        dry_run=False,
        profile_name="mock",
    )

    assert result["errors"] == []
    assert captured[0]["definition"]["servers"][0]["url"] == "http://localhost:9999"
    assert captured[0]["custom_headers"] == [{"key": "x-apikey", "value": "mock-api-key"}]


def test_apply_tool_definitions_updates_existing_tool_for_target_profile(
    monkeypatch,
) -> None:
    module = _load_module()
    updated: list[dict] = []
    monkeypatch.setattr(
        module,
        "load_integration_configs",
        lambda: [
            {
                "name": "threat_intel_lookup",
                "template": "threat_intel_api",
                "description": "desc",
                "api_url_env": "THREAT_INTEL_API_URL",
                "api_key_env": "THREAT_INTEL_API_KEY",
                "persona_bindings": ["安全事件分析师"],
            },
        ],
    )
    monkeypatch.setattr(
        module,
        "load_integration_profiles",
        lambda: {
            "profiles": {
                "live": {"env_overrides": {}},
                "mock": {
                    "env_overrides": {
                        "THREAT_INTEL_API_URL": "SECURITY_TOOLS_MOCK_SERVER_URL",
                        "THREAT_INTEL_API_KEY": "SECURITY_TOOLS_MOCK_API_KEY",
                    }
                },
            }
        },
    )
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_SERVER_URL", "http://localhost:9999")
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_API_KEY", "mock-api-key")
    monkeypatch.setattr(module, "load_template", lambda template_name: {"servers": [{"url": "{API_BASE_URL}"}]})
    monkeypatch.setattr(
        module,
        "get_tool_by_name",
        lambda base_url, cookie, tool_name: {
            "id": 16,
            "name": "threat_intel_lookup",
            "description": "old desc",
            "definition": {"servers": [{"url": "https://live.example.com"}]},
            "custom_headers": [{"key": "x-apikey", "value": "old-key"}],
            "passthrough_auth": False,
        },
    )
    monkeypatch.setattr(
        module,
        "update_tool",
        lambda **kwargs: updated.append(kwargs) or {"id": 16},
    )
    monkeypatch.setattr(module, "get_persona_id_by_name", lambda *args, **kwargs: 2)
    monkeypatch.setattr(
        module,
        "get_persona",
        lambda *args, **kwargs: {
            "tools": [
                {"id": 1, "display_name": "Internal Search", "in_code_tool_id": "SearchTool"},
                {"id": 3, "display_name": "Web Search", "in_code_tool_id": "WebSearchTool"},
                {"id": 4, "display_name": "Open URL", "in_code_tool_id": "OpenURLTool"},
                {"id": 16, "name": "threat_intel_lookup"},
            ]
        },
    )
    monkeypatch.setattr(module, "attach_tools_to_persona_db", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "update_persona_tools", lambda *args, **kwargs: True)

    result = module.apply_tool_definitions(
        "http://example.com",
        "cookie",
        dry_run=False,
        profile_name="mock",
    )

    assert result["errors"] == []
    assert updated[0]["tool_id"] == 16


def test_apply_tool_definitions_uses_profile_overrides_for_gateway(
    monkeypatch,
) -> None:
    module = _load_module()
    captured: list[dict] = []
    monkeypatch.setattr(
        module,
        "load_integration_configs",
        lambda: [
            {
                "name": "threat_intel_lookup",
                "template": "threat_intel_api",
                "description": "desc",
                "api_url_env": "THREAT_INTEL_API_URL",
                "api_key_env": "THREAT_INTEL_API_KEY",
                "persona_bindings": ["安全事件分析师"],
            },
        ],
    )
    monkeypatch.setattr(
        module,
        "load_integration_profiles",
        lambda: {
            "profiles": {
                "live": {"env_overrides": {}},
                "gateway": {
                    "env_overrides": {
                        "THREAT_INTEL_API_URL": "SECURITY_TOOLS_GATEWAY_URL",
                        "THREAT_INTEL_API_KEY": "SECURITY_TOOLS_GATEWAY_API_KEY",
                    }
                },
            }
        },
    )
    monkeypatch.setenv("SECURITY_TOOLS_GATEWAY_URL", "http://host.docker.internal:9999")
    monkeypatch.setenv("SECURITY_TOOLS_GATEWAY_API_KEY", "gateway-key")
    monkeypatch.setattr(module, "load_template", lambda template_name: {"servers": [{"url": "{API_BASE_URL}"}]})
    monkeypatch.setattr(module, "get_tool_id", lambda base_url, cookie, tool_name: None)
    monkeypatch.setattr(
        module,
        "create_tool",
        lambda **kwargs: captured.append(kwargs) or {"id": 13},
    )
    monkeypatch.setattr(module, "get_persona_id_by_name", lambda *args, **kwargs: 2)
    monkeypatch.setattr(
        module,
        "get_persona",
        lambda *args, **kwargs: {
            "tools": [
                {"id": 1, "display_name": "Internal Search", "in_code_tool_id": "SearchTool"},
                {"id": 3, "display_name": "Web Search", "in_code_tool_id": "WebSearchTool"},
                {"id": 4, "display_name": "Open URL", "in_code_tool_id": "OpenURLTool"},
            ]
        },
    )
    monkeypatch.setattr(module, "attach_tools_to_persona_db", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "update_persona_tools", lambda *args, **kwargs: True)

    result = module.apply_tool_definitions(
        "http://example.com",
        "cookie",
        dry_run=False,
        profile_name="gateway",
    )

    assert result["errors"] == []
    assert captured[0]["definition"]["servers"][0]["url"] == "http://host.docker.internal:9999"
    assert captured[0]["custom_headers"] == [{"key": "x-apikey", "value": "gateway-key"}]


def test_apply_tool_definitions_skips_update_when_persona_already_has_tools(
    monkeypatch,
) -> None:
    module = _load_module()
    updated: list[tuple[int, list[int]]] = []
    monkeypatch.setattr(
        module,
        "load_integration_configs",
        lambda: [
            {
                "name": "send_security_alert",
                "template": "security_alert_webhook",
                "description": "desc",
                "webhook_url_env": "SECURITY_ALERT_WEBHOOK_URL",
                "persona_bindings": ["应急响应指挥官"],
            },
            {
                "name": "create_security_ticket",
                "template": "security_ticket_api",
                "description": "desc",
                "api_url_env": "SECURITY_TICKET_API_URL",
                "api_key_env": "SECURITY_TICKET_API_KEY",
                "persona_bindings": ["安全事件分析师", "应急响应指挥官", "漏洞评估专家", "合规审计员"],
            },
            {
                "name": "threat_intel_lookup",
                "template": "threat_intel_api",
                "description": "desc",
                "api_url_env": "THREAT_INTEL_API_URL",
                "api_key_env": "THREAT_INTEL_API_KEY",
                "persona_bindings": ["安全事件分析师", "漏洞评估专家"],
            },
        ],
    )

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
        "get_persona",
        lambda base_url, cookie, persona_id: {
            "tools": [
                {"id": 1, "display_name": "Internal Search", "in_code_tool_id": "SearchTool"},
                {"id": 3, "display_name": "Web Search", "in_code_tool_id": "WebSearchTool"},
                {"id": 4, "display_name": "Open URL", "in_code_tool_id": "OpenURLTool"},
                {"id": 12, "name": "create_security_ticket"},
                {"id": 13, "name": "threat_intel_lookup"},
            ]
        },
    )
    monkeypatch.setattr(module, "attach_tools_to_persona_db", lambda *args, **kwargs: None)
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
