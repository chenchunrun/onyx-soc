from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "verify_security_platform_acceptance.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "verify_security_platform_acceptance", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_evaluate_acceptance_returns_ok_for_complete_state() -> None:
    module = _load_module()
    module.load_security_tool_configs = lambda: [
        {
            "name": "create_security_ticket",
            "persona_bindings": ["安全事件分析师", "应急响应指挥官", "漏洞评估专家", "合规审计员"],
        },
        {
            "name": "send_security_alert",
            "persona_bindings": ["应急响应指挥官"],
        },
        {
            "name": "threat_intel_lookup",
            "persona_bindings": ["安全事件分析师", "漏洞评估专家"],
        },
        {
            "name": "search_security_alerts",
            "persona_bindings": ["安全事件分析师", "应急响应指挥官"],
        },
        {
            "name": "isolate_endpoint_host",
            "persona_bindings": ["安全事件分析师", "应急响应指挥官"],
        },
        {
            "name": "lookup_asset_context",
            "persona_bindings": ["安全事件分析师", "漏洞评估专家", "合规审计员"],
        },
    ]

    personas = [
        {
            "name": "安全事件分析师",
            "tools": [
                {"display_name": "Internal Search"},
                {"display_name": "Web Search"},
                    {"display_name": "Open URL"},
                    {"name": "threat_intel_lookup"},
                    {"name": "create_security_ticket"},
                    {"name": "search_security_alerts"},
                    {"name": "isolate_endpoint_host"},
                    {"name": "lookup_asset_context"},
                ],
            },
        {
            "name": "应急响应指挥官",
            "tools": [
                {"display_name": "Internal Search"},
                {"display_name": "Web Search"},
                {"display_name": "Open URL"},
                    {"display_name": "Code Interpreter"},
                    {"name": "send_security_alert"},
                    {"name": "create_security_ticket"},
                    {"name": "search_security_alerts"},
                    {"name": "isolate_endpoint_host"},
                ],
            },
        {
            "name": "漏洞评估专家",
            "tools": [
                {"display_name": "Internal Search"},
                {"display_name": "Web Search"},
                {"display_name": "Open URL"},
                    {"display_name": "Code Interpreter"},
                    {"name": "threat_intel_lookup"},
                    {"name": "create_security_ticket"},
                    {"name": "lookup_asset_context"},
                ],
            },
        {
            "name": "合规审计员",
            "tools": [
                {"display_name": "Internal Search"},
                    {"display_name": "Web Search"},
                    {"display_name": "Open URL"},
                    {"name": "create_security_ticket"},
                    {"name": "lookup_asset_context"},
                ],
            },
    ]

    db_state = {
        "persona_rows": {
            "安全事件分析师": {"id": 2, "is_public": False},
            "应急响应指挥官": {"id": 3, "is_public": False},
            "漏洞评估专家": {"id": 4, "is_public": False},
            "合规审计员": {"id": 5, "is_public": False},
        },
        "document_set_id": 1,
        "user_rows": {
            "analyst@security.local": "u-1",
            "commander@security.local": "u-2",
            "vuln_expert@security.local": "u-3",
            "auditor@security.local": "u-4",
        },
        "persona_user_links": {
            (2, "u-1"),
            (3, "u-2"),
            (4, "u-3"),
            (5, "u-4"),
        },
        "document_set_links": {
            (1, "u-1"),
            (1, "u-2"),
            (1, "u-3"),
            (1, "u-4"),
        },
    }

    result = module.evaluate_acceptance(
        document_sets=[{"id": 1, "name": "安全知识库"}],
        personas=personas,
        openapi_tools=[
            {
                "name": "create_security_ticket",
                "definition": {"servers": [{"url": "http://localhost:9999"}]},
                "custom_headers": [{"key": "Authorization", "value": "Bearer mock"}],
            },
            {
                "name": "send_security_alert",
                "definition": {"servers": [{"url": "http://localhost:9999"}]},
                "custom_headers": [],
            },
                {
                    "name": "threat_intel_lookup",
                    "definition": {"servers": [{"url": "http://localhost:9999"}]},
                    "custom_headers": [{"key": "x-apikey", "value": "mock"}],
                },
                {
                    "name": "search_security_alerts",
                    "definition": {"servers": [{"url": "http://localhost:9999"}]},
                    "custom_headers": [{"key": "Authorization", "value": "Bearer mock"}],
                },
                {
                    "name": "isolate_endpoint_host",
                    "definition": {"servers": [{"url": "http://localhost:9999"}]},
                    "custom_headers": [{"key": "Authorization", "value": "Bearer mock"}],
                },
                {
                    "name": "lookup_asset_context",
                    "definition": {"servers": [{"url": "http://localhost:9999"}]},
                    "custom_headers": [{"key": "Authorization", "value": "Bearer mock"}],
                },
            ],
        ingestion_docs=[{"semantic_id": "CVE-2024-1234_threat_intel"}],
        db_state=db_state,
        threat_intel_sync_summary={
            "source_profile": "mock",
            "last_sync_run_at": "2026-04-07T00:00:00Z",
            "due_status": "WAIT",
            "due_feeds": [],
        },
        threat_intel_curation_summary={
            "governed_feeds": 1902,
            "governed_source_counts": {
                "CISA Known Exploited Vulnerabilities Catalog": 1553,
                "NIST National Vulnerability Database (NVD)": 349,
            },
            "unmanaged_local_feeds": 1,
            "promotion_candidates": 0,
            "manual_review": 0,
            "keep_runtime_only": 1,
        },
        security_tool_profile_summary={
            "profile": "mock",
            "tools": {
                "create_security_ticket": {
                    "configured_server_url": "http://localhost:9999",
                    "configured_header_keys": ["Authorization"],
                    "expected_server_url": "http://localhost:9999",
                    "expected_header_keys": ["Authorization"],
                },
                "send_security_alert": {
                    "configured_server_url": "http://localhost:9999",
                    "configured_header_keys": [],
                    "expected_server_url": "http://localhost:9999",
                    "expected_header_keys": [],
                },
                    "threat_intel_lookup": {
                        "configured_server_url": "http://localhost:9999",
                        "configured_header_keys": ["x-apikey"],
                        "expected_server_url": "http://localhost:9999",
                        "expected_header_keys": ["x-apikey"],
                    },
                    "search_security_alerts": {
                        "configured_server_url": "http://localhost:9999",
                        "configured_header_keys": ["Authorization"],
                        "expected_server_url": "http://localhost:9999",
                        "expected_header_keys": ["Authorization"],
                    },
                    "isolate_endpoint_host": {
                        "configured_server_url": "http://localhost:9999",
                        "configured_header_keys": ["Authorization"],
                        "expected_server_url": "http://localhost:9999",
                        "expected_header_keys": ["Authorization"],
                    },
                    "lookup_asset_context": {
                        "configured_server_url": "http://localhost:9999",
                        "configured_header_keys": ["Authorization"],
                        "expected_server_url": "http://localhost:9999",
                        "expected_header_keys": ["Authorization"],
                    },
                },
            "mismatches": [],
        },
        deployment_profile_summary={
            "deployment_profile": "demo",
            "expected_threat_intel_source_profile": "mock",
            "expected_security_tools_profile": "mock",
            "required_env": ["SECURITY_TOOLS_MOCK_SERVER_URL", "SECURITY_TOOLS_MOCK_API_KEY"],
            "profile_env": {
                "SECURITY_TOOLS_MOCK_SERVER_URL": "http://host.docker.internal:9999",
                "SECURITY_TOOLS_MOCK_API_KEY": "mock-key",
            },
        },
        playbook_definitions_summary={
            "count": 2,
            "names": ["incident-triage-readonly", "incident-containment-and-ticketing"],
            "playbooks_with_examples": [
                "incident-triage-readonly",
                "incident-containment-and-ticketing",
            ],
            "invalid_files": [],
        },
    )

    assert result["ok"] is True
    assert result["failures"] == []
    assert result["health"]["overall_status"] == "healthy"
    assert result["recommended_next_actions"] == []
    assert result["summary"]["deployment_profile"] == "demo"
    assert result["summary"]["security_tools_profile"] == "mock"
    assert result["summary"]["security_tools_summary"]["threat_intel_lookup"]["configured_header_keys"] == [
        "x-apikey"
    ]
    assert result["summary"]["threat_intel_source_profile"] == "mock"
    assert result["summary"]["threat_intel_due_status"] == "WAIT"
    assert result["summary"]["threat_intel_governed_feeds"] == 1902
    assert result["summary"]["threat_intel_promotion_candidates"] == 0
    assert result["summary"]["playbook_count"] == 2


def test_evaluate_acceptance_reports_missing_tools_and_links() -> None:
    module = _load_module()
    module.load_security_tool_configs = lambda: [
        {
            "name": "create_security_ticket",
            "persona_bindings": ["安全事件分析师", "应急响应指挥官", "漏洞评估专家", "合规审计员"],
        },
        {
            "name": "send_security_alert",
            "persona_bindings": ["应急响应指挥官"],
        },
        {
            "name": "threat_intel_lookup",
            "persona_bindings": ["安全事件分析师", "漏洞评估专家"],
        },
    ]

    result = module.evaluate_acceptance(
        document_sets=[],
        personas=[
            {
                "name": "安全事件分析师",
                "tools": [{"display_name": "Internal Search"}],
            }
        ],
        openapi_tools=[{"name": "create_security_ticket"}],
        ingestion_docs=[],
        db_state={
            "persona_rows": {
                "安全事件分析师": {"id": 2, "is_public": True},
            },
            "document_set_id": None,
            "user_rows": {
                "analyst@security.local": "u-1",
            },
            "persona_user_links": set(),
            "document_set_links": set(),
        },
        threat_intel_sync_summary={
            "source_profile": "live",
            "last_sync_run_at": None,
            "due_status": "DUE",
            "due_feeds": ["cisa_kev"],
        },
        threat_intel_curation_summary={
            "governed_feeds": 1557,
            "governed_source_counts": {},
            "unmanaged_local_feeds": 346,
            "promotion_candidates": 345,
            "manual_review": 0,
            "keep_runtime_only": 1,
        },
        security_tool_profile_summary={
            "profile": "live",
            "tools": {},
            "mismatches": [
                "Tool threat_intel_lookup server_url mismatch: expected https://example.com, got http://localhost:9999"
            ],
        },
        deployment_profile_summary={
            "deployment_profile": "demo",
            "expected_threat_intel_source_profile": "mock",
            "expected_security_tools_profile": "mock",
            "required_env": ["SECURITY_TOOLS_MOCK_SERVER_URL"],
            "profile_env": {},
        },
        playbook_definitions_summary={
            "count": 1,
            "names": ["incident-triage-readonly"],
            "playbooks_with_examples": [],
            "invalid_files": [],
        },
    )

    assert result["ok"] is False
    assert result["health"]["overall_status"] == "failing"
    assert result["recommended_next_actions"]
    assert any("Missing document set" in failure for failure in result["failures"])
    assert any("Missing OpenAPI tools" in failure for failure in result["failures"])
    assert any("Missing threat-intel ingestion documents" in failure for failure in result["failures"])
    assert any("Missing personas" in failure for failure in result["failures"])
    assert any("missing tools" in failure for failure in result["failures"])
    assert any("Missing security users" in failure for failure in result["failures"])
    assert any("must be private" in failure for failure in result["failures"])
    assert any("server_url mismatch" in failure for failure in result["failures"])
    assert any("Threat-intel source profile mismatch" in failure for failure in result["failures"])
    assert any("Security tools profile mismatch" in failure for failure in result["failures"])
    assert any("Threat-intel promotion candidates remain: 345" in failure for failure in result["failures"])
    assert any("Playbooks missing example_inputs" in failure for failure in result["failures"])


def test_load_threat_intel_sync_summary_reports_due_feeds(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    plan_path = tmp_path / "sync_plan.yaml"
    state_path = tmp_path / "sync_state.json"
    plan_path.write_text(
        "feeds:\n  - name: cisa_kev\n    min_refresh_interval_hours: 24\n",
        encoding="utf-8",
    )
    state_path.write_text(
        '{\n  "feeds": {"cisa_kev": {"last_success_at": "2026-04-05T00:00:00Z"}},\n  "last_sync_run_at": "2026-04-05T00:00:00Z"\n}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "THREAT_INTEL_SYNC_PLAN_PATH", plan_path)
    monkeypatch.setattr(module, "THREAT_INTEL_SYNC_STATE_PATH", state_path)
    monkeypatch.setattr(module, "_utc_now", lambda: module._parse_iso_datetime("2026-04-07T00:00:00Z"))
    monkeypatch.setenv("THREAT_INTEL_SOURCE_PROFILE", "mock")

    result = module.load_threat_intel_sync_summary()

    assert result["source_profile"] == "mock"
    assert result["due_status"] == "DUE"
    assert result["due_feeds"] == ["cisa_kev"]


def test_load_threat_intel_sync_summary_derives_profile_from_deployment_profile(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    plan_path = tmp_path / "sync_plan.yaml"
    state_path = tmp_path / "sync_state.json"
    plan_path.write_text("feeds: []\n", encoding="utf-8")
    state_path.write_text("{\"feeds\": {}}\n", encoding="utf-8")
    monkeypatch.setattr(module, "THREAT_INTEL_SYNC_PLAN_PATH", plan_path)
    monkeypatch.setattr(module, "THREAT_INTEL_SYNC_STATE_PATH", state_path)
    monkeypatch.delenv("THREAT_INTEL_SOURCE_PROFILE", raising=False)

    result = module.load_threat_intel_sync_summary(
        {
            "profile_env": {
                "THREAT_INTEL_SOURCE_PROFILE": "mock",
            }
        }
    )

    assert result["source_profile"] == "mock"


def test_load_threat_intel_curation_summary_reads_manifest_and_report(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    manifest_path = tmp_path / "feed_manifest.json"
    manifest_path.write_text(
        (
            "{\n"
            '  "summary": {\n'
            '    "total_feeds": 1902,\n'
            '    "source_counts": {\n'
            '      "NIST National Vulnerability Database (NVD)": 349\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "THREAT_INTEL_MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(
        module,
        "build_unmanaged_report",
        lambda manifest_path: {
            "summary": {
                "unmanaged_total": 1,
                "promotion_candidate_total": 0,
                "manual_review_total": 0,
                "keep_runtime_only_total": 1,
            }
        },
    )
    monkeypatch.setattr(
        module,
        "build_lifecycle_report",
        lambda manifest_path: {
            "summary": {
                "active_total": 1500,
                "archive_candidate_total": 125,
                "retained_historical_total": 277,
                "quality_counts": {"authoritative": 1902},
            }
        },
    )

    summary = module.load_threat_intel_curation_summary()

    assert summary == {
        "governed_feeds": 1902,
        "governed_source_counts": {
            "NIST National Vulnerability Database (NVD)": 349,
        },
        "active_feeds": 1500,
        "archive_candidates": 125,
        "retained_historical": 277,
        "unmanaged_local_feeds": 1,
        "promotion_candidates": 0,
        "manual_review": 0,
        "keep_runtime_only": 1,
        "quality_counts": {"authoritative": 1902},
    }


def test_load_security_tool_profile_summary_uses_mock_profile(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    integrations_dir = tmp_path / "5-integrations"
    integrations_dir.mkdir()

    (integrations_dir / "profiles.yaml").write_text(
        (
            "profiles:\n"
            "  live:\n"
            "    env_overrides: {}\n"
            "  mock:\n"
            "    env_overrides:\n"
            "      SECURITY_TICKET_API_URL: SECURITY_TOOLS_MOCK_SERVER_URL\n"
            "      SECURITY_TICKET_API_KEY: SECURITY_TOOLS_MOCK_API_KEY\n"
        ),
        encoding="utf-8",
    )
    (integrations_dir / "security-ticket.yaml").write_text(
        (
            "name: create_security_ticket\n"
            "template: security_ticket_api\n"
            "description: test\n"
            "persona_bindings:\n"
            "  - 安全事件分析师\n"
            "api_url_env: SECURITY_TICKET_API_URL\n"
            "api_key_env: SECURITY_TICKET_API_KEY\n"
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(module, "SECURITY_TOOL_INTEGRATIONS_DIR", integrations_dir)
    monkeypatch.setattr(
        module, "SECURITY_TOOL_PROFILES_PATH", integrations_dir / "profiles.yaml"
    )
    monkeypatch.setenv("SECURITY_TOOLS_PROFILE", "mock")
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_SERVER_URL", "http://localhost:9999")
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_API_KEY", "mock-key")

    summary = module.load_security_tool_profile_summary(
        [
            {
                "name": "create_security_ticket",
                "definition": {"servers": [{"url": "http://localhost:9999"}]},
                "custom_headers": [{"key": "Authorization", "value": "Bearer mock-key"}],
            }
        ]
    )

    assert summary["profile"] == "mock"
    assert summary["mismatches"] == []
    assert summary["tools"]["create_security_ticket"]["configured_server_url"] == "http://localhost:9999"
    assert summary["tools"]["create_security_ticket"]["expected_header_keys"] == [
        "Authorization"
    ]


def test_load_playbook_definitions_summary_reads_yaml_files(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    playbooks_dir = tmp_path / "playbooks"
    playbooks_dir.mkdir()
    (playbooks_dir / "triage.yaml").write_text(
        (
            "name: incident-triage-readonly\n"
            "example_inputs:\n"
            "  incident_ip: 8.8.8.8\n"
            "steps:\n"
            "  - id: s1\n"
            "    persona: 安全事件分析师\n"
            "    prompt: test\n"
        ),
        encoding="utf-8",
    )
    (playbooks_dir / "invalid.yaml").write_text("- not-a-mapping\n", encoding="utf-8")
    monkeypatch.setattr(module, "PLAYBOOKS_DIR", playbooks_dir)

    summary = module.load_playbook_definitions_summary()

    assert summary["count"] == 1
    assert summary["names"] == ["incident-triage-readonly"]
    assert summary["playbooks_with_examples"] == ["incident-triage-readonly"]
    assert summary["invalid_files"] == ["invalid.yaml"]


def test_validate_deployment_profile_runtime_rejects_localhost_for_demo(
    monkeypatch,
) -> None:
    module = _load_module()
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_SERVER_URL", "http://localhost:9999")

    issues = module.validate_deployment_profile_runtime(
        {
            "deployment_profile": "demo",
            "profile_env": {},
        }
    )

    assert issues == [
        "Deployment profile demo requires SECURITY_TOOLS_MOCK_SERVER_URL to be reachable from Docker containers; use host.docker.internal instead of http://localhost:9999"
    ]


def test_load_security_tool_profile_summary_derives_profile_from_deployment_profile(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    integrations_dir = tmp_path / "5-integrations"
    integrations_dir.mkdir()

    (integrations_dir / "profiles.yaml").write_text(
        (
            "profiles:\n"
            "  live:\n"
            "    env_overrides: {}\n"
            "  mock:\n"
            "    env_overrides:\n"
            "      SECURITY_TICKET_API_URL: SECURITY_TOOLS_MOCK_SERVER_URL\n"
            "      SECURITY_TICKET_API_KEY: SECURITY_TOOLS_MOCK_API_KEY\n"
        ),
        encoding="utf-8",
    )
    (integrations_dir / "security-ticket.yaml").write_text(
        (
            "name: create_security_ticket\n"
            "template: security_ticket_api\n"
            "description: test\n"
            "persona_bindings:\n"
            "  - 安全事件分析师\n"
            "api_url_env: SECURITY_TICKET_API_URL\n"
            "api_key_env: SECURITY_TICKET_API_KEY\n"
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(module, "SECURITY_TOOL_INTEGRATIONS_DIR", integrations_dir)
    monkeypatch.setattr(
        module, "SECURITY_TOOL_PROFILES_PATH", integrations_dir / "profiles.yaml"
    )
    monkeypatch.delenv("SECURITY_TOOLS_PROFILE", raising=False)
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_SERVER_URL", "http://localhost:9999")
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_API_KEY", "mock-key")

    summary = module.load_security_tool_profile_summary(
        [
            {
                "name": "create_security_ticket",
                "definition": {"servers": [{"url": "http://localhost:9999"}]},
                "custom_headers": [{"key": "Authorization", "value": "Bearer mock-key"}],
            }
        ],
        {"profile_env": {"SECURITY_TOOLS_PROFILE": "mock"}},
    )

    assert summary["profile"] == "mock"


def test_build_persona_tool_requirements_includes_new_integrations() -> None:
    module = _load_module()

    requirements = module.build_persona_tool_requirements(
        [
            {
                "name": "search_security_alerts",
                "persona_bindings": ["安全事件分析师", "应急响应指挥官"],
            },
            {
                "name": "lookup_asset_context",
                "persona_bindings": ["安全事件分析师", "漏洞评估专家", "合规审计员"],
            },
        ]
    )

    assert requirements["安全事件分析师"]["custom_tools"] == {
        "search_security_alerts",
        "lookup_asset_context",
    }
    assert requirements["应急响应指挥官"]["custom_tools"] == {"search_security_alerts"}
    assert requirements["合规审计员"]["custom_tools"] == {"lookup_asset_context"}


def test_load_deployment_profile_summary_reads_expectations(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    deployment_profiles_path = tmp_path / "deployment-profiles.yaml"
    deployment_profiles_path.write_text(
        (
            "profiles:\n"
            "  demo:\n"
            "    required_env:\n"
            "      - SECURITY_TOOLS_MOCK_SERVER_URL\n"
            "    expectations:\n"
            "      threat_intel_source_profile: mock\n"
            "      security_tools_profile: mock\n"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "DEPLOYMENT_PROFILES_PATH", deployment_profiles_path)
    monkeypatch.setenv("SECURITY_PLATFORM_DEPLOYMENT_PROFILE", "demo")

    summary = module.load_deployment_profile_summary()

    assert summary == {
        "deployment_profile": "demo",
        "expected_threat_intel_source_profile": "mock",
        "expected_security_tools_profile": "mock",
        "required_env": ["SECURITY_TOOLS_MOCK_SERVER_URL"],
        "profile_env": {},
    }
