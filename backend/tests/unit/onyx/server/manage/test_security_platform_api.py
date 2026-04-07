from types import SimpleNamespace

from onyx.server.manage.security_platform.api import SecurityPlatformDocumentSetStatus
from onyx.server.manage.security_platform.api import SecurityPlatformPersonaStatus
from onyx.server.manage.security_platform.api import SecurityPlatformUserStatus
from onyx.server.manage.security_platform.api import build_remediation_commands
from onyx.server.manage.security_platform.api import build_recommended_next_actions
from onyx.server.manage.security_platform.api import build_tool_status
from onyx.server.manage.security_platform.api import build_health_status
from onyx.server.manage.security_platform.api import get_deployment_profile_issues


def test_get_deployment_profile_issues_rejects_localhost_for_demo(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_SERVER_URL", "http://localhost:9999")

    issues = get_deployment_profile_issues("demo")

    assert issues == [
        "SECURITY_TOOLS_MOCK_SERVER_URL must use host.docker.internal in Docker-backed demo deployments"
    ]


def test_get_deployment_profile_issues_allows_host_docker_internal(monkeypatch) -> None:
    monkeypatch.setenv(
        "SECURITY_TOOLS_MOCK_SERVER_URL", "http://host.docker.internal:9999"
    )

    issues = get_deployment_profile_issues("demo")

    assert issues == []


def test_build_tool_status_extracts_server_headers_and_personas() -> None:
    tool = SimpleNamespace(
        id=15,
        name="create_security_ticket",
        enabled=True,
        openapi_schema={"servers": [{"url": "http://host.docker.internal:9999"}]},
        custom_headers=[
            {"key": "Authorization", "value": "Bearer mock"},
            {"key": "x-extra", "value": "1"},
        ],
        personas=[
            SimpleNamespace(name="安全事件分析师"),
            SimpleNamespace(name="Random Persona"),
            SimpleNamespace(name="应急响应指挥官"),
        ],
    )

    status = build_tool_status(tool)

    assert status.id == 15
    assert status.name == "create_security_ticket"
    assert status.server_url == "http://host.docker.internal:9999"
    assert status.header_keys == ["Authorization", "x-extra"]
    assert status.persona_names == ["安全事件分析师", "应急响应指挥官"]


def test_build_health_status_reports_failing_checks() -> None:
    health = build_health_status(
        profile_name="demo",
        expected_threat_profile="mock",
        expected_tools_profile="mock",
        threat_intel_source_profile="live",
        security_tools_profile="mock",
        required_env=["SECURITY_TOOLS_MOCK_SERVER_URL", "SECURITY_TOOLS_MOCK_API_KEY"],
        missing_required_env=["SECURITY_TOOLS_MOCK_API_KEY"],
        deployment_profile_issues=[],
        document_set_status=SecurityPlatformDocumentSetStatus(
            id=None,
            name="安全知识库",
            exists=False,
            is_public=None,
            shared_user_count=0,
        ),
        personas=[
            SecurityPlatformPersonaStatus(
                id=2,
                name="安全事件分析师",
                is_public=True,
                tool_count=2,
                document_set_count=0,
                shared_user_count=0,
            )
        ],
        tools=[
            SimpleNamespace(
                id=15,
                name="create_security_ticket",
                enabled=True,
                server_url=None,
                header_keys=["Authorization"],
                persona_names=["安全事件分析师"],
            )
        ],
        security_users=[
            SecurityPlatformUserStatus(
                email="analyst@security.local",
                role="UserRole.BASIC",
                is_active=True,
            )
        ],
        persona_user_links=0,
        document_set_user_links=0,
        snapshot={
            "threat_intel_sync": {
                "source_profile": "live",
                "due_status": "DUE",
                "last_sync_run_at": None,
                "due_feeds": ["cisa_kev"],
            },
            "threat_intel_corpus": {
                "governed": 1902,
                "unmanaged": 1,
                "promotion_candidates": 3,
                "manual_review": 1,
                "keep_runtime_only": 1,
            },
            "playbooks": {"count": 1, "with_examples": 0, "items": []},
        },
    )

    assert health["overall_status"] == "failing"
    assert health["failing_checks"] >= 5
    deployment_check = next(check for check in health["checks"] if check["name"] == "deployment_profile")
    assert "SECURITY_TOOLS_MOCK_API_KEY" in deployment_check["issues"][0]
    threat_check = next(check for check in health["checks"] if check["name"] == "threat_intel")
    assert any("promotion candidates remain: 3" in issue for issue in threat_check["issues"])


def test_build_health_status_reports_warning_for_due_threat_intel_only() -> None:
    health = build_health_status(
        profile_name="demo",
        expected_threat_profile="mock",
        expected_tools_profile="mock",
        threat_intel_source_profile="mock",
        security_tools_profile="mock",
        required_env=[],
        missing_required_env=[],
        deployment_profile_issues=[],
        document_set_status=SecurityPlatformDocumentSetStatus(
            id=1,
            name="安全知识库",
            exists=True,
            is_public=True,
            shared_user_count=4,
        ),
        personas=[
            SecurityPlatformPersonaStatus(
                id=2,
                name=name,
                is_public=False,
                tool_count=2,
                document_set_count=1,
                shared_user_count=1,
            )
            for name in [
                "安全事件分析师",
                "应急响应指挥官",
                "漏洞评估专家",
                "合规审计员",
            ]
        ],
        tools=[
            SimpleNamespace(
                id=index,
                name=name,
                enabled=True,
                server_url="http://host.docker.internal:9999",
                header_keys=[],
                persona_names=["安全事件分析师"],
            )
            for index, name in enumerate(
                [
                    "create_security_ticket",
                    "send_security_alert",
                    "threat_intel_lookup",
                    "search_security_alerts",
                    "isolate_endpoint_host",
                    "lookup_asset_context",
                ],
                start=14,
            )
        ],
        security_users=[
            SecurityPlatformUserStatus(
                email=email,
                role="UserRole.BASIC",
                is_active=True,
            )
            for email in [
                "analyst@security.local",
                "auditor@security.local",
                "commander@security.local",
                "vuln_expert@security.local",
            ]
        ],
        persona_user_links=4,
        document_set_user_links=4,
        snapshot={
            "threat_intel_sync": {
                "source_profile": "mock",
                "due_status": "DUE",
                "last_sync_run_at": "2026-04-07T00:00:00Z",
                "due_feeds": ["cisa_kev"],
            },
            "threat_intel_corpus": {
                "governed": 1902,
                "unmanaged": 1,
                "promotion_candidates": 0,
                "manual_review": 0,
                "keep_runtime_only": 1,
            },
            "playbooks": {"count": 2, "with_examples": 2, "items": []},
            "historical_packages": {
                "package_count": 2,
                "total_item_count": 203,
                "total_size_bytes": 242152,
                "package_ids": [
                    "phase-1-cisa-limited-historical",
                    "phase-2-nvd-authoritative-historical",
                ],
            },
        },
    )

    assert health["overall_status"] == "warning"
    assert health["failing_checks"] == 0
    assert health["warning_checks"] == 1


def test_build_health_status_reports_historical_package_catalog_drift() -> None:
    health = build_health_status(
        profile_name="demo",
        expected_threat_profile="mock",
        expected_tools_profile="mock",
        threat_intel_source_profile="mock",
        security_tools_profile="mock",
        required_env=[],
        missing_required_env=[],
        deployment_profile_issues=[],
        document_set_status=SecurityPlatformDocumentSetStatus(
            id=1,
            name="安全知识库",
            exists=True,
            is_public=False,
            shared_user_count=4,
        ),
        personas=[],
        tools=[],
        security_users=[],
        persona_user_links=4,
        document_set_user_links=4,
        snapshot={
            "threat_intel_sync": {
                "source_profile": "mock",
                "due_status": "WAIT",
                "last_sync_run_at": "2026-04-07T00:00:00Z",
                "due_feeds": [],
            },
            "threat_intel_corpus": {
                "governed": 1902,
                "unmanaged": 1,
                "promotion_candidates": 0,
                "manual_review": 0,
                "keep_runtime_only": 1,
            },
            "historical_packages": {
                "package_count": 2,
                "total_item_count": 0,
                "total_size_bytes": 123,
                "package_ids": ["phase-1-cisa-limited-historical"],
            },
            "playbooks": {"count": 2, "with_examples": 2, "items": []},
        },
    )

    historical_check = next(
        check for check in health["checks"] if check["name"] == "historical_packages"
    )
    assert historical_check["status"] == "failing"
    assert any("catalog summary does not match package id count" in issue for issue in historical_check["issues"])
    assert any("zero archived items" in issue for issue in historical_check["issues"])


def test_build_recommended_next_actions_prefers_non_healthy_checks() -> None:
    actions = build_recommended_next_actions(
        {
            "checks": [
                {
                    "name": "deployment_profile",
                    "status": "failing",
                    "remediations": [
                        "Fill the missing required env vars for the selected deployment profile.",
                    ],
                },
                {
                    "name": "threat_intel",
                    "status": "warning",
                    "remediations": [
                        "Run setup_security_threat_intel.py --verify or the scheduled sync wrapper to refresh threat-intel state."
                    ],
                },
                {
                    "name": "tools",
                    "status": "healthy",
                    "remediations": ["should not appear"],
                },
            ]
        }
    )

    assert actions == [
        "Fill the missing required env vars for the selected deployment profile.",
        "Run setup_security_threat_intel.py --verify or the scheduled sync wrapper to refresh threat-intel state.",
    ]


def test_build_remediation_commands_maps_checks_to_copy_ready_commands() -> None:
    commands = build_remediation_commands(
        profile_name="demo",
        health={
            "checks": [
                {"name": "deployment_profile", "status": "failing"},
                {"name": "tools", "status": "failing"},
                {"name": "threat_intel", "status": "warning"},
                {"name": "playbooks", "status": "healthy"},
            ]
        },
    )

    assert commands == [
        "SECURITY_PLATFORM_DEPLOYMENT_PROFILE=demo python knowledge-base/bootstrap_security_platform.py --verify",
        "python knowledge-base/security-automation/setup_security_tools.py --apply --profile mock",
        "python knowledge-base/setup_security_threat_intel.py --verify",
    ]


def test_build_remediation_commands_includes_historical_package_rebuild() -> None:
    commands = build_remediation_commands(
        profile_name="demo",
        health={
            "checks": [
                {"name": "historical_packages", "status": "failing"},
            ]
        },
    )

    assert commands == [
        "python knowledge-base/build_threat_intel_historical_package_index.py --write-index"
    ]
