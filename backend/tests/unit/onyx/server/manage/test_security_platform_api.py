from datetime import datetime
from datetime import timezone
from types import SimpleNamespace

from onyx.server.manage.security_platform.api import SecurityPlatformDocumentSetStatus
from onyx.server.manage.security_platform.api import SecurityPlatformPersonaStatus
from onyx.server.manage.security_platform.api import SecurityPlatformUserStatus
from onyx.server.manage.security_platform.api import build_failure_summary
from onyx.server.manage.security_platform.api import build_threat_intel_sync_health_summary
from onyx.server.manage.security_platform.api import build_custom_permission_summary
from onyx.server.manage.security_platform.api import build_custom_theming_snapshot
from onyx.server.manage.security_platform.api import build_hook_summary
from onyx.server.manage.security_platform.api import load_custom_deployment_summary
from onyx.server.manage.security_platform.api import load_region_processing_summary
from onyx.server.manage.security_platform.api import load_self_hosting_summary
from onyx.server.manage.security_platform.api import load_white_labeling_summary
from onyx.server.manage.security_platform.api import build_permission_inheritance_summary
from onyx.server.manage.security_platform.api import build_persona_usage_summary
from onyx.server.manage.security_platform.api import build_query_history_usage_summary
from onyx.server.manage.security_platform.api import build_rbac_summary
from onyx.server.manage.security_platform.api import build_scim_summary
from onyx.server.manage.security_platform.api import build_secrets_encryption_summary
from onyx.server.manage.security_platform.api import build_service_account_summary
from onyx.server.manage.security_platform.api import build_tool_audit_summary
from onyx.server.manage.security_platform.api import build_tool_drift_summary
from onyx.server.manage.security_platform.api import build_usage_limit_summary
from onyx.server.manage.security_platform.api import build_remediation_commands
from onyx.server.manage.security_platform.api import build_recommended_next_actions
from onyx.server.manage.security_platform.api import build_security_task_route
from onyx.server.manage.security_platform.api import build_tool_status
from onyx.server.manage.security_platform.api import build_health_status
from onyx.server.manage.security_platform.api import get_deployment_profile_issues
from onyx.server.manage.security_platform.api import get_placeholder_required_env
from onyx.server.manage.security_platform.api import LICENSE_ENFORCEMENT_ENABLED


def test_get_deployment_profile_issues_rejects_localhost_for_demo(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_SERVER_URL", "http://localhost:9999")

    issues = get_deployment_profile_issues("demo")

    assert issues == [
        "SECURITY_TOOLS_MOCK_SERVER_URL must use host.docker.internal in Docker-backed demo deployments"
    ]


def test_build_security_task_route_detects_vulnerability_assessment() -> None:
    route = build_security_task_route("CVE-2025-1234 影响我们哪些版本，需要补丁优先级")

    assert route.task_type == "vulnerability_assessment"
    assert route.persona_name == "漏洞评估专家"
    assert route.skill_keys == [
        "researching-vulnerabilities",
        "sca-analyzer",
        "asset-discovery",
    ]
    assert route.confidence > 0.5


def test_build_security_task_route_detects_containment_playbook() -> None:
    route = build_security_task_route("EDR 告警确认后需要隔离主机并创建工单")

    assert route.task_type == "incident_containment"
    assert route.persona_name == "应急响应指挥官"
    assert route.playbook_name == "incident-containment-and-ticketing"


def test_build_security_task_route_defaults_to_readonly_triage() -> None:
    route = build_security_task_route("帮我看看这个情况")

    assert route.task_type == "incident_triage"
    assert route.persona_name == "安全事件分析师"
    assert route.playbook_name == "incident-triage-readonly"


def test_get_deployment_profile_issues_allows_host_docker_internal(monkeypatch) -> None:
    monkeypatch.setenv(
        "SECURITY_TOOLS_MOCK_SERVER_URL", "http://host.docker.internal:9999"
    )

    issues = get_deployment_profile_issues("demo")

    assert issues == []


def test_get_deployment_profile_issues_rejects_localhost_for_gateway(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_TOOLS_GATEWAY_URL", "http://localhost:9999")

    issues = get_deployment_profile_issues("gateway")

    assert issues == [
        "SECURITY_TOOLS_GATEWAY_URL must use host.docker.internal in Docker-backed gateway deployments"
    ]


def test_get_placeholder_required_env_detects_example_values(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_TICKET_API_URL", "https://your-company.atlassian.net/rest/api/3")
    monkeypatch.setenv("SECURITY_TICKET_API_KEY", "replace-me")
    monkeypatch.setenv("SECURITY_EDR_API_URL", "https://edr.prod.local/api/v1")

    placeholders = get_placeholder_required_env(
        [
            "SECURITY_TICKET_API_URL",
            "SECURITY_TICKET_API_KEY",
            "SECURITY_EDR_API_URL",
        ]
    )

    assert placeholders == ["SECURITY_TICKET_API_URL", "SECURITY_TICKET_API_KEY"]


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


def test_build_tool_audit_summary_formats_recent_calls_and_counts() -> None:
    summary = build_tool_audit_summary(
        total_calls=7,
        tool_counts={
            "create_security_ticket": 2,
            "search_security_alerts": 5,
        },
        persona_counts={
            "安全事件分析师": 6,
            "应急响应指挥官": 1,
        },
        recent_rows=[
            SimpleNamespace(
                tool_name="search_security_alerts",
                persona_name="安全事件分析师",
                user_email="analyst@security.local",
                time_sent=datetime(2026, 4, 7, 8, 0, tzinfo=timezone.utc),
                turn_number=2,
                parent_tool_call_id=None,
            ),
            SimpleNamespace(
                tool_name="create_security_ticket",
                persona_name="应急响应指挥官",
                user_email="commander@security.local",
                time_sent=None,
                turn_number=3,
                parent_tool_call_id=41,
            ),
        ],
    )

    assert summary.total_calls == 7
    assert summary.recent_call_count == 2
    assert summary.tool_counts == {
        "create_security_ticket": 2,
        "search_security_alerts": 5,
    }
    assert summary.persona_counts == {
        "安全事件分析师": 6,
        "应急响应指挥官": 1,
    }
    assert summary.recent_calls[0].time_sent == "2026-04-07T08:00:00+00:00"
    assert summary.recent_calls[0].is_nested is False
    assert summary.recent_calls[1].is_nested is True


def test_build_tool_drift_summary_reports_server_header_and_persona_drift() -> None:
    summary = build_tool_drift_summary(
        declared_configs={
            "search_security_alerts": {
                "persona_names": ["安全事件分析师"],
                "expected_server_url": "http://host.docker.internal:9999",
                "expected_header_keys": ["Authorization"],
            }
        },
        tools=[
            SimpleNamespace(
                id=19,
                name="search_security_alerts",
                enabled=True,
                server_url="http://localhost:9999",
                header_keys=[],
                persona_names=["应急响应指挥官"],
            )
        ],
    )

    assert summary.mismatch_count == 1
    assert summary.missing_declared_configs == []
    assert summary.mismatched_tools[0].tool_name == "search_security_alerts"
    assert any("server_url drift" in issue for issue in summary.mismatched_tools[0].issues)
    assert any("header drift" in issue for issue in summary.mismatched_tools[0].issues)
    assert any(
        "persona binding drift" in issue for issue in summary.mismatched_tools[0].issues
    )


def test_build_tool_drift_summary_tracks_missing_declared_configs() -> None:
    summary = build_tool_drift_summary(
        declared_configs={},
        tools=[
            SimpleNamespace(
                id=15,
                name="create_security_ticket",
                enabled=True,
                server_url="http://host.docker.internal:9999",
                header_keys=["Authorization"],
                persona_names=["安全事件分析师"],
            )
        ],
    )

    assert summary.mismatch_count == 0
    assert summary.missing_declared_configs == ["create_security_ticket"]


def test_build_failure_summary_formats_recent_failures() -> None:
    summary = build_failure_summary(
        total_failures=4,
        recent_rows=[
            SimpleNamespace(
                persona_name="安全事件分析师",
                user_email="analyst@security.local",
                time_sent=datetime(2026, 4, 7, 9, 30, tzinfo=timezone.utc),
                stage="tool_followup",
                tool_name="create_security_ticket",
                error="Tool call timed out",
            ),
            SimpleNamespace(
                persona_name=None,
                user_email=None,
                time_sent=None,
                stage="assistant_generation",
                tool_name=None,
                error="Upstream gateway error",
            ),
        ],
        stage_count_rows=[
            SimpleNamespace(stage="assistant_generation", failure_count=2),
            SimpleNamespace(stage="tool_followup", failure_count=2),
        ],
        persona_count_rows=[
            SimpleNamespace(persona_name="安全事件分析师", failure_count=1),
        ],
        tool_count_rows=[
            SimpleNamespace(tool_name="create_security_ticket", failure_count=1),
        ],
        daily_count_rows=[
            SimpleNamespace(day="2026-04-06", failure_count=1),
            SimpleNamespace(day="2026-04-07", failure_count=2),
        ],
    )

    assert summary.total_failures == 4
    assert summary.recent_failure_count == 2
    assert summary.stage_counts[0].label == "assistant_generation"
    assert summary.recent_failures[0].time_sent == "2026-04-07T09:30:00+00:00"
    assert summary.recent_failures[0].stage == "tool_followup"
    assert summary.recent_failures[0].tool_name == "create_security_ticket"
    assert summary.recent_failures[0].error == "Tool call timed out"
    assert summary.recent_failures[1].persona_name is None
    assert len(summary.daily_counts) == 7
    assert any("tool configuration" in hint.lower() for hint in summary.remediation_hints)
    assert any("timeout" in hint.lower() for hint in summary.remediation_hints)
    assert any("gateway" in hint.lower() for hint in summary.remediation_hints)


def test_build_permission_inheritance_summary_formats_recent_attempts() -> None:
    summary = build_permission_inheritance_summary(
        sync_cc_pair_count=3,
        docs_with_external_acl_count=12,
        docs_with_user_acl_count=8,
        docs_with_group_acl_count=5,
        recent_doc_sync_failure_count=2,
        recent_group_sync_failure_count=1,
        recent_doc_sync_rows=[
            SimpleNamespace(
                id=11,
                connector_credential_pair_id=41,
                status="SUCCESS",
                error_message=None,
                time_created=datetime(2026, 4, 7, 10, 0, tzinfo=timezone.utc),
                time_finished=datetime(2026, 4, 7, 10, 1, tzinfo=timezone.utc),
            )
        ],
        recent_group_sync_rows=[
            SimpleNamespace(
                id=12,
                connector_credential_pair_id=42,
                status="FAILED",
                error_message="group sync failed",
                time_created=datetime(2026, 4, 7, 10, 2, tzinfo=timezone.utc),
                time_finished=None,
            )
        ],
    )

    assert summary.sync_cc_pair_count == 3
    assert summary.docs_with_external_acl_count == 12
    assert summary.docs_with_user_acl_count == 8
    assert summary.docs_with_group_acl_count == 5
    assert summary.recent_doc_sync_failure_count == 2
    assert summary.recent_group_sync_failure_count == 1
    assert summary.recent_doc_sync_attempts[0].sync_type == "document"
    assert summary.recent_doc_sync_attempts[0].time_created == "2026-04-07T10:00:00+00:00"
    assert summary.recent_group_sync_attempts[0].sync_type == "group"
    assert summary.recent_group_sync_attempts[0].error_message == "group sync failed"


def test_build_rbac_summary_sorts_role_and_permission_counts() -> None:
    summary = build_rbac_summary(
        persona_user_links=4,
        document_set_user_links=4,
        all_user_role_counts={"basic": 4, "admin": 1},
        security_user_role_counts={"basic": 3, "admin": 1},
        user_group_count=3,
        groups_with_permission_grants_count=2,
        permission_grant_count=5,
        users_with_effective_permissions_count=3,
        curator_membership_count=1,
        top_permissions={"manage:connectors": 2, "admin": 1},
    )

    assert summary.persona_user_links == 4
    assert summary.document_set_user_links == 4
    assert list(summary.all_user_role_counts.keys()) == ["admin", "basic"]
    assert summary.security_user_role_counts == {"admin": 1, "basic": 3}
    assert summary.user_group_count == 3
    assert summary.groups_with_permission_grants_count == 2
    assert summary.permission_grant_count == 5
    assert summary.users_with_effective_permissions_count == 3
    assert summary.curator_membership_count == 1
    assert summary.top_permissions == {"admin": 1, "manage:connectors": 2}


def test_build_service_account_summary_formats_recent_accounts() -> None:
    summary = build_service_account_summary(
        api_key_count=3,
        service_account_user_count=3,
        ownerless_api_key_count=1,
        role_counts={"basic": 2, "admin": 1},
        recent_rows=[
            SimpleNamespace(
                api_key_id=9,
                api_key_name="automation-bot",
                api_key_display="dnsa_abcd********wxyz",
                service_role="UserRole.BASIC",
                owner_email="admin@example.com",
                created_at=datetime(2026, 4, 7, 11, 0, tzinfo=timezone.utc),
            )
        ],
    )

    assert summary.api_key_count == 3
    assert summary.service_account_user_count == 3
    assert summary.ownerless_api_key_count == 1
    assert summary.role_counts == {"admin": 1, "basic": 2}
    assert summary.recent_accounts[0].role == "basic"
    assert summary.recent_accounts[0].created_at == "2026-04-07T11:00:00+00:00"


def test_build_scim_summary_formats_token_state() -> None:
    summary = build_scim_summary(
        active_token_count=1,
        token_last_used_at=datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc),
        user_mapping_count=4,
        group_mapping_count=2,
        recent_group_sync_failure_count=1,
    )

    assert summary.has_active_token is True
    assert summary.token_last_used_at == "2026-04-07T12:00:00+00:00"
    assert summary.user_mapping_count == 4
    assert summary.group_mapping_count == 2
    assert summary.recent_group_sync_failure_count == 1


def test_build_query_history_usage_summary_formats_export_state() -> None:
    summary = build_query_history_usage_summary(
        query_history_type="normal",
        recent_query_count=42,
        recent_chat_session_count=18,
        recent_active_user_count=7,
        recent_like_count=5,
        recent_dislike_count=2,
        recent_export_count=3,
        recent_export_failure_count=1,
        recent_export_rows=[
            SimpleNamespace(
                task_id="task-1",
                status="SUCCESS",
                start_time=datetime(2026, 4, 7, 13, 0, tzinfo=timezone.utc),
            )
        ],
    )

    assert summary.query_history_type == "normal"
    assert summary.query_history_enabled is True
    assert summary.recent_query_count == 42
    assert summary.recent_chat_session_count == 18
    assert summary.recent_active_user_count == 7
    assert summary.recent_like_count == 5
    assert summary.recent_dislike_count == 2
    assert summary.recent_export_count == 3
    assert summary.recent_export_failure_count == 1
    assert summary.recent_exports[0].start_time == "2026-04-07T13:00:00+00:00"


def test_build_persona_usage_summary_formats_entries() -> None:
    summary = build_persona_usage_summary(
        recent_active_persona_count=2,
        recent_session_count=5,
        recent_message_count=12,
        recent_tool_call_count=4,
        persona_rows=[
            SimpleNamespace(
                persona_id=6,
                persona_name="威胁狩猎工程师",
                recent_session_count=3,
                recent_message_count=8,
                recent_tool_call_count=3,
                last_activity_at=datetime(2026, 4, 8, 9, 30, tzinfo=timezone.utc),
            ),
            SimpleNamespace(
                persona_id=7,
                persona_name="恶意软件分析师",
                recent_session_count=2,
                recent_message_count=4,
                recent_tool_call_count=1,
                last_activity_at=None,
            ),
        ],
    )

    assert summary.recent_active_persona_count == 2
    assert summary.recent_session_count == 5
    assert summary.recent_message_count == 12
    assert summary.recent_tool_call_count == 4
    assert len(summary.persona_entries) == 2
    assert summary.persona_entries[0].persona_name == "威胁狩猎工程师"
    assert summary.persona_entries[0].last_activity_at == "2026-04-08T09:30:00+00:00"
    assert summary.persona_entries[1].last_activity_at is None


def test_build_failure_summary_formats_recent_rows_and_aggregates() -> None:
    summary = build_failure_summary(
        total_failures=5,
        recent_rows=[
            SimpleNamespace(
                persona_name="威胁狩猎工程师",
                user_email="hunter@security.local",
                time_sent=datetime(2026, 4, 9, 10, 0, tzinfo=timezone.utc),
                stage="tool_followup",
                tool_name="search_security_alerts",
                error="tool follow-up failed",
            ),
            SimpleNamespace(
                persona_name="检测工程师",
                user_email="detection@security.local",
                time_sent=datetime(2026, 4, 9, 11, 0, tzinfo=timezone.utc),
                stage="assistant_generation",
                tool_name=None,
                error="assistant failed",
            ),
        ],
        stage_count_rows=[
            SimpleNamespace(stage="assistant_generation", failure_count=3),
            SimpleNamespace(stage="tool_followup", failure_count=2),
        ],
        persona_count_rows=[
            SimpleNamespace(persona_name="威胁狩猎工程师", failure_count=2),
            SimpleNamespace(persona_name="检测工程师", failure_count=1),
        ],
        tool_count_rows=[
            SimpleNamespace(tool_name="search_security_alerts", failure_count=2),
        ],
        daily_count_rows=[
            SimpleNamespace(day="2026-04-08", failure_count=1),
            SimpleNamespace(day="2026-04-09", failure_count=2),
        ],
    )

    assert summary.total_failures == 5
    assert summary.recent_failure_count == 2
    assert summary.stage_counts[0].label == "assistant_generation"
    assert summary.stage_counts[0].count == 3
    assert summary.persona_counts[0].label == "威胁狩猎工程师"
    assert summary.tool_counts[0].label == "search_security_alerts"
    assert summary.recent_failures[0].stage == "tool_followup"
    assert summary.recent_failures[0].tool_name == "search_security_alerts"
    assert summary.recent_failures[1].stage == "assistant_generation"
    assert summary.recent_failures[1].tool_name is None
    assert len(summary.daily_counts) == 7


def test_build_failure_summary_fills_missing_days_in_trend(monkeypatch) -> None:
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 4, 9, 12, 0, tzinfo=timezone.utc if tz else None)

    monkeypatch.setattr("onyx.server.manage.security_platform.api.datetime", FixedDateTime)

    summary = build_failure_summary(
        total_failures=2,
        recent_rows=[],
        stage_count_rows=[],
        persona_count_rows=[],
        tool_count_rows=[],
        daily_count_rows=[
            SimpleNamespace(day="2026-04-08", failure_count=1),
            SimpleNamespace(day="2026-04-09", failure_count=1),
        ],
    )

    assert [item.day for item in summary.daily_counts] == [
        "2026-04-03",
        "2026-04-04",
        "2026-04-05",
        "2026-04-06",
        "2026-04-07",
        "2026-04-08",
        "2026-04-09",
    ]
    assert [item.count for item in summary.daily_counts] == [0, 0, 0, 0, 0, 1, 1]


def test_build_failure_summary_limits_remediation_hints(monkeypatch) -> None:
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 4, 9, 12, 0, tzinfo=timezone.utc if tz else None)

    monkeypatch.setattr("onyx.server.manage.security_platform.api.datetime", FixedDateTime)

    summary = build_failure_summary(
        total_failures=3,
        recent_rows=[
            SimpleNamespace(
                persona_name="安全事件分析师",
                user_email="analyst@security.local",
                time_sent=datetime(2026, 4, 9, 12, 0, tzinfo=timezone.utc),
                stage="tool_followup",
                tool_name="threat_intel_lookup",
                error="401 unauthorized bad gateway timeout",
            )
        ],
        stage_count_rows=[],
        persona_count_rows=[],
        tool_count_rows=[],
        daily_count_rows=[],
    )

    assert len(summary.remediation_hints) == 3


def test_build_threat_intel_sync_health_summary_flags_missing_and_stale_feeds() -> None:
    summary = build_threat_intel_sync_health_summary(
        configured_feeds=[
            {"name": "cisa_kev", "min_refresh_interval_hours": 24},
            {"name": "cncert_weekly_reports", "min_refresh_interval_hours": 24},
            {"name": "nvd_security_advisories", "min_refresh_interval_hours": 48},
        ],
        sync_state={
            "feeds": {
                "cisa_kev": {"last_success_at": "2026-04-10T08:00:00+00:00"},
                "nvd_security_advisories": {"last_success_at": "2026-04-01T10:00:00+00:00"},
            },
            "last_refreshed_feeds": ["cisa_kev", "nvd_security_advisories"],
        },
        now=datetime(2026, 4, 10, 12, 0, tzinfo=timezone.utc),
    )

    assert summary.configured_feed_count == 3
    assert summary.refreshed_feed_count == 2
    assert summary.healthy_feed_count == 1
    assert summary.issue_count == 2
    assert summary.issue_entries[0].feed_name == "cncert_weekly_reports"
    assert summary.issue_entries[0].issue == "No successful sync recorded"
    assert summary.issue_entries[1].feed_name == "nvd_security_advisories"
    assert "refresh window" in summary.issue_entries[1].issue


def test_build_custom_permission_summary_sorts_permission_counts() -> None:
    summary = build_custom_permission_summary(
        default_group_count=2,
        custom_group_count=3,
        stale_custom_group_count=1,
        groups_with_custom_grants_count=2,
        custom_permission_count=3,
        manual_grant_count=4,
        scim_grant_count=1,
        admin_override_group_count=1,
        permission_counts={"manage:user_groups": 2, "admin": 1, "read:query_history": 3},
    )

    assert summary.default_group_count == 2
    assert summary.custom_group_count == 3
    assert summary.stale_custom_group_count == 1
    assert summary.groups_with_custom_grants_count == 2
    assert summary.custom_permission_count == 3
    assert summary.manual_grant_count == 4
    assert summary.scim_grant_count == 1
    assert summary.admin_override_group_count == 1
    assert list(summary.permission_counts.keys()) == [
        "admin",
        "manage:user_groups",
        "read:query_history",
    ]


def test_build_usage_limit_summary_formats_scope_counts() -> None:
    summary = build_usage_limit_summary(
        enabled=True,
        global_limit_count=1,
        enabled_global_limit_count=1,
        user_limit_count=2,
        enabled_user_limit_count=1,
        user_group_limit_count=3,
        enabled_user_group_limit_count=2,
        limited_user_group_count=2,
    )

    assert summary.enabled is True
    assert summary.global_limit_count == 1
    assert summary.enabled_global_limit_count == 1
    assert summary.user_limit_count == 2
    assert summary.enabled_user_limit_count == 1
    assert summary.user_group_limit_count == 3
    assert summary.enabled_user_group_limit_count == 2
    assert summary.limited_user_group_count == 2


def test_build_hook_summary_formats_recent_executions() -> None:
    summary = build_hook_summary(
        hooks_enabled=True,
        supported_hook_point_count=2,
        configured_hook_count=1,
        active_hook_count=1,
        reachable_hook_count=1,
        recent_execution_count=3,
        recent_failure_count=1,
        hook_point_names=["query_processing", "document_ingestion"],
        recent_execution_rows=[
            SimpleNamespace(
                hook_name="Query Hook",
                hook_point="query_processing",
                is_success=False,
                status_code=502,
                error_message="bad gateway",
                created_at=datetime(2026, 4, 7, 14, 0, tzinfo=timezone.utc),
            )
        ],
    )

    assert summary.hooks_enabled is True
    assert summary.supported_hook_point_count == 2
    assert summary.configured_hook_count == 1
    assert summary.active_hook_count == 1
    assert summary.reachable_hook_count == 1
    assert summary.recent_execution_count == 3
    assert summary.recent_failure_count == 1
    assert summary.hook_point_names == ["document_ingestion", "query_processing"]
    assert summary.recent_executions[0].created_at == "2026-04-07T14:00:00+00:00"


def test_build_custom_theming_snapshot_formats_branding_flags() -> None:
    settings = SimpleNamespace(
        application_name="Acme Security",
        use_custom_logo=True,
        use_custom_logotype=False,
        logo_display_style="logo_only",
        custom_nav_items=[{"title": "Portal"}],
        custom_header_content="Incident desk",
        custom_lower_disclaimer_content=None,
        show_first_visit_notice=True,
        custom_popup_header="Welcome",
        custom_popup_content="Read this first.",
        enable_consent_screen=True,
        consent_screen_prompt="I agree",
        custom_greeting_message="Hello team",
    )

    summary = build_custom_theming_snapshot(settings)

    assert summary["branding_configured"] is True
    assert summary["application_name"] == "Acme Security"
    assert summary["application_name_is_default"] is False
    assert summary["use_custom_logo"] is True
    assert summary["logo_display_style"] == "logo_only"
    assert summary["custom_nav_item_count"] == 1
    assert summary["custom_header_content_enabled"] is True
    assert summary["custom_popup_enabled"] is True
    assert summary["consent_screen_enabled"] is True
    assert summary["consent_prompt_configured"] is True


def test_load_white_labeling_summary_tracks_residual_branding_examples() -> None:
    summary = load_white_labeling_summary(
        {
            "branding_configured": True,
            "application_name_is_default": False,
            "use_custom_logo": True,
        }
    )

    assert summary.branding_configured is True
    assert summary.custom_logo_enabled is True
    assert summary.custom_favicon_enabled is True
    assert summary.application_name_configured is True
    assert summary.residual_branding_count >= 1
    assert summary.white_label_ready is False


def test_load_custom_deployment_summary_detects_supported_modes() -> None:
    summary = load_custom_deployment_summary()

    assert summary.docker_compose_variant_count >= 1
    assert summary.helm_values_variant_count >= 1
    assert summary.has_install_script is True
    assert summary.has_security_platform_compose_overlay is True
    assert summary.has_security_platform_helm_overlay is True
    assert "docker-compose" in summary.supported_modes
    assert "helm" in summary.supported_modes


def test_load_region_processing_summary_detects_region_hints() -> None:
    summary = load_region_processing_summary()

    assert summary.aws_region_supported is True
    assert summary.object_store_endpoint_configurable is True
    assert summary.web_domain_configurable is True
    assert summary.region_hint_count >= 1


def test_load_self_hosting_summary_detects_license_and_entrypoints(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "onyx.server.manage.security_platform.api.get_license_metadata",
        lambda _db_session: SimpleNamespace(
            status="active",
            source="manual_upload",
            seats=25,
            used_seats=7,
        ),
    )

    summary = load_self_hosting_summary(db_session=object())

    assert summary.self_hosted_mode is True
    assert summary.license_enforcement_enabled is LICENSE_ENFORCEMENT_ENABLED
    assert summary.has_license is True
    assert summary.license_status == "active"
    assert summary.license_source == "manual_upload"
    assert summary.seat_count == 25
    assert summary.used_seat_count == 7
    assert summary.has_license_api is True
    assert summary.has_admin_billing_page is True
    assert summary.has_cloud_proxy is True


def test_build_secrets_encryption_summary_counts_models_and_columns() -> None:
    summary = build_secrets_encryption_summary(
        enabled=True,
        encrypted_columns=[
            "credential.credential_json",
            "oauth_config.client_secret",
            "oauth_config.client_id",
        ],
        rotation_script_available=True,
    )

    assert summary.enabled is True
    assert summary.encrypted_model_count == 2
    assert summary.encrypted_column_count == 3
    assert summary.rotation_script_available is True


def test_build_health_status_reports_failing_checks() -> None:
    health = build_health_status(
        profile_name="demo",
        expected_threat_profile="mock",
        expected_tools_profile="mock",
        threat_intel_source_profile="live",
        security_tools_profile="mock",
        required_env=["SECURITY_TOOLS_MOCK_SERVER_URL", "SECURITY_TOOLS_MOCK_API_KEY"],
        missing_required_env=["SECURITY_TOOLS_MOCK_API_KEY"],
        placeholder_required_env=[],
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
                role="UserRole.LIMITED",
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
            "permission_inheritance": {
                "sync_cc_pair_count": 2,
                "docs_with_external_acl_count": 0,
                "recent_doc_sync_failure_count": 1,
                "recent_group_sync_failure_count": 0,
            },
            "service_accounts": {
                "api_key_count": 2,
                "service_account_user_count": 1,
                "ownerless_api_key_count": 1,
            },
            "scim": {
                "active_token_count": 2,
                "user_mapping_count": 0,
                "group_mapping_count": 3,
                "recent_group_sync_failure_count": 1,
            },
            "query_history_usage": {
                "query_history_type": "disabled",
                "query_history_enabled": False,
                "recent_query_count": 0,
                "recent_active_user_count": 0,
                "recent_export_failure_count": 1,
            },
            "custom_permissions": {
                "custom_group_count": 2,
                "custom_permission_count": 3,
                "manual_grant_count": 2,
                "stale_custom_group_count": 1,
                "admin_override_group_count": 1,
            },
            "usage_limits": {
                "enabled": False,
                "global_limit_count": 1,
                "enabled_global_limit_count": 0,
                "user_limit_count": 0,
                "enabled_user_limit_count": 0,
                "user_group_limit_count": 0,
                "enabled_user_group_limit_count": 0,
                "limited_user_group_count": 0,
            },
            "hooks": {
                "hooks_enabled": True,
                "supported_hook_point_count": 2,
                "configured_hook_count": 1,
                "active_hook_count": 1,
                "reachable_hook_count": 0,
                "recent_failure_count": 1,
            },
            "custom_theming": {
                "branding_configured": True,
                "application_name": "Onyx",
                "application_name_is_default": True,
                "use_custom_logo": False,
                "use_custom_logotype": False,
                "logo_display_style": "logo_only",
                "custom_nav_item_count": 0,
                "custom_header_content_enabled": False,
                "custom_lower_disclaimer_enabled": False,
                "first_visit_notice_enabled": True,
                "custom_popup_enabled": False,
                "consent_screen_enabled": True,
                "custom_greeting_enabled": False,
                "consent_prompt_configured": False,
                "popup_content_configured": False,
            },
            "white_labeling": {
                "branding_configured": True,
                "custom_logo_enabled": True,
                "custom_favicon_enabled": True,
                "application_name_configured": True,
                "white_label_ready": False,
                "residual_branding_count": 2,
                "residual_external_link_count": 1,
                "residual_branding_examples": [
                    "Logo.tsx: Powered by Onyx",
                    "AdminSidebar.tsx: https://onyx.app",
                ],
            },
            "custom_deployments": {
                "docker_compose_variant_count": 4,
                "helm_values_variant_count": 3,
                "has_install_script": True,
                "has_multitenant_compose": True,
                "has_lite_compose": True,
                "has_prod_compose": True,
                "has_security_platform_compose_overlay": True,
                "has_security_platform_helm_overlay": True,
                "supported_modes": ["docker-compose", "helm", "production"],
                "overlay_examples": [
                    "deployment/docker_compose/docker-compose.security-platform.override.yml"
                ],
            },
            "region_processing": {
                "aws_region_supported": True,
                "object_store_endpoint_configurable": True,
                "web_domain_configurable": True,
                "tenant_aware_deployment_supported": True,
                "cloud_deployment_supported": True,
                "region_hint_count": 4,
                "region_hints": [
                    "env.template: AWS_REGION_NAME",
                    "env.template: S3_ENDPOINT_URL",
                ],
            },
            "self_hosting": {
                "self_hosted_mode": True,
                "multi_tenant_mode": False,
                "enterprise_features_enabled": True,
                "license_enforcement_enabled": True,
                "has_license": False,
                "license_status": None,
                "license_source": None,
                "seat_count": None,
                "used_seat_count": None,
                "has_license_api": True,
                "has_admin_billing_page": True,
                "has_billing_service": True,
                "has_cloud_proxy": True,
                "cloud_data_plane_url_configured": True,
                "has_install_script": True,
                "has_docker_compose_path": True,
                "has_helm_install_path": True,
            },
            "secrets_encryption": {
                "enabled": False,
                "encrypted_column_count": 0,
                "rotation_script_available": False,
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
    assert any(
        check["name"] == "permission_inheritance" and check["status"] == "failing"
        for check in health["checks"]
    )
    rbac_check = next(check for check in health["checks"] if check["name"] == "rbac")
    assert any("web-login roles" in issue for issue in rbac_check["issues"])
    service_account_check = next(
        check for check in health["checks"] if check["name"] == "service_accounts"
    )
    assert any("Ownerless service account API keys detected" in issue for issue in service_account_check["issues"])
    scim_check = next(check for check in health["checks"] if check["name"] == "scim")
    assert any("Multiple active SCIM tokens detected" in issue for issue in scim_check["issues"])
    query_history_check = next(
        check for check in health["checks"] if check["name"] == "query_history_usage"
    )
    assert any("Query history is disabled" in issue for issue in query_history_check["issues"])
    custom_permissions_check = next(
        check for check in health["checks"] if check["name"] == "custom_permissions"
    )
    assert any(
        "Custom permission groups pending sync detected" in issue
        for issue in custom_permissions_check["issues"]
    )
    usage_limits_check = next(
        check for check in health["checks"] if check["name"] == "usage_limits"
    )
    assert any("Usage limits are disabled" in issue for issue in usage_limits_check["issues"])
    hooks_check = next(check for check in health["checks"] if check["name"] == "hooks")
    assert any("Active but unreachable hooks detected" in issue for issue in hooks_check["issues"])
    theming_check = next(
        check for check in health["checks"] if check["name"] == "custom_theming"
    )
    assert theming_check["status"] == "warning"
    assert any("Consent screen is enabled" in issue for issue in theming_check["issues"])
    white_label_check = next(
        check for check in health["checks"] if check["name"] == "white_labeling"
    )
    assert white_label_check["status"] == "warning"
    assert any("residual Onyx UI traces remain" in issue for issue in white_label_check["issues"])
    deployment_check = next(
        check for check in health["checks"] if check["name"] == "custom_deployments"
    )
    assert deployment_check["status"] == "healthy"
    region_check = next(
        check for check in health["checks"] if check["name"] == "region_processing"
    )
    assert region_check["status"] == "healthy"
    self_hosting_check = next(
        check for check in health["checks"] if check["name"] == "self_hosting"
    )
    assert self_hosting_check["status"] == "warning"
    assert any("no local self-hosted license metadata" in issue for issue in self_hosting_check["issues"])
    secrets_check = next(
        check for check in health["checks"] if check["name"] == "secrets_encryption"
    )
    assert any("ENCRYPTION_KEY_SECRET is not configured" in issue for issue in secrets_check["issues"])


def test_build_health_status_reports_warning_for_due_threat_intel_only() -> None:
    health = build_health_status(
        profile_name="demo",
        expected_threat_profile="mock",
        expected_tools_profile="mock",
        threat_intel_source_profile="mock",
        security_tools_profile="mock",
        required_env=[],
        missing_required_env=[],
        placeholder_required_env=[],
        deployment_profile_issues=[],
        document_set_status=SecurityPlatformDocumentSetStatus(
            id=1,
            name="安全知识库",
            exists=True,
            is_public=True,
            shared_user_count=7,
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
                "威胁狩猎工程师",
                "恶意软件分析师",
                "检测工程师",
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
                "detection@security.local",
                "hunter@security.local",
                "malware@security.local",
                "vuln_expert@security.local",
            ]
        ],
        persona_user_links=7,
        document_set_user_links=7,
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
            "permission_inheritance": {
                "sync_cc_pair_count": 0,
                "docs_with_external_acl_count": 0,
                "recent_doc_sync_failure_count": 0,
                "recent_group_sync_failure_count": 0,
            },
            "service_accounts": {
                "api_key_count": 0,
                "service_account_user_count": 0,
                "ownerless_api_key_count": 0,
            },
            "scim": {
                "active_token_count": 0,
                "user_mapping_count": 0,
                "group_mapping_count": 0,
                "recent_group_sync_failure_count": 0,
            },
            "query_history_usage": {
                "query_history_type": "normal",
                "query_history_enabled": True,
                "recent_query_count": 12,
                "recent_active_user_count": 3,
                "recent_export_failure_count": 0,
            },
            "custom_permissions": {
                "custom_group_count": 1,
                "custom_permission_count": 1,
                "manual_grant_count": 1,
                "stale_custom_group_count": 0,
                "admin_override_group_count": 0,
            },
            "usage_limits": {
                "enabled": True,
                "global_limit_count": 1,
                "enabled_global_limit_count": 1,
                "user_limit_count": 0,
                "enabled_user_limit_count": 0,
                "user_group_limit_count": 0,
                "enabled_user_group_limit_count": 0,
                "limited_user_group_count": 0,
            },
            "hooks": {
                "hooks_enabled": True,
                "supported_hook_point_count": 2,
                "configured_hook_count": 0,
                "active_hook_count": 0,
                "reachable_hook_count": 0,
                "recent_failure_count": 0,
            },
            "custom_theming": {
                "branding_configured": True,
                "application_name": "Acme Security",
                "application_name_is_default": False,
                "use_custom_logo": True,
                "use_custom_logotype": False,
                "logo_display_style": "logo_and_name",
                "custom_nav_item_count": 2,
                "custom_header_content_enabled": True,
                "custom_lower_disclaimer_enabled": False,
                "first_visit_notice_enabled": True,
                "custom_popup_enabled": True,
                "consent_screen_enabled": True,
                "custom_greeting_enabled": True,
                "consent_prompt_configured": True,
                "popup_content_configured": True,
            },
            "white_labeling": {
                "branding_configured": True,
                "custom_logo_enabled": True,
                "custom_favicon_enabled": True,
                "application_name_configured": True,
                "white_label_ready": False,
                "residual_branding_count": 2,
                "residual_external_link_count": 1,
                "residual_branding_examples": [
                    "Logo.tsx: Powered by Onyx",
                    "AdminSidebar.tsx: https://onyx.app",
                ],
            },
            "custom_deployments": {
                "docker_compose_variant_count": 4,
                "helm_values_variant_count": 3,
                "has_install_script": True,
                "has_multitenant_compose": True,
                "has_lite_compose": True,
                "has_prod_compose": True,
                "has_security_platform_compose_overlay": True,
                "has_security_platform_helm_overlay": True,
                "supported_modes": ["docker-compose", "helm", "multitenant", "lite", "production"],
                "overlay_examples": [
                    "deployment/docker_compose/docker-compose.security-platform.override.yml",
                    "deployment/helm/charts/onyx/values.security-platform.yaml",
                ],
            },
            "region_processing": {
                "aws_region_supported": True,
                "object_store_endpoint_configurable": True,
                "web_domain_configurable": True,
                "tenant_aware_deployment_supported": True,
                "cloud_deployment_supported": True,
                "region_hint_count": 5,
                "region_hints": [
                    "env.template: AWS_REGION_NAME",
                    "values.yaml: WEB_DOMAIN",
                ],
            },
            "self_hosting": {
                "self_hosted_mode": False,
                "multi_tenant_mode": True,
                "enterprise_features_enabled": True,
                "license_enforcement_enabled": True,
                "has_license": False,
                "license_status": None,
                "license_source": None,
                "seat_count": None,
                "used_seat_count": None,
                "has_license_api": True,
                "has_admin_billing_page": True,
                "has_billing_service": True,
                "has_cloud_proxy": True,
                "cloud_data_plane_url_configured": True,
                "has_install_script": True,
                "has_docker_compose_path": True,
                "has_helm_install_path": True,
            },
            "secrets_encryption": {
                "enabled": True,
                "encrypted_column_count": 3,
                "rotation_script_available": True,
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
                "packages": [],
                "consistency": {
                    "ok": True,
                    "summary": {
                        "package_count": 2,
                        "consistent_package_count": 2,
                        "issue_count": 0,
                    },
                    "issues": [],
                    "package_checks": [],
                },
            },
        },
    )

    assert health["overall_status"] == "warning"
    assert health["failing_checks"] == 0
    assert health["warning_checks"] == 2


def test_build_health_status_reports_historical_package_catalog_drift() -> None:
    health = build_health_status(
        profile_name="demo",
        expected_threat_profile="mock",
        expected_tools_profile="mock",
        threat_intel_source_profile="mock",
        security_tools_profile="mock",
        required_env=[],
        missing_required_env=[],
        placeholder_required_env=[],
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
            "permission_inheritance": {
                "sync_cc_pair_count": 0,
                "docs_with_external_acl_count": 0,
                "recent_doc_sync_failure_count": 0,
                "recent_group_sync_failure_count": 0,
            },
            "service_accounts": {
                "api_key_count": 0,
                "service_account_user_count": 0,
                "ownerless_api_key_count": 0,
            },
            "scim": {
                "active_token_count": 0,
                "user_mapping_count": 0,
                "group_mapping_count": 0,
                "recent_group_sync_failure_count": 0,
            },
            "query_history_usage": {
                "query_history_type": "normal",
                "query_history_enabled": True,
                "recent_query_count": 12,
                "recent_active_user_count": 3,
                "recent_export_failure_count": 0,
            },
            "custom_permissions": {
                "custom_group_count": 1,
                "custom_permission_count": 1,
                "manual_grant_count": 1,
                "stale_custom_group_count": 0,
                "admin_override_group_count": 0,
            },
            "usage_limits": {
                "enabled": True,
                "global_limit_count": 1,
                "enabled_global_limit_count": 1,
                "user_limit_count": 1,
                "enabled_user_limit_count": 1,
                "user_group_limit_count": 1,
                "enabled_user_group_limit_count": 1,
                "limited_user_group_count": 1,
            },
            "hooks": {
                "hooks_enabled": True,
                "supported_hook_point_count": 2,
                "configured_hook_count": 1,
                "active_hook_count": 1,
                "reachable_hook_count": 1,
                "recent_failure_count": 0,
            },
            "custom_theming": {
                "branding_configured": False,
                "application_name": "Onyx",
                "application_name_is_default": True,
                "use_custom_logo": False,
                "use_custom_logotype": False,
                "logo_display_style": "logo_and_name",
                "custom_nav_item_count": 0,
                "custom_header_content_enabled": False,
                "custom_lower_disclaimer_enabled": False,
                "first_visit_notice_enabled": False,
                "custom_popup_enabled": False,
                "consent_screen_enabled": False,
                "custom_greeting_enabled": False,
                "consent_prompt_configured": False,
                "popup_content_configured": False,
            },
            "white_labeling": {
                "branding_configured": False,
                "custom_logo_enabled": False,
                "custom_favicon_enabled": False,
                "application_name_configured": False,
                "white_label_ready": False,
                "residual_branding_count": 2,
                "residual_external_link_count": 1,
                "residual_branding_examples": [
                    "Logo.tsx: Powered by Onyx",
                    "AdminSidebar.tsx: https://onyx.app",
                ],
            },
            "custom_deployments": {
                "docker_compose_variant_count": 4,
                "helm_values_variant_count": 3,
                "has_install_script": True,
                "has_multitenant_compose": True,
                "has_lite_compose": True,
                "has_prod_compose": True,
                "has_security_platform_compose_overlay": True,
                "has_security_platform_helm_overlay": True,
                "supported_modes": ["docker-compose", "helm"],
                "overlay_examples": [
                    "deployment/docker_compose/docker-compose.security-platform.override.yml"
                ],
            },
            "region_processing": {
                "aws_region_supported": True,
                "object_store_endpoint_configurable": True,
                "web_domain_configurable": True,
                "tenant_aware_deployment_supported": True,
                "cloud_deployment_supported": True,
                "region_hint_count": 3,
                "region_hints": [
                    "env.template: AWS_REGION_NAME",
                ],
            },
            "self_hosting": {
                "self_hosted_mode": False,
                "multi_tenant_mode": True,
                "enterprise_features_enabled": True,
                "license_enforcement_enabled": True,
                "has_license": False,
                "license_status": None,
                "license_source": None,
                "seat_count": None,
                "used_seat_count": None,
                "has_license_api": True,
                "has_admin_billing_page": True,
                "has_billing_service": True,
                "has_cloud_proxy": True,
                "cloud_data_plane_url_configured": True,
                "has_install_script": True,
                "has_docker_compose_path": True,
                "has_helm_install_path": True,
            },
            "secrets_encryption": {
                "enabled": True,
                "encrypted_column_count": 3,
                "rotation_script_available": True,
            },
            "historical_packages": {
                "package_count": 2,
                "total_item_count": 0,
                "total_size_bytes": 123,
                "package_ids": ["phase-1-cisa-limited-historical"],
                "packages": [],
                "consistency": {
                    "ok": False,
                    "summary": {
                        "package_count": 2,
                        "consistent_package_count": 1,
                        "issue_count": 1,
                    },
                    "issues": ["README drift"],
                    "package_checks": [],
                },
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
    assert any("Catalog consistency issue: README drift" in issue for issue in historical_check["issues"])


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
        "python knowledge-base/build_threat_intel_historical_package_index.py --write-index",
        "python knowledge-base/check_threat_intel_historical_package_consistency.py --json",
    ]
