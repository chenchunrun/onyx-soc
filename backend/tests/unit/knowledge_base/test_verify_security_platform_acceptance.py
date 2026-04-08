from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace


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
        "rbac": {
            "user_group_count": 3,
            "permission_grant_count": 6,
            "users_with_effective_permissions_count": 4,
            "curator_membership_count": 1,
        },
        "service_accounts": {
            "api_key_count": 2,
            "service_account_user_count": 2,
            "ownerless_api_key_count": 0,
        },
        "query_history_usage": {
            "query_history_type": "normal",
            "query_history_enabled": True,
            "recent_query_count": 42,
            "recent_chat_session_count": 18,
            "recent_active_user_count": 7,
            "recent_like_count": 5,
            "recent_dislike_count": 2,
            "recent_export_count": 3,
            "recent_export_failure_count": 0,
            "recent_exports": [],
        },
        "custom_permissions": {
            "default_group_count": 2,
            "custom_group_count": 3,
            "stale_custom_group_count": 0,
            "groups_with_custom_grants_count": 2,
            "custom_permission_count": 3,
            "manual_grant_count": 4,
            "scim_grant_count": 1,
            "admin_override_group_count": 0,
            "permission_counts": {
                "manage:user_groups": 2,
                "read:query_history": 2,
                "create:service_account_api_keys": 1,
            },
        },
        "usage_limits": {
            "enabled": True,
            "global_limit_count": 1,
            "enabled_global_limit_count": 1,
            "user_limit_count": 2,
            "enabled_user_limit_count": 1,
            "user_group_limit_count": 3,
            "enabled_user_group_limit_count": 2,
            "limited_user_group_count": 2,
        },
        "hooks": {
            "hooks_enabled": True,
            "supported_hook_point_count": 2,
            "configured_hook_count": 1,
            "active_hook_count": 1,
            "reachable_hook_count": 1,
            "recent_execution_count": 3,
            "recent_failure_count": 0,
            "hook_point_names": ["document_ingestion", "query_processing"],
            "recent_executions": [],
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
            "docker_compose_variant_count": 6,
            "helm_values_variant_count": 4,
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
                "env.template: S3_ENDPOINT_URL",
                "values.yaml: WEB_DOMAIN",
            ],
        },
        "self_hosting": {
            "self_hosted_mode": True,
            "multi_tenant_mode": False,
            "enterprise_features_enabled": True,
            "license_enforcement_enabled": True,
            "has_license": True,
            "license_status": "active",
            "license_source": "manual_upload",
            "seat_count": 25,
            "used_seat_count": 7,
            "has_license_api": True,
            "has_admin_billing_page": True,
            "has_billing_service": True,
            "has_cloud_proxy": True,
            "cloud_data_plane_url_configured": True,
            "has_install_script": True,
            "has_docker_compose_path": True,
            "has_helm_install_path": True,
        },
        "scim": {
            "active_token_count": 1,
            "user_mapping_count": 4,
            "group_mapping_count": 2,
            "recent_group_sync_failure_count": 0,
        },
        "permission_inheritance": {
            "sync_cc_pair_count": 2,
            "docs_with_external_acl_count": 25,
            "docs_with_user_acl_count": 17,
            "docs_with_group_acl_count": 8,
            "recent_doc_sync_failure_count": 0,
            "recent_group_sync_failure_count": 0,
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
        historical_package_summary={
            "package_count": 2,
            "total_item_count": 203,
            "total_size_bytes": 242152,
            "package_ids": [
                "phase-1-cisa-limited-historical",
                "phase-2-nvd-authoritative-historical",
            ],
            "consistent_package_count": 2,
            "consistency_issue_count": 0,
            "consistency_issues": [],
        },
        archive_execution_summary={
            "batch_count": 2,
            "fully_materialized_batch_count": 2,
            "artifact_counts": {
                "worklist": 2,
                "patch_preview": 2,
                "action_script": 2,
                "execution_plan": 2,
                "execution_record": 2,
                "execution_result": 2,
            },
            "consistency_issue_count": 0,
            "consistency_issues": [],
            "batches": [],
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
                "ENCRYPTION_KEY_SECRET": "test-secret-key",
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
    assert result["health"]["overall_status"] == "warning"
    assert any(
        "remaining Onyx strings" in action or "white-labeling support" in action
        for action in result["recommended_next_actions"]
    )
    assert result["summary"]["deployment_profile"] == "demo"
    assert result["summary"]["security_tools_profile"] == "mock"
    assert result["summary"]["security_tools_summary"]["threat_intel_lookup"]["configured_header_keys"] == [
        "x-apikey"
    ]
    assert result["summary"]["threat_intel_source_profile"] == "mock"
    assert result["summary"]["threat_intel_due_status"] == "WAIT"
    assert result["summary"]["threat_intel_governed_feeds"] == 1902
    assert result["summary"]["threat_intel_promotion_candidates"] == 0
    assert result["summary"]["historical_package_count"] == 2
    assert result["summary"]["historical_package_total_items"] == 203
    assert result["summary"]["historical_package_ids"] == [
        "phase-1-cisa-limited-historical",
        "phase-2-nvd-authoritative-historical",
    ]
    assert result["summary"]["historical_package_consistent_count"] == 2
    assert result["summary"]["historical_package_consistency_issue_count"] == 0
    assert result["summary"]["playbook_count"] == 2
    assert result["summary"]["rbac_user_group_count"] == 3
    assert result["summary"]["rbac_permission_grant_count"] == 6
    assert result["summary"]["service_account_api_key_count"] == 2
    assert result["summary"]["service_account_user_count"] == 2
    assert result["summary"]["query_history_type"] == "normal"
    assert result["summary"]["query_history_enabled"] is True
    assert result["summary"]["query_history_recent_query_count"] == 42
    assert result["summary"]["query_history_export_failure_count"] == 0
    assert result["summary"]["custom_permission_group_count"] == 3
    assert result["summary"]["custom_permission_count"] == 3
    assert result["summary"]["custom_permission_manual_grant_count"] == 4
    assert result["summary"]["usage_limits_enabled"] is True
    assert result["summary"]["usage_limit_global_count"] == 1
    assert result["summary"]["usage_limit_enabled_user_group_count"] == 2
    assert result["summary"]["hooks_enabled"] is True
    assert result["summary"]["hook_configured_count"] == 1
    assert result["summary"]["hook_recent_failure_count"] == 0
    assert result["summary"]["custom_theming_branding_configured"] is True
    assert result["summary"]["custom_theming_application_name"] == "Acme Security"
    assert result["summary"]["custom_theming_use_custom_logo"] is True
    assert result["summary"]["white_labeling_branding_configured"] is True
    assert result["summary"]["white_labeling_ready"] is False
    assert result["summary"]["white_labeling_residual_branding_count"] == 2
    assert result["summary"]["custom_deployment_compose_variant_count"] == 6
    assert result["summary"]["custom_deployment_has_security_platform_helm_overlay"] is True
    assert result["summary"]["region_processing_aws_region_supported"] is True
    assert result["summary"]["region_processing_cloud_supported"] is True
    assert result["summary"]["self_hosting_self_hosted_mode"] is True
    assert result["summary"]["self_hosting_has_license"] is True
    assert result["summary"]["self_hosting_license_status"] == "active"
    assert result["summary"]["self_hosting_has_admin_billing_page"] is True
    assert result["summary"]["scim_active_token_count"] == 1
    assert result["summary"]["scim_user_mapping_count"] == 4
    assert result["summary"]["secrets_encryption_enabled"] is True
    assert result["summary"]["permission_sync_cc_pairs"] == 2
    assert result["summary"]["permission_docs_with_external_acl"] == 25


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
            "rbac": {
                "user_group_count": 0,
                "permission_grant_count": 0,
                "users_with_effective_permissions_count": 0,
                "curator_membership_count": 0,
            },
            "service_accounts": {
                "api_key_count": 2,
                "service_account_user_count": 1,
                "ownerless_api_key_count": 1,
            },
            "query_history_usage": {
                "query_history_type": "disabled",
                "query_history_enabled": False,
                "recent_query_count": 0,
                "recent_chat_session_count": 0,
                "recent_active_user_count": 0,
                "recent_like_count": 0,
                "recent_dislike_count": 0,
                "recent_export_count": 1,
                "recent_export_failure_count": 1,
                "recent_exports": [],
            },
            "custom_permissions": {
                "default_group_count": 2,
                "custom_group_count": 2,
                "stale_custom_group_count": 1,
                "groups_with_custom_grants_count": 2,
                "custom_permission_count": 2,
                "manual_grant_count": 1,
                "scim_grant_count": 0,
                "admin_override_group_count": 1,
                "permission_counts": {
                    "admin": 1,
                    "manage:user_groups": 1,
                },
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
                "recent_execution_count": 2,
                "recent_failure_count": 1,
                "hook_point_names": ["document_ingestion", "query_processing"],
                "recent_executions": [],
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
                "docker_compose_variant_count": 6,
                "helm_values_variant_count": 4,
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
                "region_hint_count": 4,
                "region_hints": [
                    "env.template: AWS_REGION_NAME",
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
            "scim": {
                "active_token_count": 2,
                "user_mapping_count": 0,
                "group_mapping_count": 3,
                "recent_group_sync_failure_count": 1,
            },
            "permission_inheritance": {
                "sync_cc_pair_count": 2,
                "docs_with_external_acl_count": 0,
                "docs_with_user_acl_count": 0,
                "docs_with_group_acl_count": 0,
                "recent_doc_sync_failure_count": 1,
                "recent_group_sync_failure_count": 1,
            },
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
        historical_package_summary={
            "package_count": 0,
            "total_item_count": 0,
            "total_size_bytes": 0,
            "package_ids": [],
            "consistent_package_count": 0,
            "consistency_issue_count": 1,
            "consistency_issues": ["Missing historical package index"],
        },
        archive_execution_summary={
            "batch_count": 2,
            "fully_materialized_batch_count": 1,
            "artifact_counts": {
                "worklist": 2,
                "patch_preview": 1,
                "action_script": 2,
                "execution_plan": 2,
                "execution_record": 1,
                "execution_result": 2,
            },
            "consistency_issue_count": 2,
            "consistency_issues": [
                "Archive batch phase-1 missing artifact: patch_preview",
                "Archive batch phase-2 execution_result consistency issues: 1",
            ],
            "batches": [],
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
    assert any("Historical package catalog consistency issues: 1" in failure for failure in result["failures"])
    assert any("Archive execution artifact consistency issues: 2" in failure for failure in result["failures"])
    assert any("Playbooks missing example_inputs" in failure for failure in result["failures"])
    assert any("API key count and service-account user count diverge: 2/1" in failure for failure in result["failures"])
    assert any("Ownerless service account API keys detected: 1" in failure for failure in result["failures"])
    assert any("Query history is disabled" in failure for failure in result["failures"])
    assert any("Recent query history export failures observed: 1" in failure for failure in result["failures"])
    assert any(
        "Custom permission groups pending sync detected: 1" in failure
        for failure in result["failures"]
    )
    usage_limits_check = next(
        check for check in result["health"]["checks"] if check["name"] == "usage_limits"
    )
    assert usage_limits_check["status"] == "warning"
    assert any("Usage limits are disabled" in issue for issue in usage_limits_check["issues"])
    assert any(
        "Active but unreachable hooks detected: 1" in failure
        for failure in result["failures"]
    )
    assert any("Multiple active SCIM tokens detected: 2" in failure for failure in result["failures"])
    assert any("SCIM group mappings exist without any SCIM user mappings" in failure for failure in result["failures"])
    assert any("ENCRYPTION_KEY_SECRET is not configured" in failure for failure in result["failures"])
    assert any("SYNC connectors exist but no documents currently carry external ACL metadata" in failure for failure in result["failures"])
    assert any("Recent doc permission sync failures observed: 1" in failure for failure in result["failures"])
    assert any("Recent external group sync failures observed: 1" in failure for failure in result["failures"])


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


def test_load_historical_package_summary_includes_consistency_status(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    index_path = tmp_path / "index.json"
    index_path.write_text(
        (
            "{\n"
            '  "summary": {"package_count": 1, "total_item_count": 12, "total_size_bytes": 2048},\n'
            '  "packages": [{"batch_id": "phase-1", "item_count": 12, "total_size_bytes": 2048}]\n'
            "}\n"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "HISTORICAL_PACKAGE_INDEX_PATH", index_path)
    monkeypatch.setattr(
        module,
        "evaluate_catalog_consistency",
        lambda: {
            "ok": False,
            "summary": {
                "package_count": 1,
                "consistent_package_count": 0,
                "issue_count": 2,
            },
            "issues": ["phase-1: Missing README", "phase-1: README does not mention item_count"],
        },
    )

    summary = module.load_historical_package_summary()

    assert summary["package_count"] == 1
    assert summary["consistent_package_count"] == 0
    assert summary["consistency_issue_count"] == 2
    assert summary["consistency_issues"] == [
        "phase-1: Missing README",
        "phase-1: README does not mention item_count",
    ]


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


def test_load_archive_execution_summary_reports_complete_batches(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    threat_intel_dir = tmp_path / "threat-intelligence"
    (threat_intel_dir / "archive_worklists").mkdir(parents=True)
    (threat_intel_dir / "archive_patch_previews").mkdir()
    (threat_intel_dir / "archive_action_scripts").mkdir()
    (threat_intel_dir / "archive_execution_plans").mkdir()
    (threat_intel_dir / "archive_execution_records").mkdir()
    (threat_intel_dir / "archive_execution_results").mkdir()
    (threat_intel_dir / "archive_batches.json").write_text(
        json.dumps({"batches": [{"batch_id": "phase-1"}]}),
        encoding="utf-8",
    )
    (threat_intel_dir / "archive_worklists" / "phase-1.json").write_text("{}", encoding="utf-8")
    (threat_intel_dir / "archive_patch_previews" / "phase-1.json").write_text("{}", encoding="utf-8")
    (threat_intel_dir / "archive_action_scripts" / "phase-1.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    (threat_intel_dir / "archive_execution_plans" / "phase-1.md").write_text("# plan\n", encoding="utf-8")
    (threat_intel_dir / "archive_execution_records" / "phase-1.md").write_text("# record\n", encoding="utf-8")
    (threat_intel_dir / "archive_execution_results" / "phase-1.json").write_text(
        json.dumps({"batch_id": "phase-1", "summary": {"consistency_issue_count": 0}}),
        encoding="utf-8",
    )

    monkeypatch.setattr(module, "ARCHIVE_BATCHES_PATH", threat_intel_dir / "archive_batches.json")
    monkeypatch.setattr(module, "ARCHIVE_WORKLIST_DIR", threat_intel_dir / "archive_worklists")
    monkeypatch.setattr(module, "ARCHIVE_PATCH_PREVIEW_DIR", threat_intel_dir / "archive_patch_previews")
    monkeypatch.setattr(module, "ARCHIVE_ACTION_SCRIPT_DIR", threat_intel_dir / "archive_action_scripts")
    monkeypatch.setattr(module, "ARCHIVE_EXECUTION_PLAN_DIR", threat_intel_dir / "archive_execution_plans")
    monkeypatch.setattr(module, "ARCHIVE_EXECUTION_RECORD_DIR", threat_intel_dir / "archive_execution_records")
    monkeypatch.setattr(module, "ARCHIVE_EXECUTION_RESULT_DIR", threat_intel_dir / "archive_execution_results")

    summary = module.load_archive_execution_summary()

    assert summary["batch_count"] == 1
    assert summary["fully_materialized_batch_count"] == 1
    assert summary["consistency_issue_count"] == 0
    assert summary["artifact_counts"]["execution_result"] == 1


def test_load_archive_execution_summary_reports_missing_artifacts_and_result_issues(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    threat_intel_dir = tmp_path / "threat-intelligence"
    (threat_intel_dir / "archive_worklists").mkdir(parents=True)
    (threat_intel_dir / "archive_patch_previews").mkdir()
    (threat_intel_dir / "archive_action_scripts").mkdir()
    (threat_intel_dir / "archive_execution_plans").mkdir()
    (threat_intel_dir / "archive_execution_records").mkdir()
    (threat_intel_dir / "archive_execution_results").mkdir()
    (threat_intel_dir / "archive_batches.json").write_text(
        json.dumps({"batches": [{"batch_id": "phase-1"}]}),
        encoding="utf-8",
    )
    (threat_intel_dir / "archive_worklists" / "phase-1.json").write_text("{}", encoding="utf-8")
    (threat_intel_dir / "archive_action_scripts" / "phase-1.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    (threat_intel_dir / "archive_execution_plans" / "phase-1.md").write_text("# plan\n", encoding="utf-8")
    (threat_intel_dir / "archive_execution_results" / "phase-1.json").write_text(
        json.dumps({"batch_id": "phase-1", "summary": {"consistency_issue_count": 2}}),
        encoding="utf-8",
    )

    monkeypatch.setattr(module, "ARCHIVE_BATCHES_PATH", threat_intel_dir / "archive_batches.json")
    monkeypatch.setattr(module, "ARCHIVE_WORKLIST_DIR", threat_intel_dir / "archive_worklists")
    monkeypatch.setattr(module, "ARCHIVE_PATCH_PREVIEW_DIR", threat_intel_dir / "archive_patch_previews")
    monkeypatch.setattr(module, "ARCHIVE_ACTION_SCRIPT_DIR", threat_intel_dir / "archive_action_scripts")
    monkeypatch.setattr(module, "ARCHIVE_EXECUTION_PLAN_DIR", threat_intel_dir / "archive_execution_plans")
    monkeypatch.setattr(module, "ARCHIVE_EXECUTION_RECORD_DIR", threat_intel_dir / "archive_execution_records")
    monkeypatch.setattr(module, "ARCHIVE_EXECUTION_RESULT_DIR", threat_intel_dir / "archive_execution_results")

    summary = module.load_archive_execution_summary()

    assert summary["batch_count"] == 1
    assert summary["fully_materialized_batch_count"] == 0
    assert summary["consistency_issue_count"] == 3
    assert "Archive batch phase-1 missing artifact: patch_preview" in summary["consistency_issues"]
    assert "Archive batch phase-1 missing artifact: execution_record" in summary["consistency_issues"]
    assert "Archive batch phase-1 execution_result consistency issues: 2" in summary["consistency_issues"]


def test_main_returns_one_when_login_fails(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            url="http://example.com",
            email="security-admin@example.com",
            password="secret",
            db_password="postgres",
            json=False,
        ),
    )
    monkeypatch.setattr(module, "get_cookie", lambda *_args, **_kwargs: None)

    result = module.main()

    assert result == 1
    assert "[ERROR] Login failed. Check credentials." in capsys.readouterr().out


def test_main_json_returns_zero_for_successful_acceptance(monkeypatch, capsys) -> None:
    module = _load_module()
    expected_result = {"ok": True, "summary": {"deployment_profile": "demo"}}
    monkeypatch.setattr(
        module.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            url="http://example.com",
            email="security-admin@example.com",
            password="secret",
            db_password="postgres",
            json=True,
        ),
    )
    monkeypatch.setattr(module, "get_cookie", lambda *_args, **_kwargs: "cookie")
    monkeypatch.setattr(module, "load_deployment_profile_summary", lambda: {"deployment_profile": "demo"})
    monkeypatch.setattr(
        module,
        "load_security_tool_configs",
        lambda: [{"name": "create_security_ticket", "persona_bindings": ["安全事件分析师"]}],
    )
    monkeypatch.setattr(
        module,
        "build_persona_tool_requirements",
        lambda _configs: {"安全事件分析师": {"builtin_tools": set(), "custom_tools": set()}},
    )
    monkeypatch.setattr(
        module,
        "list_personas",
        lambda *_args, **_kwargs: [{"id": 1, "name": "安全事件分析师"}],
    )
    monkeypatch.setattr(
        module,
        "get_persona",
        lambda *_args, **_kwargs: {"id": 1, "name": "安全事件分析师", "tools": []},
    )
    monkeypatch.setattr(module, "list_openapi_tools", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "list_document_sets", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "list_ingestion_documents", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "fetch_db_state", lambda **_kwargs: {})
    monkeypatch.setattr(module, "load_threat_intel_sync_summary", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(module, "load_threat_intel_curation_summary", lambda: {})
    monkeypatch.setattr(module, "load_historical_package_summary", lambda: {})
    monkeypatch.setattr(module, "load_security_tool_profile_summary", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(module, "load_playbook_definitions_summary", lambda: {})
    monkeypatch.setattr(module, "evaluate_acceptance", lambda **_kwargs: expected_result)

    result = module.main()

    assert result == 0
    assert json.loads(capsys.readouterr().out) == expected_result


def test_main_human_returns_one_for_failed_acceptance(monkeypatch) -> None:
    module = _load_module()
    expected_result = {"ok": False, "summary": {}, "failures": ["missing personas"]}
    printed: list[dict] = []
    monkeypatch.setattr(
        module.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            url="http://example.com",
            email="security-admin@example.com",
            password="secret",
            db_password="postgres",
            json=False,
        ),
    )
    monkeypatch.setattr(module, "get_cookie", lambda *_args, **_kwargs: "cookie")
    monkeypatch.setattr(module, "load_deployment_profile_summary", lambda: {})
    monkeypatch.setattr(module, "load_security_tool_configs", lambda: [])
    monkeypatch.setattr(module, "build_persona_tool_requirements", lambda _configs: {})
    monkeypatch.setattr(module, "list_personas", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "list_openapi_tools", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "list_document_sets", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "list_ingestion_documents", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "fetch_db_state", lambda **_kwargs: {})
    monkeypatch.setattr(module, "load_threat_intel_sync_summary", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(module, "load_threat_intel_curation_summary", lambda: {})
    monkeypatch.setattr(module, "load_historical_package_summary", lambda: {})
    monkeypatch.setattr(module, "load_security_tool_profile_summary", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(module, "load_playbook_definitions_summary", lambda: {})
    monkeypatch.setattr(module, "evaluate_acceptance", lambda **_kwargs: expected_result)
    monkeypatch.setattr(module, "print_human_result", lambda result: printed.append(result))

    result = module.main()

    assert result == 1
    assert printed == [expected_result]
