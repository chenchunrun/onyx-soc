from __future__ import annotations

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Any
import json
import os
from pathlib import Path
from sqlalchemy.orm import Mapper

from fastapi import APIRouter
from fastapi import Depends
from pydantic import BaseModel
from ee.onyx.configs.app_configs import CLOUD_DATA_PLANE_URL
from ee.onyx.configs.app_configs import LICENSE_ENFORCEMENT_ENABLED
from ee.onyx.db.license import get_license_metadata
from ee.onyx.server.enterprise_settings.store import load_settings as load_enterprise_settings
from onyx.configs.constants import MessageType
from onyx.configs.constants import QueryHistoryType
from onyx.configs.app_configs import ENCRYPTION_KEY_SECRET
from onyx.configs.app_configs import ONYX_QUERY_HISTORY_TYPE
from onyx.configs.constants import ONYX_DEFAULT_APPLICATION_NAME
from onyx.configs.constants import TokenRateLimitScope
from onyx.db.enums import AccessType
from onyx.db.enums import AccountType
from onyx.db.enums import GrantSource
from onyx.db.enums import Permission
from onyx.db.enums import TaskStatus
from sqlalchemy import case
from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy.orm import aliased
from sqlalchemy.orm import Session
import yaml

from onyx.auth.users import current_admin_user
from onyx.configs.constants import PUBLIC_API_TAGS
from onyx.db.document_set import get_document_set_by_name
from onyx.db.engine.sql_engine import get_session
from onyx.db.models import ChatMessage
from onyx.db.models import ChatSession
from onyx.db.models import ConnectorCredentialPair
from onyx.db.models import DocPermissionSyncAttempt
from onyx.db.models import Document
from onyx.db.models import DocumentSet__User
from onyx.db.models import ExternalGroupPermissionSyncAttempt
from onyx.db.models import ApiKey
from onyx.db.models import Base
from onyx.db.models import ChatMessageFeedback
from onyx.db.models import EncryptedJson
from onyx.db.models import EncryptedString
from onyx.db.models import Hook
from onyx.db.models import HookExecutionLog
from onyx.db.models import PermissionGrant
from onyx.db.models import Persona
from onyx.db.models import Persona__User
from onyx.db.models import ScimGroupMapping
from onyx.db.models import ScimToken
from onyx.db.models import ScimUserMapping
from onyx.db.models import TaskQueueState
from onyx.db.models import TokenRateLimit
from onyx.db.models import TokenRateLimit__UserGroup
from onyx.db.models import Tool
from onyx.db.models import ToolCall
from onyx.db.models import User
from onyx.db.models import User__UserGroup
from onyx.db.models import UserGroup
from onyx.db.persona import get_personas
from onyx.db.tools import get_tools
from onyx.hooks.registry import get_all_specs
from shared_configs.configs import MULTI_TENANT


router = APIRouter(prefix="/manage/admin/security-platform", tags=PUBLIC_API_TAGS)
SNAPSHOT_PATH = Path(__file__).resolve().parent / "static_snapshot.json"
ROOT_PATH = Path(__file__).resolve().parents[5]
INTEGRATIONS_DIR = Path(__file__).resolve().parent / "tool_configs"
INTEGRATION_PROFILES_PATH = INTEGRATIONS_DIR / "profiles.yaml"

SECURITY_DOCUMENT_SET_NAME = "安全知识库"
SECURITY_PERSONA_NAMES = {
    "安全事件分析师",
    "应急响应指挥官",
    "漏洞评估专家",
    "合规审计员",
    "威胁狩猎工程师",
    "恶意软件分析师",
    "检测工程师",
}
SECURITY_USER_EMAILS = {
    "commander@security.local",
    "analyst@security.local",
    "vuln_expert@security.local",
    "auditor@security.local",
    "hunter@security.local",
    "malware@security.local",
    "detection@security.local",
}
SECURITY_TOOL_NAMES = {
    "create_security_ticket",
    "send_security_alert",
    "threat_intel_lookup",
    "search_security_alerts",
    "isolate_endpoint_host",
    "lookup_asset_context",
}
TEMPLATE_HEADER_KEYS = {
    "security_alert_webhook": None,
    "security_ticket_api": "Authorization",
    "threat_intel_api": "x-apikey",
    "siem_search_api": "Authorization",
    "edr_response_api": "Authorization",
    "asset_inventory_api": "Authorization",
}

DEPLOYMENT_PROFILES: dict[str, dict[str, Any]] = {
    "live": {
        "required_env": [
            "SECURITY_ALERT_WEBHOOK_URL",
            "SECURITY_TICKET_API_URL",
            "SECURITY_TICKET_API_KEY",
            "THREAT_INTEL_API_URL",
            "THREAT_INTEL_API_KEY",
            "SECURITY_SIEM_API_URL",
            "SECURITY_SIEM_API_KEY",
            "SECURITY_EDR_API_URL",
            "SECURITY_EDR_API_KEY",
            "SECURITY_ASSET_API_URL",
            "SECURITY_ASSET_API_KEY",
        ],
        "threat_intel_source_profile": "live",
        "security_tools_profile": "live",
    },
    "demo": {
        "required_env": [
            "SECURITY_TOOLS_MOCK_SERVER_URL",
            "SECURITY_TOOLS_MOCK_API_KEY",
        ],
        "threat_intel_source_profile": "mock",
        "security_tools_profile": "mock",
    },
}


class SecurityPlatformPersonaStatus(BaseModel):
    id: int
    name: str
    is_public: bool
    tool_count: int
    document_set_count: int
    shared_user_count: int


class SecurityPlatformToolStatus(BaseModel):
    id: int
    name: str
    enabled: bool
    server_url: str | None
    header_keys: list[str]
    persona_names: list[str]


class SecurityPlatformUserStatus(BaseModel):
    email: str
    role: str
    is_active: bool


class SecurityPlatformDocumentSetStatus(BaseModel):
    id: int | None
    name: str
    exists: bool
    is_public: bool | None
    shared_user_count: int


class SecurityPlatformToolAuditEntry(BaseModel):
    tool_name: str
    persona_name: str | None
    user_email: str | None
    time_sent: str | None
    turn_number: int
    is_nested: bool


class SecurityPlatformToolAuditSummary(BaseModel):
    total_calls: int
    recent_call_count: int
    tool_counts: dict[str, int]
    persona_counts: dict[str, int]
    recent_calls: list[SecurityPlatformToolAuditEntry]


class SecurityPlatformToolDriftEntry(BaseModel):
    tool_name: str
    declared_persona_names: list[str]
    actual_persona_names: list[str]
    expected_server_url: str | None
    actual_server_url: str | None
    expected_header_keys: list[str]
    actual_header_keys: list[str]
    issues: list[str]


class SecurityPlatformToolDriftSummary(BaseModel):
    mismatch_count: int
    missing_declared_configs: list[str]
    mismatched_tools: list[SecurityPlatformToolDriftEntry]


class SecurityPlatformFailureEntry(BaseModel):
    persona_name: str | None
    user_email: str | None
    time_sent: str | None
    error: str


class SecurityPlatformFailureSummary(BaseModel):
    total_failures: int
    recent_failure_count: int
    recent_failures: list[SecurityPlatformFailureEntry]


class SecurityPlatformPermissionSyncAttemptEntry(BaseModel):
    attempt_id: int
    sync_type: str
    cc_pair_id: int | None
    status: str
    error_message: str | None
    time_created: str | None
    time_finished: str | None


class SecurityPlatformPermissionInheritanceSummary(BaseModel):
    sync_cc_pair_count: int
    docs_with_external_acl_count: int
    docs_with_user_acl_count: int
    docs_with_group_acl_count: int
    recent_doc_sync_failure_count: int
    recent_group_sync_failure_count: int
    recent_doc_sync_attempts: list[SecurityPlatformPermissionSyncAttemptEntry]
    recent_group_sync_attempts: list[SecurityPlatformPermissionSyncAttemptEntry]


class SecurityPlatformRbacSummary(BaseModel):
    persona_user_links: int
    document_set_user_links: int
    all_user_role_counts: dict[str, int]
    security_user_role_counts: dict[str, int]
    user_group_count: int
    groups_with_permission_grants_count: int
    permission_grant_count: int
    users_with_effective_permissions_count: int
    curator_membership_count: int
    top_permissions: dict[str, int]


def _normalize_role_name(raw_role: str) -> str:
    return raw_role.split(".")[-1].lower() if "." in raw_role else raw_role.lower()


class SecurityPlatformServiceAccountEntry(BaseModel):
    api_key_id: int
    api_key_name: str | None
    api_key_display: str
    role: str
    owner_email: str | None
    created_at: str | None


class SecurityPlatformServiceAccountSummary(BaseModel):
    api_key_count: int
    service_account_user_count: int
    ownerless_api_key_count: int
    role_counts: dict[str, int]
    recent_accounts: list[SecurityPlatformServiceAccountEntry]


class SecurityPlatformScimSummary(BaseModel):
    active_token_count: int
    has_active_token: bool
    token_last_used_at: str | None
    user_mapping_count: int
    group_mapping_count: int
    recent_group_sync_failure_count: int


class SecurityPlatformQueryUsageExportEntry(BaseModel):
    task_id: str
    status: str
    start_time: str | None


class SecurityPlatformQueryUsageSummary(BaseModel):
    query_history_type: str
    query_history_enabled: bool
    recent_query_count: int
    recent_chat_session_count: int
    recent_active_user_count: int
    recent_like_count: int
    recent_dislike_count: int
    recent_export_count: int
    recent_export_failure_count: int
    recent_exports: list[SecurityPlatformQueryUsageExportEntry]


class SecurityPlatformCustomPermissionSummary(BaseModel):
    default_group_count: int
    custom_group_count: int
    stale_custom_group_count: int
    groups_with_custom_grants_count: int
    custom_permission_count: int
    manual_grant_count: int
    scim_grant_count: int
    admin_override_group_count: int
    permission_counts: dict[str, int]


class SecurityPlatformUsageLimitSummary(BaseModel):
    enabled: bool
    global_limit_count: int
    enabled_global_limit_count: int
    user_limit_count: int
    enabled_user_limit_count: int
    user_group_limit_count: int
    enabled_user_group_limit_count: int
    limited_user_group_count: int


class SecurityPlatformHookExecutionEntry(BaseModel):
    hook_name: str
    hook_point: str
    is_success: bool
    status_code: int | None
    error_message: str | None
    created_at: str | None


class SecurityPlatformHookSummary(BaseModel):
    hooks_enabled: bool
    supported_hook_point_count: int
    configured_hook_count: int
    active_hook_count: int
    reachable_hook_count: int
    recent_execution_count: int
    recent_failure_count: int
    hook_point_names: list[str]
    recent_executions: list[SecurityPlatformHookExecutionEntry]


class SecurityPlatformCustomThemingSummary(BaseModel):
    branding_configured: bool
    application_name: str
    application_name_is_default: bool
    use_custom_logo: bool
    use_custom_logotype: bool
    logo_display_style: str
    custom_nav_item_count: int
    custom_header_content_enabled: bool
    custom_lower_disclaimer_enabled: bool
    first_visit_notice_enabled: bool
    custom_popup_enabled: bool
    consent_screen_enabled: bool
    custom_greeting_enabled: bool


class SecurityPlatformWhiteLabelingSummary(BaseModel):
    branding_configured: bool
    custom_logo_enabled: bool
    custom_favicon_enabled: bool
    application_name_configured: bool
    white_label_ready: bool
    residual_branding_count: int
    residual_external_link_count: int
    residual_branding_examples: list[str]


class SecurityPlatformCustomDeploymentSummary(BaseModel):
    docker_compose_variant_count: int
    helm_values_variant_count: int
    has_install_script: bool
    has_multitenant_compose: bool
    has_lite_compose: bool
    has_prod_compose: bool
    has_security_platform_compose_overlay: bool
    has_security_platform_helm_overlay: bool
    supported_modes: list[str]
    overlay_examples: list[str]


class SecurityPlatformRegionProcessingSummary(BaseModel):
    aws_region_supported: bool
    object_store_endpoint_configurable: bool
    web_domain_configurable: bool
    tenant_aware_deployment_supported: bool
    cloud_deployment_supported: bool
    region_hint_count: int
    region_hints: list[str]


class SecurityPlatformSelfHostingSummary(BaseModel):
    self_hosted_mode: bool
    multi_tenant_mode: bool
    enterprise_features_enabled: bool
    license_enforcement_enabled: bool
    has_license: bool
    license_status: str | None
    license_source: str | None
    seat_count: int | None
    used_seat_count: int | None
    has_license_api: bool
    has_admin_billing_page: bool
    has_billing_service: bool
    has_cloud_proxy: bool
    cloud_data_plane_url_configured: bool
    has_install_script: bool
    has_docker_compose_path: bool
    has_helm_install_path: bool


def build_secrets_encryption_summary(
    *,
    enabled: bool,
    encrypted_columns: list[str],
    rotation_script_available: bool,
) -> SecurityPlatformSecretsEncryptionSummary:
    model_names = {column.split(".", 1)[0] for column in encrypted_columns}
    return SecurityPlatformSecretsEncryptionSummary(
        enabled=enabled,
        encrypted_model_count=len(model_names),
        encrypted_column_count=len(encrypted_columns),
        encrypted_columns=sorted(encrypted_columns),
        rotation_script_available=rotation_script_available,
    )


class SecurityPlatformSecretsEncryptionSummary(BaseModel):
    enabled: bool
    encrypted_model_count: int
    encrypted_column_count: int
    encrypted_columns: list[str]
    rotation_script_available: bool


class SecurityPlatformRuntimeStatus(BaseModel):
    deployment_profile: str
    expected_profiles: dict[str, str]
    required_env: list[str]
    missing_required_env: list[str]
    placeholder_required_env: list[str]
    deployment_profile_issues: list[str]
    threat_intel_source_profile: str
    security_tools_profile: str
    threat_intel_sync: dict[str, Any]
    threat_intel_corpus: dict[str, Any]
    historical_packages: dict[str, Any]
    playbooks: dict[str, Any]
    health: dict[str, Any]
    recommended_next_actions: list[str]
    remediation_commands: list[str]
    document_set: SecurityPlatformDocumentSetStatus
    personas: list[SecurityPlatformPersonaStatus]
    tools: list[SecurityPlatformToolStatus]
    tool_audit: SecurityPlatformToolAuditSummary
    tool_drift: SecurityPlatformToolDriftSummary
    failure_summary: SecurityPlatformFailureSummary
    permission_inheritance: SecurityPlatformPermissionInheritanceSummary
    service_accounts: SecurityPlatformServiceAccountSummary
    scim: SecurityPlatformScimSummary
    query_history_usage: SecurityPlatformQueryUsageSummary
    custom_permissions: SecurityPlatformCustomPermissionSummary
    usage_limits: SecurityPlatformUsageLimitSummary
    hooks: SecurityPlatformHookSummary
    custom_theming: SecurityPlatformCustomThemingSummary
    white_labeling: SecurityPlatformWhiteLabelingSummary
    custom_deployments: SecurityPlatformCustomDeploymentSummary
    region_processing: SecurityPlatformRegionProcessingSummary
    self_hosting: SecurityPlatformSelfHostingSummary
    secrets_encryption: SecurityPlatformSecretsEncryptionSummary
    security_users: list[SecurityPlatformUserStatus]
    rbac: SecurityPlatformRbacSummary


def _health_check(
    name: str,
    status: str,
    summary: str,
    issues: list[str] | None = None,
    remediations: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "summary": summary,
        "issues": issues or [],
        "remediations": remediations or [],
    }


def build_health_status(
    *,
    profile_name: str,
    expected_threat_profile: str,
    expected_tools_profile: str,
    threat_intel_source_profile: str,
    security_tools_profile: str,
    required_env: list[str],
    missing_required_env: list[str],
    placeholder_required_env: list[str] | None = None,
    deployment_profile_issues: list[str],
    document_set_status: SecurityPlatformDocumentSetStatus,
    personas: list[SecurityPlatformPersonaStatus],
    tools: list[SecurityPlatformToolStatus],
    security_users: list[SecurityPlatformUserStatus],
    persona_user_links: int,
    document_set_user_links: int,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    placeholder_required_env = placeholder_required_env or []

    deployment_issues = list(deployment_profile_issues)
    if threat_intel_source_profile != expected_threat_profile:
        deployment_issues.append(
            f"Threat-intel source profile mismatch: expected {expected_threat_profile}, got {threat_intel_source_profile}"
        )
    if security_tools_profile != expected_tools_profile:
        deployment_issues.append(
            f"Security tools profile mismatch: expected {expected_tools_profile}, got {security_tools_profile}"
        )
    checks.append(
        _health_check(
            name="deployment_profile",
            status=(
                "failing"
                if (missing_required_env or placeholder_required_env or deployment_issues)
                else "healthy"
            ),
            summary=(
                f"profile={profile_name}, required_env={len(required_env)}, "
                f"missing_env={len(missing_required_env)}, "
                f"placeholder_env={len(placeholder_required_env)}"
            ),
            issues=missing_required_env + deployment_issues,
            remediations=[
                "Fill the missing required env vars for the selected deployment profile.",
                *(
                    [
                        "For demo deployments in Docker, use host.docker.internal for SECURITY_TOOLS_MOCK_SERVER_URL."
                    ]
                    if profile_name == "demo"
                    else []
                ),
            ],
        )
    )

    document_set_issues: list[str] = []
    if not document_set_status.exists:
        document_set_issues.append(f"Missing document set: {SECURITY_DOCUMENT_SET_NAME}")
    if document_set_status.shared_user_count < len(SECURITY_USER_EMAILS):
        document_set_issues.append(
            f"Document set user links below expected baseline: {document_set_status.shared_user_count}/{len(SECURITY_USER_EMAILS)}"
        )
    checks.append(
        _health_check(
            name="document_set",
            status="failing" if document_set_issues else "healthy",
            summary=f"exists={document_set_status.exists}, shared_users={document_set_status.shared_user_count}",
            issues=document_set_issues,
            remediations=[
                "Run setup_security_document_set.py and provision_security_team.py to recreate document set links."
            ],
        )
    )

    persona_issues: list[str] = []
    persona_names = {persona.name for persona in personas}
    missing_personas = sorted(SECURITY_PERSONA_NAMES - persona_names)
    if missing_personas:
        persona_issues.append(f"Missing personas: {', '.join(missing_personas)}")
    public_personas = sorted(persona.name for persona in personas if persona.is_public)
    if public_personas:
        persona_issues.append(f"Personas must be private: {', '.join(public_personas)}")
    checks.append(
        _health_check(
            name="personas",
            status="failing" if persona_issues else "healthy",
            summary=f"count={len(personas)}, expected={len(SECURITY_PERSONA_NAMES)}",
            issues=persona_issues,
            remediations=[
                "Run setup_security_personas.py --apply to recreate or update the standard security personas."
            ],
        )
    )

    tool_issues: list[str] = []
    tool_names = {tool.name for tool in tools}
    missing_tools = sorted(SECURITY_TOOL_NAMES - tool_names)
    if missing_tools:
        tool_issues.append(f"Missing tools: {', '.join(missing_tools)}")
    disabled_tools = sorted(tool.name for tool in tools if not tool.enabled)
    if disabled_tools:
        tool_issues.append(f"Disabled tools: {', '.join(disabled_tools)}")
    tools_without_server = sorted(
        tool.name for tool in tools if tool.server_url is None or not tool.server_url.strip()
    )
    if tools_without_server:
        tool_issues.append(f"Tools missing server_url: {', '.join(tools_without_server)}")
    checks.append(
        _health_check(
            name="tools",
            status="failing" if tool_issues else "healthy",
            summary=f"count={len(tools)}, expected={len(SECURITY_TOOL_NAMES)}",
            issues=tool_issues,
            remediations=[
                "Run setup_security_tools.py --apply with the target profile to recreate and realign tool configuration."
            ],
        )
    )

    rbac_issues: list[str] = []
    if len(security_users) != len(SECURITY_USER_EMAILS):
        rbac_issues.append(
            f"Security user count mismatch: {len(security_users)}/{len(SECURITY_USER_EMAILS)}"
        )
    non_web_roles = sorted(
        user.email for user in security_users if user.role.split(".")[-1].lower() in {"limited", "slack_user", "ext_perm_user"}
    )
    if non_web_roles:
        rbac_issues.append(
            f"Security users must use web-login roles: {', '.join(non_web_roles)}"
        )
    if persona_user_links < len(SECURITY_USER_EMAILS):
        rbac_issues.append(
            f"Persona__user links below expected baseline: {persona_user_links}/{len(SECURITY_USER_EMAILS)}"
        )
    if document_set_user_links < len(SECURITY_USER_EMAILS):
        rbac_issues.append(
            f"DocumentSet__user links below expected baseline: {document_set_user_links}/{len(SECURITY_USER_EMAILS)}"
        )
    checks.append(
        _health_check(
            name="rbac",
            status="failing" if rbac_issues else "healthy",
            summary=f"users={len(security_users)}, persona_links={persona_user_links}, docset_links={document_set_user_links}",
            issues=rbac_issues,
            remediations=[
                "Run provision_security_team.py --apply to restore security users and RBAC links."
            ],
        )
    )

    threat_sync = snapshot.get("threat_intel_sync", {})
    threat_corpus = snapshot.get("threat_intel_corpus", {})
    historical_packages = snapshot.get("historical_packages", {})
    threat_issues: list[str] = []
    if str(threat_sync.get("source_profile", "unknown")) != threat_intel_source_profile:
        threat_issues.append(
            f"Threat-intel snapshot/profile mismatch: snapshot={threat_sync.get('source_profile')}, runtime={threat_intel_source_profile}"
        )
    if int(threat_corpus.get("promotion_candidates", 0) or 0) > 0:
        threat_issues.append(
            f"Threat-intel promotion candidates remain: {threat_corpus.get('promotion_candidates', 0)}"
        )
    if int(threat_corpus.get("manual_review", 0) or 0) > 0:
        threat_issues.append(
            f"Threat-intel manual review items remain: {threat_corpus.get('manual_review', 0)}"
        )
    threat_status = "healthy"
    if threat_issues:
        threat_status = "failing"
    elif str(threat_sync.get("due_status", "UNKNOWN")) == "DUE":
        threat_status = "warning"
    checks.append(
        _health_check(
            name="threat_intel",
            status=threat_status,
            summary=(
                f"sync={threat_sync.get('due_status', 'UNKNOWN')}, "
                f"governed={threat_corpus.get('governed', 0)}, "
                f"unmanaged={threat_corpus.get('unmanaged', 0)}"
            ),
            issues=threat_issues,
            remediations=[
                "Run setup_security_threat_intel.py --verify or the scheduled sync wrapper to refresh threat-intel state.",
                "Promote governed corpus candidates before treating the platform as release-ready."
            ],
        )
    )

    historical_package_issues: list[str] = []
    historical_package_count = int(
        historical_packages.get("package_count", 0) or 0
    )
    historical_package_items = int(
        historical_packages.get("total_item_count", 0) or 0
    )
    package_ids = historical_packages.get("package_ids", [])
    if not isinstance(package_ids, list):
        package_ids = []
    consistency = historical_packages.get("consistency", {})
    if not isinstance(consistency, dict):
        consistency = {}
    consistency_summary = consistency.get("summary", {})
    if not isinstance(consistency_summary, dict):
        consistency_summary = {}
    if historical_package_count != len(package_ids):
        historical_package_issues.append(
            "Historical package catalog summary does not match package id count"
        )
    if historical_package_count > 0 and historical_package_items <= 0:
        historical_package_issues.append(
            "Historical package catalog reports packages but zero archived items"
        )
    if not bool(consistency.get("ok", True)):
        for issue in consistency.get("issues", []) or []:
            historical_package_issues.append(f"Catalog consistency issue: {issue}")
    checks.append(
        _health_check(
            name="historical_packages",
            status="failing" if historical_package_issues else "healthy",
            summary=(
                f"packages={historical_package_count}, "
                f"items={historical_package_items}, "
                f"consistent={consistency_summary.get('consistent_package_count', historical_package_count)}"
            ),
            issues=historical_package_issues,
            remediations=[
                "Run build_threat_intel_historical_package_index.py --write-index to rebuild the historical package catalog.",
                "Run check_threat_intel_historical_package_consistency.py --json to inspect catalog/package drift.",
            ],
        )
    )

    playbooks = snapshot.get("playbooks", {})
    playbook_issues: list[str] = []
    if int(playbooks.get("count", 0) or 0) < 2:
        playbook_issues.append(
            f"Playbook count below expected baseline: {playbooks.get('count', 0)}/2"
        )
    if int(playbooks.get("with_examples", 0) or 0) < int(playbooks.get("count", 0) or 0):
        playbook_issues.append(
            f"Playbooks missing example inputs: {int(playbooks.get('count', 0) or 0) - int(playbooks.get('with_examples', 0) or 0)}"
        )
    checks.append(
        _health_check(
            name="playbooks",
            status="failing" if playbook_issues else "healthy",
            summary=f"count={playbooks.get('count', 0)}, with_examples={playbooks.get('with_examples', 0)}",
            issues=playbook_issues,
            remediations=[
                "Run run_security_playbook.py --verify-definitions and restore any missing playbook YAML definitions."
            ],
        )
    )

    permission_inheritance = snapshot.get("permission_inheritance", {})
    permission_issues: list[str] = []
    sync_cc_pair_count = int(permission_inheritance.get("sync_cc_pair_count", 0) or 0)
    docs_with_external_acl_count = int(
        permission_inheritance.get("docs_with_external_acl_count", 0) or 0
    )
    recent_doc_sync_failure_count = int(
        permission_inheritance.get("recent_doc_sync_failure_count", 0) or 0
    )
    recent_group_sync_failure_count = int(
        permission_inheritance.get("recent_group_sync_failure_count", 0) or 0
    )
    if sync_cc_pair_count > 0 and docs_with_external_acl_count <= 0:
        permission_issues.append(
            "SYNC connectors exist but no documents currently carry external ACL metadata"
        )
    if recent_doc_sync_failure_count > 0:
        permission_issues.append(
            f"Recent doc permission sync failures observed: {recent_doc_sync_failure_count}"
        )
    if recent_group_sync_failure_count > 0:
        permission_issues.append(
            f"Recent external group sync failures observed: {recent_group_sync_failure_count}"
        )
    checks.append(
        _health_check(
            name="permission_inheritance",
            status="failing" if permission_issues else "healthy",
            summary=(
                f"sync_cc_pairs={sync_cc_pair_count}, "
                f"docs_with_acl={docs_with_external_acl_count}, "
                f"doc_failures={recent_doc_sync_failure_count}, "
                f"group_failures={recent_group_sync_failure_count}"
            ),
            issues=permission_issues,
            remediations=[
                "Inspect recent permission sync attempts for failing connectors and rerun connector permission sync if needed."
            ],
        )
    )

    service_accounts = snapshot.get("service_accounts", {})
    service_account_issues: list[str] = []
    api_key_count = int(service_accounts.get("api_key_count", 0) or 0)
    service_account_user_count = int(
        service_accounts.get("service_account_user_count", 0) or 0
    )
    ownerless_api_key_count = int(
        service_accounts.get("ownerless_api_key_count", 0) or 0
    )
    if api_key_count != service_account_user_count:
        service_account_issues.append(
            f"API key count and service-account user count diverge: {api_key_count}/{service_account_user_count}"
        )
    if ownerless_api_key_count > 0:
        service_account_issues.append(
            f"Ownerless service account API keys detected: {ownerless_api_key_count}"
        )
    checks.append(
        _health_check(
            name="service_accounts",
            status="failing" if service_account_issues else "healthy",
            summary=(
                f"api_keys={api_key_count}, "
                f"service_users={service_account_user_count}, "
                f"ownerless={ownerless_api_key_count}"
            ),
            issues=service_account_issues,
            remediations=[
                "Inspect the Service Accounts admin page and reconcile orphaned or mismatched service account records."
            ],
        )
    )

    scim = snapshot.get("scim", {})
    scim_issues: list[str] = []
    active_token_count = int(scim.get("active_token_count", 0) or 0)
    user_mapping_count = int(scim.get("user_mapping_count", 0) or 0)
    group_mapping_count = int(scim.get("group_mapping_count", 0) or 0)
    recent_group_sync_failure_count = int(
        scim.get("recent_group_sync_failure_count", 0) or 0
    )
    if active_token_count > 1:
        scim_issues.append(f"Multiple active SCIM tokens detected: {active_token_count}")
    if group_mapping_count > user_mapping_count and user_mapping_count == 0:
        scim_issues.append(
            "SCIM group mappings exist without any SCIM user mappings"
        )
    if recent_group_sync_failure_count > 0:
        scim_issues.append(
            f"Recent external group sync failures observed: {recent_group_sync_failure_count}"
        )
    checks.append(
        _health_check(
            name="scim",
            status="failing" if scim_issues else "healthy",
            summary=(
                f"active_tokens={active_token_count}, "
                f"user_mappings={user_mapping_count}, "
                f"group_mappings={group_mapping_count}"
            ),
            issues=scim_issues,
            remediations=[
                "Inspect the SCIM admin page, ensure only one active token exists, and rerun any failing external group sync."
            ],
        )
    )

    secrets_encryption = snapshot.get("secrets_encryption", {})
    encryption_issues: list[str] = []
    encryption_enabled = bool(secrets_encryption.get("enabled", False))
    encrypted_column_count = int(
        secrets_encryption.get("encrypted_column_count", 0) or 0
    )
    rotation_script_available = bool(
        secrets_encryption.get("rotation_script_available", False)
    )
    if not encryption_enabled:
        encryption_issues.append("ENCRYPTION_KEY_SECRET is not configured")
    if encrypted_column_count <= 0:
        encryption_issues.append("No encrypted ORM columns were discovered")
    if not rotation_script_available:
        encryption_issues.append("Encryption key rotation script is missing")
    checks.append(
        _health_check(
            name="secrets_encryption",
            status="failing" if encryption_issues else "healthy",
            summary=(
                f"enabled={encryption_enabled}, "
                f"encrypted_columns={encrypted_column_count}, "
                f"rotation_script={rotation_script_available}"
            ),
            issues=encryption_issues,
            remediations=[
                "Set ENCRYPTION_KEY_SECRET for the deployment and use backend/onyx/db/rotate_encryption_key.py when rotating secrets."
            ],
        )
    )

    query_history_usage = snapshot.get("query_history_usage", {})
    query_usage_issues: list[str] = []
    query_history_enabled = bool(
        query_history_usage.get("query_history_enabled", False)
    )
    recent_query_count = int(query_history_usage.get("recent_query_count", 0) or 0)
    recent_active_user_count = int(
        query_history_usage.get("recent_active_user_count", 0) or 0
    )
    recent_export_failure_count = int(
        query_history_usage.get("recent_export_failure_count", 0) or 0
    )
    if not query_history_enabled:
        query_usage_issues.append("Query history is disabled")
    if recent_export_failure_count > 0:
        query_usage_issues.append(
            f"Recent query history export failures observed: {recent_export_failure_count}"
        )
    query_usage_status = "healthy"
    if query_usage_issues:
        query_usage_status = "failing"
    elif recent_query_count <= 0:
        query_usage_status = "warning"
    checks.append(
        _health_check(
            name="query_history_usage",
            status=query_usage_status,
            summary=(
                f"type={query_history_usage.get('query_history_type', 'unknown')}, "
                f"queries_30d={recent_query_count}, "
                f"active_users_30d={recent_active_user_count}"
            ),
            issues=query_usage_issues,
            remediations=[
                "Enable query history in settings and inspect /admin/performance/query-history plus /admin/performance/usage for export or analytics issues."
            ],
        )
    )

    custom_permissions = snapshot.get("custom_permissions", {})
    custom_permission_issues: list[str] = []
    stale_custom_group_count = int(
        custom_permissions.get("stale_custom_group_count", 0) or 0
    )
    admin_override_group_count = int(
        custom_permissions.get("admin_override_group_count", 0) or 0
    )
    if stale_custom_group_count > 0:
        custom_permission_issues.append(
            f"Custom permission groups pending sync detected: {stale_custom_group_count}"
        )
    custom_permission_status = "healthy"
    if custom_permission_issues:
        custom_permission_status = "failing"
    elif admin_override_group_count > 0:
        custom_permission_status = "warning"
        custom_permission_issues.append(
            f"Groups with full admin override permission detected: {admin_override_group_count}"
        )
    checks.append(
        _health_check(
            name="custom_permissions",
            status=custom_permission_status,
            summary=(
                f"custom_groups={custom_permissions.get('custom_group_count', 0)}, "
                f"custom_permissions={custom_permissions.get('custom_permission_count', 0)}, "
                f"manual_grants={custom_permissions.get('manual_grant_count', 0)}"
            ),
            issues=custom_permission_issues,
            remediations=[
                "Inspect the Groups admin page and reconcile stale group sync or overly broad admin permission grants."
            ],
        )
    )

    usage_limits = snapshot.get("usage_limits", {})
    usage_limit_issues: list[str] = []
    usage_limits_enabled = bool(usage_limits.get("enabled", False))
    enabled_global_limit_count = int(
        usage_limits.get("enabled_global_limit_count", 0) or 0
    )
    enabled_user_limit_count = int(
        usage_limits.get("enabled_user_limit_count", 0) or 0
    )
    enabled_user_group_limit_count = int(
        usage_limits.get("enabled_user_group_limit_count", 0) or 0
    )
    usage_limit_status = "healthy"
    if not usage_limits_enabled:
        usage_limit_status = "warning"
        usage_limit_issues.append("Usage limits are disabled")
    elif (
        enabled_global_limit_count <= 0
        and enabled_user_limit_count <= 0
        and enabled_user_group_limit_count <= 0
    ):
        usage_limit_status = "warning"
        usage_limit_issues.append("No enabled token rate limits configured")
    checks.append(
        _health_check(
            name="usage_limits",
            status=usage_limit_status,
            summary=(
                f"enabled={usage_limits_enabled}, "
                f"global={usage_limits.get('global_limit_count', 0)}, "
                f"user={usage_limits.get('user_limit_count', 0)}, "
                f"group={usage_limits.get('user_group_limit_count', 0)}"
            ),
            issues=usage_limit_issues,
            remediations=[
                "Inspect /admin/token-rate-limits and enable at least one appropriate global, user, or user-group rate limit."
            ],
        )
    )

    hooks = snapshot.get("hooks", {})
    hook_issues: list[str] = []
    hooks_enabled = bool(hooks.get("hooks_enabled", False))
    configured_hook_count = int(hooks.get("configured_hook_count", 0) or 0)
    active_hook_count = int(hooks.get("active_hook_count", 0) or 0)
    reachable_hook_count = int(hooks.get("reachable_hook_count", 0) or 0)
    recent_hook_failure_count = int(hooks.get("recent_failure_count", 0) or 0)
    hook_status = "healthy"
    if not hooks_enabled:
        hook_status = "warning"
        hook_issues.append("Hooks are unavailable in this deployment mode")
    elif configured_hook_count > 0 and active_hook_count > reachable_hook_count:
        hook_status = "failing"
        hook_issues.append(
            f"Active but unreachable hooks detected: {active_hook_count - reachable_hook_count}"
        )
    elif recent_hook_failure_count > 0:
        hook_status = "warning"
        hook_issues.append(
            f"Recent hook execution failures observed: {recent_hook_failure_count}"
        )
    checks.append(
        _health_check(
            name="hooks",
            status=hook_status,
            summary=(
                f"enabled={hooks_enabled}, "
                f"supported_points={hooks.get('supported_hook_point_count', 0)}, "
                f"configured={configured_hook_count}, "
                f"active={active_hook_count}"
            ),
            issues=hook_issues,
            remediations=[
                "Inspect /admin/hooks, validate configured endpoints, and review recent hook execution logs."
            ],
        )
    )

    custom_theming = snapshot.get("custom_theming", {})
    theming_issues: list[str] = []
    branding_configured = bool(custom_theming.get("branding_configured", False))
    use_custom_logo = bool(custom_theming.get("use_custom_logo", False))
    logo_display_style = str(
        custom_theming.get("logo_display_style", "logo_and_name") or "logo_and_name"
    )
    consent_screen_enabled = bool(
        custom_theming.get("consent_screen_enabled", False)
    )
    custom_popup_enabled = bool(custom_theming.get("custom_popup_enabled", False))
    if logo_display_style in {"logo_only", "logo_and_name"} and not use_custom_logo:
        theming_issues.append(
            "Logo display expects a custom logo, but use_custom_logo is disabled"
        )
    if consent_screen_enabled and not bool(
        custom_theming.get("consent_prompt_configured", False)
    ):
        theming_issues.append(
            "Consent screen is enabled, but consent_screen_prompt is not configured"
        )
    if bool(custom_theming.get("first_visit_notice_enabled", False)) and not bool(
        custom_theming.get("popup_content_configured", False)
    ):
        theming_issues.append(
            "First-visit notice is enabled, but popup header/content is incomplete"
        )
    theming_status = "healthy"
    if theming_issues:
        theming_status = "warning"
    checks.append(
        _health_check(
            name="custom_theming",
            status=theming_status,
            summary=(
                f"branding_configured={branding_configured}, "
                f"application_name={custom_theming.get('application_name', ONYX_DEFAULT_APPLICATION_NAME)}, "
                f"nav_items={custom_theming.get('custom_nav_item_count', 0)}"
            ),
            issues=theming_issues,
            remediations=[
                "Inspect /admin/theme and complete logo, notice, or consent-screen fields before treating branding as production-ready."
            ],
        )
    )

    white_labeling = snapshot.get("white_labeling", {})
    white_label_issues: list[str] = []
    branding_configured = bool(white_labeling.get("branding_configured", False))
    residual_branding_count = int(
        white_labeling.get("residual_branding_count", 0) or 0
    )
    residual_external_link_count = int(
        white_labeling.get("residual_external_link_count", 0) or 0
    )
    white_label_status = "healthy"
    if branding_configured and residual_branding_count > 0:
        white_label_status = "warning"
        white_label_issues.append(
            f"Branding is configured, but {residual_branding_count} residual Onyx UI traces remain"
        )
    if residual_external_link_count > 0:
        white_label_status = "warning"
        white_label_issues.append(
            f"Residual Onyx external links detected: {residual_external_link_count}"
        )
    checks.append(
        _health_check(
            name="white_labeling",
            status=white_label_status,
            summary=(
                f"configured={branding_configured}, "
                f"ready={bool(white_labeling.get('white_label_ready', False))}, "
                f"residual_traces={residual_branding_count}"
            ),
            issues=white_label_issues,
            remediations=[
                "Review login, signup, sidebar, footer, and bot-facing copy for remaining Onyx strings before claiming full white-labeling support."
            ],
        )
    )

    custom_deployments = snapshot.get("custom_deployments", {})
    deployment_issues: list[str] = []
    supported_modes = custom_deployments.get("supported_modes", [])
    if not custom_deployments.get("has_security_platform_compose_overlay", False):
        deployment_issues.append("Security-platform Docker Compose overlay is missing")
    if not custom_deployments.get("has_security_platform_helm_overlay", False):
        deployment_issues.append("Security-platform Helm overlay is missing")
    deployment_status = "healthy" if not deployment_issues else "warning"
    checks.append(
        _health_check(
            name="custom_deployments",
            status=deployment_status,
            summary=(
                f"compose_variants={custom_deployments.get('docker_compose_variant_count', 0)}, "
                f"helm_values={custom_deployments.get('helm_values_variant_count', 0)}, "
                f"modes={', '.join(supported_modes) if isinstance(supported_modes, list) and supported_modes else 'none'}"
            ),
            issues=deployment_issues,
            remediations=[
                "Keep Docker Compose and Helm overlays aligned for prod, lite, multitenant, and security-platform deployment paths."
            ],
        )
    )

    region_processing = snapshot.get("region_processing", {})
    region_issues: list[str] = []
    if not bool(region_processing.get("object_store_endpoint_configurable", False)):
        region_issues.append("Object-store endpoint is not configurable")
    if not bool(region_processing.get("aws_region_supported", False)):
        region_issues.append("AWS region-specific config hooks are not present")
    region_status = "healthy" if not region_issues else "warning"
    checks.append(
        _health_check(
            name="region_processing",
            status=region_status,
            summary=(
                f"aws_region={bool(region_processing.get('aws_region_supported', False))}, "
                f"tenant_aware={bool(region_processing.get('tenant_aware_deployment_supported', False))}, "
                f"cloud={bool(region_processing.get('cloud_deployment_supported', False))}"
            ),
            issues=region_issues,
            remediations=[
                "Keep S3/object-store endpoint, WEB_DOMAIN, and tenant-aware deployment options aligned if you need region-specific data handling."
            ],
        )
    )

    self_hosting = snapshot.get("self_hosting", {})
    self_hosting_issues: list[str] = []
    self_hosted_mode = bool(self_hosting.get("self_hosted_mode", not MULTI_TENANT))
    if self_hosted_mode and not bool(self_hosting.get("has_license_api", False)):
        self_hosting_issues.append("Self-hosted license API entrypoint is missing.")
    if self_hosted_mode and not (
        bool(self_hosting.get("has_install_script", False))
        or bool(self_hosting.get("has_helm_install_path", False))
    ):
        self_hosting_issues.append(
            "Self-hosted deployment entrypoints are missing install.sh/Helm support."
        )
    if self_hosted_mode and bool(
        self_hosting.get("license_enforcement_enabled", False)
    ) and not bool(self_hosting.get("has_license", False)):
        self_hosting_issues.append(
            "License enforcement is enabled but no local self-hosted license metadata is cached."
        )
    if self_hosted_mode and not bool(self_hosting.get("has_admin_billing_page", False)):
        self_hosting_issues.append("Self-hosted billing admin UI entrypoint is missing.")
    if self_hosted_mode and not bool(self_hosting.get("has_cloud_proxy", False)):
        self_hosting_issues.append(
            "Self-hosted cloud proxy endpoints are missing; claim/refresh flows may be unavailable."
        )
    checks.append(
        _health_check(
            name="self_hosting",
            status=(
                "failing"
                if any(
                    issue
                    for issue in self_hosting_issues
                    if "missing" in issue.lower() or "entrypoints" in issue.lower()
                )
                else "warning" if self_hosting_issues else "healthy"
            ),
            summary=(
                f"self_hosted={self_hosted_mode}, "
                f"license_enforcement={bool(self_hosting.get('license_enforcement_enabled', False))}, "
                f"has_license={bool(self_hosting.get('has_license', False))}, "
                f"install_script={bool(self_hosting.get('has_install_script', False))}, "
                f"helm={bool(self_hosting.get('has_helm_install_path', False))}"
            ),
            issues=self_hosting_issues,
            remediations=[
                "Keep at least one self-hosted install path available (install.sh or Helm values).",
                "If license enforcement is enabled, claim or upload a self-hosted license before rollout.",
            ],
        )
    )

    failing_checks = sum(1 for check in checks if check["status"] == "failing")
    warning_checks = sum(1 for check in checks if check["status"] == "warning")
    overall_status = "healthy"
    if failing_checks:
        overall_status = "failing"
    elif warning_checks:
        overall_status = "warning"

    return {
        "overall_status": overall_status,
        "failing_checks": failing_checks,
        "warning_checks": warning_checks,
        "checks": checks,
    }


def build_recommended_next_actions(health: dict[str, Any]) -> list[str]:
    actions: list[str] = []
    checks = health.get("checks", [])
    if not isinstance(checks, list):
        return actions

    for check in checks:
        if not isinstance(check, dict):
            continue
        status = str(check.get("status", ""))
        if status not in {"failing", "warning"}:
            continue
        remediations = check.get("remediations", [])
        if not isinstance(remediations, list):
            continue
        for remediation in remediations:
            action = str(remediation).strip()
            if action and action not in actions:
                actions.append(action)
        if len(actions) >= 4:
            break

    return actions


def build_remediation_commands(
    *,
    health: dict[str, Any],
    profile_name: str,
) -> list[str]:
    commands: list[str] = []
    checks = health.get("checks", [])
    if not isinstance(checks, list):
        return commands

    status_by_name = {
        str(check.get("name", "")): str(check.get("status", ""))
        for check in checks
        if isinstance(check, dict)
    }

    if status_by_name.get("deployment_profile") == "failing":
        if profile_name == "demo":
            commands.append(
                "SECURITY_PLATFORM_DEPLOYMENT_PROFILE=demo python knowledge-base/bootstrap_security_platform.py --verify"
            )
        else:
            commands.append(
                "SECURITY_PLATFORM_DEPLOYMENT_PROFILE=demo python knowledge-base/bootstrap_security_platform.py --verify"
            )

    if status_by_name.get("tools") == "failing":
        profile = "mock" if profile_name == "demo" else "live"
        commands.append(
            f"python knowledge-base/security-automation/setup_security_tools.py --apply --profile {profile}"
        )

    if status_by_name.get("threat_intel") in {"failing", "warning"}:
        commands.append(
            "python knowledge-base/setup_security_threat_intel.py --verify"
        )

    if status_by_name.get("historical_packages") == "failing":
        commands.append(
            "python knowledge-base/build_threat_intel_historical_package_index.py --write-index"
        )
        commands.append(
            "python knowledge-base/check_threat_intel_historical_package_consistency.py --json"
        )

    if status_by_name.get("playbooks") == "failing":
        commands.append(
            "python knowledge-base/run_security_playbook.py --verify-definitions"
        )

    if status_by_name.get("personas") == "failing":
        commands.append(
            "python knowledge-base/setup_security_personas.py --apply"
        )

    if status_by_name.get("document_set") == "failing":
        commands.append(
            "python knowledge-base/setup_security_document_set.py --apply"
        )

    if status_by_name.get("rbac") == "failing":
        commands.append(
            "python knowledge-base/sso-rbac/provision_security_team.py --apply"
        )

    if status_by_name.get("permission_inheritance") == "failing":
        commands.append(
            "Check connector permission sync attempts and rerun permission sync for affected connectors."
        )

    if status_by_name.get("scim") == "failing":
        commands.append(
            "Inspect /admin/scim and rerun the affected external group sync job for the failing connector."
        )

    if status_by_name.get("secrets_encryption") == "failing":
        commands.append(
            "Set ENCRYPTION_KEY_SECRET and run python backend/onyx/db/rotate_encryption_key.py with the prior key if secrets need re-encryption."
        )

    deduped: list[str] = []
    for command in commands:
        if command not in deduped:
            deduped.append(command)
    return deduped


def get_selected_profile() -> tuple[str, dict[str, Any]]:
    import os

    profile_name = str(os.environ.get("SECURITY_PLATFORM_DEPLOYMENT_PROFILE", "live"))
    profile = DEPLOYMENT_PROFILES.get(profile_name, DEPLOYMENT_PROFILES["live"])
    return profile_name, profile


def get_runtime_profile_value(env_name: str, default: str) -> str:
    import os

    return str(os.environ.get(env_name, default)).strip() or default


def get_missing_required_env(required_env: list[str]) -> list[str]:
    return [
        env_name
        for env_name in required_env
        if not str(os.environ.get(env_name, "")).strip()
    ]


def _looks_like_placeholder_value(env_name: str, env_value: str) -> bool:
    normalized = env_value.strip().lower()
    if not normalized:
        return False

    generic_markers = [
        "replace-me",
        "your-company",
        "example.com",
        "example.local",
        "changeme",
        "placeholder",
        "mock-api-key-for-testing",
    ]
    if any(marker in normalized for marker in generic_markers):
        return True

    if env_name.endswith("_API_KEY") and normalized in {"mock-api-key", "test-api-key"}:
        return True

    return False


def get_placeholder_required_env(required_env: list[str]) -> list[str]:
    placeholders: list[str] = []
    for env_name in required_env:
        env_value = str(os.environ.get(env_name, "")).strip()
        if _looks_like_placeholder_value(env_name, env_value):
            placeholders.append(env_name)
    return placeholders


def get_deployment_profile_issues(profile_name: str) -> list[str]:
    issues: list[str] = []
    mock_server_url = str(os.environ.get("SECURITY_TOOLS_MOCK_SERVER_URL", "")).strip()
    if (
        profile_name == "demo"
        and mock_server_url
        and ("localhost" in mock_server_url.lower() or "127.0.0.1" in mock_server_url)
    ):
        issues.append(
            "SECURITY_TOOLS_MOCK_SERVER_URL must use host.docker.internal in Docker-backed demo deployments"
        )
    return issues


def build_tool_status(tool: Tool) -> SecurityPlatformToolStatus:
    server_url = None
    if isinstance(tool.openapi_schema, dict):
        servers = tool.openapi_schema.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            url = servers[0].get("url")
            if isinstance(url, str) and url.strip():
                server_url = url.strip()

    header_keys: list[str] = []
    if isinstance(tool.custom_headers, list):
        for header in tool.custom_headers:
            if isinstance(header, dict):
                key = header.get("key")
                if isinstance(key, str) and key.strip():
                    header_keys.append(key.strip())

    persona_names = sorted(
        persona.name
        for persona in tool.personas
        if persona.name in SECURITY_PERSONA_NAMES
    )
    return SecurityPlatformToolStatus(
        id=tool.id,
        name=tool.name,
        enabled=tool.enabled,
        server_url=server_url,
        header_keys=sorted(header_keys),
        persona_names=persona_names,
    )


def build_tool_audit_summary(
    *,
    total_calls: int,
    tool_counts: dict[str, int],
    persona_counts: dict[str, int],
    recent_rows: list[Any],
) -> SecurityPlatformToolAuditSummary:
    recent_calls: list[SecurityPlatformToolAuditEntry] = []

    for row in recent_rows:
        time_sent = getattr(row, "time_sent", None)
        recent_calls.append(
            SecurityPlatformToolAuditEntry(
                tool_name=str(getattr(row, "tool_name", "unknown") or "unknown"),
                persona_name=getattr(row, "persona_name", None),
                user_email=getattr(row, "user_email", None),
                time_sent=time_sent.isoformat() if time_sent is not None else None,
                turn_number=int(getattr(row, "turn_number", 0) or 0),
                is_nested=bool(getattr(row, "parent_tool_call_id", None) is not None),
            )
        )

    return SecurityPlatformToolAuditSummary(
        total_calls=total_calls,
        recent_call_count=len(recent_calls),
        tool_counts=dict(sorted(tool_counts.items())),
        persona_counts=dict(sorted(persona_counts.items())),
        recent_calls=recent_calls,
    )


def load_integration_profiles() -> dict[str, Any]:
    if not INTEGRATION_PROFILES_PATH.exists():
        return {"profiles": {}}
    return yaml.safe_load(INTEGRATION_PROFILES_PATH.read_text(encoding="utf-8")) or {}


def load_declared_tool_configs(profile_name: str) -> dict[str, dict[str, Any]]:
    profiles_doc = load_integration_profiles()
    profiles = profiles_doc.get("profiles", {}) if isinstance(profiles_doc, dict) else {}
    profile = profiles.get(profile_name, {}) if isinstance(profiles, dict) else {}
    env_overrides = profile.get("env_overrides", {}) if isinstance(profile, dict) else {}

    declared_configs: dict[str, dict[str, Any]] = {}
    if not INTEGRATIONS_DIR.exists():
        return declared_configs

    for config_path in sorted(INTEGRATIONS_DIR.glob("*.yaml")):
        if config_path.name == INTEGRATION_PROFILES_PATH.name:
            continue
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            continue

        tool_name = str(config.get("name", "")).strip()
        if not tool_name:
            continue

        logical_env_name = str(
            config.get("api_url_env") or config.get("webhook_url_env") or ""
        ).strip()
        resolved_env_name = str(env_overrides.get(logical_env_name) or logical_env_name).strip()
        expected_server_url = (
            str(os.environ.get(resolved_env_name, "")).strip() if resolved_env_name else None
        )
        if expected_server_url == "":
            expected_server_url = None

        template_name = str(config.get("template", "")).strip()
        header_key = TEMPLATE_HEADER_KEYS.get(template_name)
        expected_header_keys = [header_key] if header_key else []

        declared_configs[tool_name] = {
            "persona_names": sorted(
                str(name).strip()
                for name in config.get("persona_bindings", [])
                if str(name).strip()
            ),
            "expected_server_url": expected_server_url,
            "expected_header_keys": sorted(expected_header_keys),
        }

    return declared_configs


def build_tool_drift_summary(
    declared_configs: dict[str, dict[str, Any]],
    tools: list[SecurityPlatformToolStatus],
) -> SecurityPlatformToolDriftSummary:
    actual_by_name = {tool.name: tool for tool in tools}
    missing_declared_configs = sorted(
        tool.name for tool in tools if tool.name not in declared_configs
    )

    mismatched_tools: list[SecurityPlatformToolDriftEntry] = []
    for tool_name, declared in sorted(declared_configs.items()):
        actual = actual_by_name.get(tool_name)
        if actual is None:
            continue

        declared_persona_names = sorted(
            str(name) for name in declared.get("persona_names", [])
        )
        actual_persona_names = sorted(actual.persona_names)
        expected_server_url = declared.get("expected_server_url")
        actual_server_url = actual.server_url
        expected_header_keys = sorted(
            str(name) for name in declared.get("expected_header_keys", [])
        )
        actual_header_keys = sorted(actual.header_keys)

        issues: list[str] = []
        if expected_server_url and expected_server_url != actual_server_url:
            issues.append(
                f"server_url drift: expected {expected_server_url}, got {actual_server_url or 'none'}"
            )
        if expected_header_keys != actual_header_keys:
            issues.append(
                "header drift: expected "
                + (", ".join(expected_header_keys) if expected_header_keys else "none")
                + ", got "
                + (", ".join(actual_header_keys) if actual_header_keys else "none")
            )
        if declared_persona_names != actual_persona_names:
            issues.append(
                "persona binding drift: expected "
                + (", ".join(declared_persona_names) if declared_persona_names else "none")
                + ", got "
                + (", ".join(actual_persona_names) if actual_persona_names else "none")
            )

        if issues:
            mismatched_tools.append(
                SecurityPlatformToolDriftEntry(
                    tool_name=tool_name,
                    declared_persona_names=declared_persona_names,
                    actual_persona_names=actual_persona_names,
                    expected_server_url=expected_server_url,
                    actual_server_url=actual_server_url,
                    expected_header_keys=expected_header_keys,
                    actual_header_keys=actual_header_keys,
                    issues=issues,
                )
            )

    return SecurityPlatformToolDriftSummary(
        mismatch_count=len(mismatched_tools),
        missing_declared_configs=missing_declared_configs,
        mismatched_tools=mismatched_tools,
    )


def build_failure_summary(
    *,
    total_failures: int,
    recent_rows: list[Any],
) -> SecurityPlatformFailureSummary:
    recent_failures: list[SecurityPlatformFailureEntry] = []
    for row in recent_rows:
        time_sent = getattr(row, "time_sent", None)
        error = str(getattr(row, "error", "") or "").strip()
        if not error:
            continue
        recent_failures.append(
            SecurityPlatformFailureEntry(
                persona_name=getattr(row, "persona_name", None),
                user_email=getattr(row, "user_email", None),
                time_sent=time_sent.isoformat() if time_sent is not None else None,
                error=error,
            )
        )

    return SecurityPlatformFailureSummary(
        total_failures=total_failures,
        recent_failure_count=len(recent_failures),
        recent_failures=recent_failures,
    )


def build_permission_inheritance_summary(
    *,
    sync_cc_pair_count: int,
    docs_with_external_acl_count: int,
    docs_with_user_acl_count: int,
    docs_with_group_acl_count: int,
    recent_doc_sync_failure_count: int,
    recent_group_sync_failure_count: int,
    recent_doc_sync_rows: list[Any],
    recent_group_sync_rows: list[Any],
) -> SecurityPlatformPermissionInheritanceSummary:
    def _build_attempt_rows(rows: list[Any], sync_type: str) -> list[SecurityPlatformPermissionSyncAttemptEntry]:
        attempts: list[SecurityPlatformPermissionSyncAttemptEntry] = []
        for row in rows:
            time_created = getattr(row, "time_created", None)
            time_finished = getattr(row, "time_finished", None)
            attempts.append(
                SecurityPlatformPermissionSyncAttemptEntry(
                    attempt_id=int(getattr(row, "id", 0) or 0),
                    sync_type=sync_type,
                    cc_pair_id=getattr(row, "connector_credential_pair_id", None),
                    status=str(getattr(row, "status", "UNKNOWN")),
                    error_message=getattr(row, "error_message", None),
                    time_created=time_created.isoformat() if time_created is not None else None,
                    time_finished=time_finished.isoformat() if time_finished is not None else None,
                )
            )
        return attempts

    return SecurityPlatformPermissionInheritanceSummary(
        sync_cc_pair_count=sync_cc_pair_count,
        docs_with_external_acl_count=docs_with_external_acl_count,
        docs_with_user_acl_count=docs_with_user_acl_count,
        docs_with_group_acl_count=docs_with_group_acl_count,
        recent_doc_sync_failure_count=recent_doc_sync_failure_count,
        recent_group_sync_failure_count=recent_group_sync_failure_count,
        recent_doc_sync_attempts=_build_attempt_rows(recent_doc_sync_rows, "document"),
        recent_group_sync_attempts=_build_attempt_rows(recent_group_sync_rows, "group"),
    )


def build_rbac_summary(
    *,
    persona_user_links: int,
    document_set_user_links: int,
    all_user_role_counts: dict[str, int],
    security_user_role_counts: dict[str, int],
    user_group_count: int,
    groups_with_permission_grants_count: int,
    permission_grant_count: int,
    users_with_effective_permissions_count: int,
    curator_membership_count: int,
    top_permissions: dict[str, int],
) -> SecurityPlatformRbacSummary:
    return SecurityPlatformRbacSummary(
        persona_user_links=persona_user_links,
        document_set_user_links=document_set_user_links,
        all_user_role_counts=dict(sorted(all_user_role_counts.items())),
        security_user_role_counts=dict(sorted(security_user_role_counts.items())),
        user_group_count=user_group_count,
        groups_with_permission_grants_count=groups_with_permission_grants_count,
        permission_grant_count=permission_grant_count,
        users_with_effective_permissions_count=users_with_effective_permissions_count,
        curator_membership_count=curator_membership_count,
        top_permissions=dict(sorted(top_permissions.items())),
    )


def build_service_account_summary(
    *,
    api_key_count: int,
    service_account_user_count: int,
    ownerless_api_key_count: int,
    role_counts: dict[str, int],
    recent_rows: list[Any],
) -> SecurityPlatformServiceAccountSummary:
    recent_accounts: list[SecurityPlatformServiceAccountEntry] = []
    for row in recent_rows:
        created_at = getattr(row, "created_at", None)
        raw_role = str(getattr(row, "service_role", "") or "")
        recent_accounts.append(
            SecurityPlatformServiceAccountEntry(
                api_key_id=int(getattr(row, "api_key_id", 0) or 0),
                api_key_name=getattr(row, "api_key_name", None),
                api_key_display=str(getattr(row, "api_key_display", "") or ""),
                role=_normalize_role_name(raw_role) if raw_role else "unknown",
                owner_email=getattr(row, "owner_email", None),
                created_at=created_at.isoformat() if created_at is not None else None,
            )
        )

    return SecurityPlatformServiceAccountSummary(
        api_key_count=api_key_count,
        service_account_user_count=service_account_user_count,
        ownerless_api_key_count=ownerless_api_key_count,
        role_counts=dict(sorted(role_counts.items())),
        recent_accounts=recent_accounts,
    )


def build_scim_summary(
    *,
    active_token_count: int,
    token_last_used_at: Any,
    user_mapping_count: int,
    group_mapping_count: int,
    recent_group_sync_failure_count: int,
) -> SecurityPlatformScimSummary:
    return SecurityPlatformScimSummary(
        active_token_count=active_token_count,
        has_active_token=active_token_count > 0,
        token_last_used_at=(
            token_last_used_at.isoformat() if token_last_used_at is not None else None
        ),
        user_mapping_count=user_mapping_count,
        group_mapping_count=group_mapping_count,
        recent_group_sync_failure_count=recent_group_sync_failure_count,
    )


def load_failure_summary(db_session: Session) -> SecurityPlatformFailureSummary:
    total_failures = int(
        db_session.scalar(
            select(func.count())
            .select_from(ChatMessage)
            .where(
                ChatMessage.message_type == MessageType.ASSISTANT,
                ChatMessage.error.is_not(None),
            )
        )
        or 0
    )

    recent_rows = db_session.execute(
        select(
            Persona.name.label("persona_name"),
            User.email.label("user_email"),
            ChatMessage.time_sent.label("time_sent"),
            ChatMessage.error.label("error"),
        )
        .select_from(ChatMessage)
        .join(ChatSession, ChatSession.id == ChatMessage.chat_session_id)
        .outerjoin(Persona, Persona.id == ChatSession.persona_id)
        .outerjoin(User, User.id == ChatSession.user_id)
        .where(
            ChatMessage.message_type == MessageType.ASSISTANT,
            ChatMessage.error.is_not(None),
        )
        .order_by(ChatMessage.time_sent.desc())
        .limit(10)
    ).all()

    return build_failure_summary(
        total_failures=total_failures,
        recent_rows=list(recent_rows),
    )


def load_tool_audit_summary(
    db_session: Session,
    security_tool_ids: list[int],
) -> SecurityPlatformToolAuditSummary:
    if not security_tool_ids:
        return build_tool_audit_summary(
            total_calls=0,
            tool_counts={},
            persona_counts={},
            recent_rows=[],
        )

    total_calls = int(
        db_session.scalar(
            select(func.count())
            .select_from(ToolCall)
            .where(ToolCall.tool_id.in_(security_tool_ids))
        )
        or 0
    )

    tool_count_rows = db_session.execute(
        select(Tool.name.label("tool_name"), func.count().label("call_count"))
        .select_from(ToolCall)
        .join(Tool, Tool.id == ToolCall.tool_id)
        .where(ToolCall.tool_id.in_(security_tool_ids))
        .group_by(Tool.name)
        .order_by(Tool.name.asc())
    ).all()
    tool_counts = {
        str(row.tool_name): int(row.call_count or 0) for row in tool_count_rows
    }

    persona_count_rows = db_session.execute(
        select(Persona.name.label("persona_name"), func.count().label("call_count"))
        .select_from(ToolCall)
        .join(ChatSession, ChatSession.id == ToolCall.chat_session_id)
        .outerjoin(Persona, Persona.id == ChatSession.persona_id)
        .where(ToolCall.tool_id.in_(security_tool_ids))
        .group_by(Persona.name)
        .order_by(Persona.name.asc().nulls_last())
    ).all()
    persona_counts = {
        str(row.persona_name or "unknown"): int(row.call_count or 0)
        for row in persona_count_rows
    }

    recent_rows = db_session.execute(
        select(
            Tool.name.label("tool_name"),
            Persona.name.label("persona_name"),
            User.email.label("user_email"),
            ChatMessage.time_sent.label("time_sent"),
            ToolCall.turn_number.label("turn_number"),
            ToolCall.parent_tool_call_id.label("parent_tool_call_id"),
        )
        .select_from(ToolCall)
        .join(Tool, Tool.id == ToolCall.tool_id)
        .join(ChatSession, ChatSession.id == ToolCall.chat_session_id)
        .outerjoin(Persona, Persona.id == ChatSession.persona_id)
        .outerjoin(User, User.id == ChatSession.user_id)
        .outerjoin(ChatMessage, ChatMessage.id == ToolCall.parent_chat_message_id)
        .where(ToolCall.tool_id.in_(security_tool_ids))
        .order_by(ToolCall.id.desc())
        .limit(10)
    ).all()

    return build_tool_audit_summary(
        total_calls=total_calls,
        tool_counts=tool_counts,
        persona_counts=persona_counts,
        recent_rows=list(recent_rows),
    )


def load_permission_inheritance_summary(
    db_session: Session,
) -> SecurityPlatformPermissionInheritanceSummary:
    sync_cc_pair_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(ConnectorCredentialPair)
            .where(ConnectorCredentialPair.access_type == AccessType.SYNC)
        )
        or 0
    )
    docs_with_user_acl_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(Document)
            .where(func.cardinality(Document.external_user_emails) > 0)
        )
        or 0
    )
    docs_with_group_acl_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(Document)
            .where(func.cardinality(Document.external_user_group_ids) > 0)
        )
        or 0
    )
    docs_with_external_acl_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(Document)
            .where(
                (func.cardinality(Document.external_user_emails) > 0)
                | (func.cardinality(Document.external_user_group_ids) > 0)
            )
        )
        or 0
    )
    recent_doc_sync_failure_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(DocPermissionSyncAttempt)
            .where(DocPermissionSyncAttempt.error_message.is_not(None))
        )
        or 0
    )
    recent_group_sync_failure_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(ExternalGroupPermissionSyncAttempt)
            .where(ExternalGroupPermissionSyncAttempt.error_message.is_not(None))
        )
        or 0
    )
    recent_doc_sync_rows = db_session.execute(
        select(DocPermissionSyncAttempt)
        .order_by(DocPermissionSyncAttempt.time_created.desc())
        .limit(5)
    ).scalars().all()
    recent_group_sync_rows = db_session.execute(
        select(ExternalGroupPermissionSyncAttempt)
        .order_by(ExternalGroupPermissionSyncAttempt.time_created.desc())
        .limit(5)
    ).scalars().all()

    return build_permission_inheritance_summary(
        sync_cc_pair_count=sync_cc_pair_count,
        docs_with_external_acl_count=docs_with_external_acl_count,
        docs_with_user_acl_count=docs_with_user_acl_count,
        docs_with_group_acl_count=docs_with_group_acl_count,
        recent_doc_sync_failure_count=recent_doc_sync_failure_count,
        recent_group_sync_failure_count=recent_group_sync_failure_count,
        recent_doc_sync_rows=list(recent_doc_sync_rows),
        recent_group_sync_rows=list(recent_group_sync_rows),
    )


def load_rbac_summary(
    db_session: Session,
    security_users: list[SecurityPlatformUserStatus],
    persona_user_links: int,
    document_set_user_links: int,
) -> SecurityPlatformRbacSummary:
    role_rows = db_session.execute(
        select(User.role, func.count().label("user_count"))
        .group_by(User.role)
        .order_by(User.role.asc())
    ).all()
    all_user_role_counts = {
        str(row.role.value if row.role is not None else "unknown"): int(row.user_count or 0)
        for row in role_rows
    }

    security_user_role_counts: dict[str, int] = {}
    for user in security_users:
        role_name = user.role.split(".")[-1].lower() if "." in user.role else user.role
        security_user_role_counts[role_name] = security_user_role_counts.get(role_name, 0) + 1

    user_group_count = int(
        db_session.scalar(select(func.count()).select_from(UserGroup)) or 0
    )
    permission_grant_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(PermissionGrant)
            .where(PermissionGrant.is_deleted.is_(False))
        )
        or 0
    )
    groups_with_permission_grants_count = int(
        db_session.scalar(
            select(func.count(func.distinct(PermissionGrant.group_id))).where(
                PermissionGrant.is_deleted.is_(False)
            )
        )
        or 0
    )
    users_with_effective_permissions_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(User)
            .where(func.jsonb_array_length(User.effective_permissions) > 0)
        )
        or 0
    )
    curator_membership_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(User__UserGroup)
            .where(User__UserGroup.is_curator.is_(True))
        )
        or 0
    )
    top_permission_rows = db_session.execute(
        select(PermissionGrant.permission, func.count().label("grant_count"))
        .where(PermissionGrant.is_deleted.is_(False))
        .group_by(PermissionGrant.permission)
        .order_by(func.count().desc(), PermissionGrant.permission.asc())
        .limit(10)
    ).all()
    top_permissions = {
        str(row.permission.value if row.permission is not None else "unknown"): int(
            row.grant_count or 0
        )
        for row in top_permission_rows
    }

    return build_rbac_summary(
        persona_user_links=persona_user_links,
        document_set_user_links=document_set_user_links,
        all_user_role_counts=all_user_role_counts,
        security_user_role_counts=security_user_role_counts,
        user_group_count=user_group_count,
        groups_with_permission_grants_count=groups_with_permission_grants_count,
        permission_grant_count=permission_grant_count,
        users_with_effective_permissions_count=users_with_effective_permissions_count,
        curator_membership_count=curator_membership_count,
        top_permissions=top_permissions,
    )


def load_service_account_summary(
    db_session: Session,
) -> SecurityPlatformServiceAccountSummary:
    owner_user = aliased(User)
    api_key_count = int(
        db_session.scalar(select(func.count()).select_from(ApiKey)) or 0
    )
    service_account_user_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(User)
            .where(User.account_type == AccountType.SERVICE_ACCOUNT)
        )
        or 0
    )
    ownerless_api_key_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(ApiKey)
            .where(ApiKey.owner_id.is_(None))
        )
        or 0
    )
    role_count_rows = db_session.execute(
        select(User.role.label("service_role"), func.count().label("user_count"))
        .select_from(ApiKey)
        .join(User, User.id == ApiKey.user_id)
        .group_by(User.role)
        .order_by(User.role.asc())
    ).all()
    role_counts = {
        _normalize_role_name(str(row.service_role.value if row.service_role is not None else "unknown")): int(
            row.user_count or 0
        )
        for row in role_count_rows
    }
    recent_rows = db_session.execute(
        select(
            ApiKey.id.label("api_key_id"),
            ApiKey.name.label("api_key_name"),
            ApiKey.api_key_display.label("api_key_display"),
            User.role.label("service_role"),
            User.email.label("service_email"),
            ApiKey.created_at.label("created_at"),
            select(owner_user.email)
            .select_from(owner_user)
            .where(owner_user.id == ApiKey.owner_id)
            .scalar_subquery()
            .label("owner_email"),
        )
        .select_from(ApiKey)
        .join(User, User.id == ApiKey.user_id)
        .order_by(ApiKey.created_at.desc(), ApiKey.id.desc())
        .limit(10)
    ).all()

    return build_service_account_summary(
        api_key_count=api_key_count,
        service_account_user_count=service_account_user_count,
        ownerless_api_key_count=ownerless_api_key_count,
        role_counts=role_counts,
        recent_rows=list(recent_rows),
    )


def load_scim_summary(
    db_session: Session,
) -> SecurityPlatformScimSummary:
    active_token_count = int(
        db_session.scalar(
            select(func.count()).select_from(ScimToken).where(ScimToken.is_active.is_(True))
        )
        or 0
    )
    token_last_used_at = db_session.scalar(
        select(ScimToken.last_used_at)
        .where(ScimToken.is_active.is_(True))
        .order_by(ScimToken.created_at.desc())
        .limit(1)
    )
    user_mapping_count = int(
        db_session.scalar(select(func.count()).select_from(ScimUserMapping)) or 0
    )
    group_mapping_count = int(
        db_session.scalar(select(func.count()).select_from(ScimGroupMapping)) or 0
    )
    recent_group_sync_failure_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(ExternalGroupPermissionSyncAttempt)
            .where(ExternalGroupPermissionSyncAttempt.error_message.is_not(None))
        )
        or 0
    )

    return build_scim_summary(
        active_token_count=active_token_count,
        token_last_used_at=token_last_used_at,
        user_mapping_count=user_mapping_count,
        group_mapping_count=group_mapping_count,
        recent_group_sync_failure_count=recent_group_sync_failure_count,
    )


def build_query_history_usage_summary(
    *,
    query_history_type: str,
    recent_query_count: int,
    recent_chat_session_count: int,
    recent_active_user_count: int,
    recent_like_count: int,
    recent_dislike_count: int,
    recent_export_count: int,
    recent_export_failure_count: int,
    recent_export_rows: list[Any],
) -> SecurityPlatformQueryUsageSummary:
    normalized_type = query_history_type.lower()
    return SecurityPlatformQueryUsageSummary(
        query_history_type=normalized_type,
        query_history_enabled=normalized_type != QueryHistoryType.DISABLED.value,
        recent_query_count=recent_query_count,
        recent_chat_session_count=recent_chat_session_count,
        recent_active_user_count=recent_active_user_count,
        recent_like_count=recent_like_count,
        recent_dislike_count=recent_dislike_count,
        recent_export_count=recent_export_count,
        recent_export_failure_count=recent_export_failure_count,
        recent_exports=[
            SecurityPlatformQueryUsageExportEntry(
                task_id=str(row.task_id),
                status=str(row.status),
                start_time=(
                    row.start_time.isoformat() if row.start_time is not None else None
                ),
            )
            for row in recent_export_rows
        ],
    )


def load_query_history_usage_summary(
    db_session: Session,
) -> SecurityPlatformQueryUsageSummary:
    lookback_start = datetime.now(timezone.utc) - timedelta(days=30)
    recent_query_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(ChatMessage)
            .where(
                ChatMessage.message_type == MessageType.ASSISTANT,
                ChatMessage.time_sent >= lookback_start,
            )
        )
        or 0
    )
    recent_chat_session_count = int(
        db_session.scalar(
            select(func.count(func.distinct(ChatMessage.chat_session_id)))
            .select_from(ChatMessage)
            .where(
                ChatMessage.message_type == MessageType.ASSISTANT,
                ChatMessage.time_sent >= lookback_start,
            )
        )
        or 0
    )
    recent_active_user_count = int(
        db_session.scalar(
            select(func.count(func.distinct(ChatSession.user_id)))
            .select_from(ChatMessage)
            .join(ChatSession, ChatSession.id == ChatMessage.chat_session_id)
            .where(
                ChatMessage.message_type == MessageType.ASSISTANT,
                ChatMessage.time_sent >= lookback_start,
                ChatSession.user_id.is_not(None),
            )
        )
        or 0
    )
    feedback_counts = db_session.execute(
        select(
            func.sum(case((ChatMessageFeedback.is_positive.is_(True), 1), else_=0)).label(
                "like_count"
            ),
            func.sum(case((ChatMessageFeedback.is_positive.is_(False), 1), else_=0)).label(
                "dislike_count"
            ),
        )
        .select_from(ChatMessage)
        .join(ChatMessageFeedback, ChatMessageFeedback.chat_message_id == ChatMessage.id)
        .where(
            ChatMessage.message_type == MessageType.ASSISTANT,
            ChatMessage.time_sent >= lookback_start,
        )
    ).one()
    recent_like_count = int(feedback_counts.like_count or 0)
    recent_dislike_count = int(feedback_counts.dislike_count or 0)

    query_history_task_prefix = "export_query_history_task"
    try:
        from ee.onyx.background.task_name_builders import QUERY_HISTORY_TASK_NAME_PREFIX

        query_history_task_prefix = str(QUERY_HISTORY_TASK_NAME_PREFIX)
    except Exception:
        pass

    recent_export_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(TaskQueueState)
            .where(TaskQueueState.task_name.like(f"{query_history_task_prefix}_%"))
        )
        or 0
    )
    recent_export_failure_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(TaskQueueState)
            .where(
                TaskQueueState.task_name.like(f"{query_history_task_prefix}_%"),
                TaskQueueState.status == TaskStatus.FAILURE,
            )
        )
        or 0
    )
    recent_export_rows = db_session.execute(
        select(
            TaskQueueState.task_id.label("task_id"),
            TaskQueueState.status.label("status"),
            TaskQueueState.start_time.label("start_time"),
        )
        .where(TaskQueueState.task_name.like(f"{query_history_task_prefix}_%"))
        .order_by(TaskQueueState.register_time.desc(), TaskQueueState.id.desc())
        .limit(5)
    ).all()

    return build_query_history_usage_summary(
        query_history_type=str(ONYX_QUERY_HISTORY_TYPE.value),
        recent_query_count=recent_query_count,
        recent_chat_session_count=recent_chat_session_count,
        recent_active_user_count=recent_active_user_count,
        recent_like_count=recent_like_count,
        recent_dislike_count=recent_dislike_count,
        recent_export_count=recent_export_count,
        recent_export_failure_count=recent_export_failure_count,
        recent_export_rows=list(recent_export_rows),
    )


def build_custom_permission_summary(
    *,
    default_group_count: int,
    custom_group_count: int,
    stale_custom_group_count: int,
    groups_with_custom_grants_count: int,
    custom_permission_count: int,
    manual_grant_count: int,
    scim_grant_count: int,
    admin_override_group_count: int,
    permission_counts: dict[str, int],
) -> SecurityPlatformCustomPermissionSummary:
    return SecurityPlatformCustomPermissionSummary(
        default_group_count=default_group_count,
        custom_group_count=custom_group_count,
        stale_custom_group_count=stale_custom_group_count,
        groups_with_custom_grants_count=groups_with_custom_grants_count,
        custom_permission_count=custom_permission_count,
        manual_grant_count=manual_grant_count,
        scim_grant_count=scim_grant_count,
        admin_override_group_count=admin_override_group_count,
        permission_counts=dict(sorted(permission_counts.items())),
    )


def load_custom_permission_summary(
    db_session: Session,
) -> SecurityPlatformCustomPermissionSummary:
    default_group_count = int(
        db_session.scalar(
            select(func.count()).select_from(UserGroup).where(UserGroup.is_default.is_(True))
        )
        or 0
    )
    custom_group_count = int(
        db_session.scalar(
            select(func.count()).select_from(UserGroup).where(UserGroup.is_default.is_(False))
        )
        or 0
    )
    stale_custom_group_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(UserGroup)
            .where(
                UserGroup.is_default.is_(False),
                UserGroup.is_up_to_date.is_(False),
                UserGroup.is_up_for_deletion.is_(False),
            )
        )
        or 0
    )
    groups_with_custom_grants_count = int(
        db_session.scalar(
            select(func.count(func.distinct(PermissionGrant.group_id)))
            .select_from(PermissionGrant)
            .join(UserGroup, UserGroup.id == PermissionGrant.group_id)
            .where(
                UserGroup.is_default.is_(False),
                PermissionGrant.is_deleted.is_(False),
                PermissionGrant.permission != Permission.BASIC_ACCESS,
            )
        )
        or 0
    )
    custom_permission_rows = db_session.execute(
        select(PermissionGrant.permission, func.count().label("grant_count"))
        .select_from(PermissionGrant)
        .join(UserGroup, UserGroup.id == PermissionGrant.group_id)
        .where(
            UserGroup.is_default.is_(False),
            PermissionGrant.is_deleted.is_(False),
            PermissionGrant.permission != Permission.BASIC_ACCESS,
        )
        .group_by(PermissionGrant.permission)
        .order_by(PermissionGrant.permission.asc())
    ).all()
    permission_counts = {
        str(row.permission.value if row.permission is not None else "unknown"): int(
            row.grant_count or 0
        )
        for row in custom_permission_rows
    }
    custom_permission_count = len(permission_counts)
    manual_grant_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(PermissionGrant)
            .join(UserGroup, UserGroup.id == PermissionGrant.group_id)
            .where(
                UserGroup.is_default.is_(False),
                PermissionGrant.is_deleted.is_(False),
                PermissionGrant.permission != Permission.BASIC_ACCESS,
                PermissionGrant.grant_source == GrantSource.USER,
            )
        )
        or 0
    )
    scim_grant_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(PermissionGrant)
            .join(UserGroup, UserGroup.id == PermissionGrant.group_id)
            .where(
                UserGroup.is_default.is_(False),
                PermissionGrant.is_deleted.is_(False),
                PermissionGrant.permission != Permission.BASIC_ACCESS,
                PermissionGrant.grant_source == GrantSource.SCIM,
            )
        )
        or 0
    )
    admin_override_group_count = int(
        db_session.scalar(
            select(func.count(func.distinct(PermissionGrant.group_id)))
            .select_from(PermissionGrant)
            .join(UserGroup, UserGroup.id == PermissionGrant.group_id)
            .where(
                UserGroup.is_default.is_(False),
                PermissionGrant.is_deleted.is_(False),
                PermissionGrant.permission == Permission.FULL_ADMIN_PANEL_ACCESS,
            )
        )
        or 0
    )

    return build_custom_permission_summary(
        default_group_count=default_group_count,
        custom_group_count=custom_group_count,
        stale_custom_group_count=stale_custom_group_count,
        groups_with_custom_grants_count=groups_with_custom_grants_count,
        custom_permission_count=custom_permission_count,
        manual_grant_count=manual_grant_count,
        scim_grant_count=scim_grant_count,
        admin_override_group_count=admin_override_group_count,
        permission_counts=permission_counts,
    )


def build_usage_limit_summary(
    *,
    enabled: bool,
    global_limit_count: int,
    enabled_global_limit_count: int,
    user_limit_count: int,
    enabled_user_limit_count: int,
    user_group_limit_count: int,
    enabled_user_group_limit_count: int,
    limited_user_group_count: int,
) -> SecurityPlatformUsageLimitSummary:
    return SecurityPlatformUsageLimitSummary(
        enabled=enabled,
        global_limit_count=global_limit_count,
        enabled_global_limit_count=enabled_global_limit_count,
        user_limit_count=user_limit_count,
        enabled_user_limit_count=enabled_user_limit_count,
        user_group_limit_count=user_group_limit_count,
        enabled_user_group_limit_count=enabled_user_group_limit_count,
        limited_user_group_count=limited_user_group_count,
    )


def load_usage_limit_summary(
    db_session: Session,
) -> SecurityPlatformUsageLimitSummary:
    global_limit_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(TokenRateLimit)
            .where(TokenRateLimit.scope == TokenRateLimitScope.GLOBAL)
        )
        or 0
    )
    enabled_global_limit_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(TokenRateLimit)
            .where(
                TokenRateLimit.scope == TokenRateLimitScope.GLOBAL,
                TokenRateLimit.enabled.is_(True),
            )
        )
        or 0
    )
    user_limit_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(TokenRateLimit)
            .where(TokenRateLimit.scope == TokenRateLimitScope.USER)
        )
        or 0
    )
    enabled_user_limit_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(TokenRateLimit)
            .where(
                TokenRateLimit.scope == TokenRateLimitScope.USER,
                TokenRateLimit.enabled.is_(True),
            )
        )
        or 0
    )
    user_group_limit_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(TokenRateLimit)
            .where(TokenRateLimit.scope == TokenRateLimitScope.USER_GROUP)
        )
        or 0
    )
    enabled_user_group_limit_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(TokenRateLimit)
            .where(
                TokenRateLimit.scope == TokenRateLimitScope.USER_GROUP,
                TokenRateLimit.enabled.is_(True),
            )
        )
        or 0
    )
    limited_user_group_count = int(
        db_session.scalar(
            select(func.count(func.distinct(TokenRateLimit__UserGroup.user_group_id)))
            .select_from(TokenRateLimit__UserGroup)
            .join(
                TokenRateLimit,
                TokenRateLimit.id == TokenRateLimit__UserGroup.rate_limit_id,
            )
            .where(TokenRateLimit.enabled.is_(True))
        )
        or 0
    )

    from onyx.server.usage_limits import is_usage_limits_enabled

    return build_usage_limit_summary(
        enabled=is_usage_limits_enabled(),
        global_limit_count=global_limit_count,
        enabled_global_limit_count=enabled_global_limit_count,
        user_limit_count=user_limit_count,
        enabled_user_limit_count=enabled_user_limit_count,
        user_group_limit_count=user_group_limit_count,
        enabled_user_group_limit_count=enabled_user_group_limit_count,
        limited_user_group_count=limited_user_group_count,
    )


def build_hook_summary(
    *,
    hooks_enabled: bool,
    supported_hook_point_count: int,
    configured_hook_count: int,
    active_hook_count: int,
    reachable_hook_count: int,
    recent_execution_count: int,
    recent_failure_count: int,
    hook_point_names: list[str],
    recent_execution_rows: list[Any],
) -> SecurityPlatformHookSummary:
    return SecurityPlatformHookSummary(
        hooks_enabled=hooks_enabled,
        supported_hook_point_count=supported_hook_point_count,
        configured_hook_count=configured_hook_count,
        active_hook_count=active_hook_count,
        reachable_hook_count=reachable_hook_count,
        recent_execution_count=recent_execution_count,
        recent_failure_count=recent_failure_count,
        hook_point_names=sorted(hook_point_names),
        recent_executions=[
            SecurityPlatformHookExecutionEntry(
                hook_name=str(row.hook_name),
                hook_point=str(row.hook_point),
                is_success=bool(row.is_success),
                status_code=row.status_code,
                error_message=row.error_message,
                created_at=(
                    row.created_at.isoformat() if row.created_at is not None else None
                ),
            )
            for row in recent_execution_rows
        ],
    )


def load_hook_summary(
    db_session: Session,
) -> SecurityPlatformHookSummary:
    hook_point_names = [spec.hook_point.value for spec in get_all_specs()]
    hooks_enabled = not MULTI_TENANT
    configured_hook_count = int(
        db_session.scalar(
            select(func.count()).select_from(Hook).where(Hook.deleted.is_(False))
        )
        or 0
    )
    active_hook_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(Hook)
            .where(Hook.deleted.is_(False), Hook.is_active.is_(True))
        )
        or 0
    )
    reachable_hook_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(Hook)
            .where(
                Hook.deleted.is_(False),
                Hook.is_active.is_(True),
                Hook.is_reachable.is_(True),
            )
        )
        or 0
    )
    recent_execution_count = int(
        db_session.scalar(select(func.count()).select_from(HookExecutionLog)) or 0
    )
    recent_failure_count = int(
        db_session.scalar(
            select(func.count())
            .select_from(HookExecutionLog)
            .where(HookExecutionLog.is_success.is_(False))
        )
        or 0
    )
    recent_execution_rows = db_session.execute(
        select(
            Hook.name.label("hook_name"),
            Hook.hook_point.label("hook_point"),
            HookExecutionLog.is_success.label("is_success"),
            HookExecutionLog.status_code.label("status_code"),
            HookExecutionLog.error_message.label("error_message"),
            HookExecutionLog.created_at.label("created_at"),
        )
        .select_from(HookExecutionLog)
        .join(Hook, Hook.id == HookExecutionLog.hook_id)
        .where(Hook.deleted.is_(False))
        .order_by(HookExecutionLog.created_at.desc(), HookExecutionLog.id.desc())
        .limit(5)
    ).all()
    return build_hook_summary(
        hooks_enabled=hooks_enabled,
        supported_hook_point_count=len(hook_point_names),
        configured_hook_count=configured_hook_count,
        active_hook_count=active_hook_count,
        reachable_hook_count=reachable_hook_count,
        recent_execution_count=recent_execution_count,
        recent_failure_count=recent_failure_count,
        hook_point_names=hook_point_names,
        recent_execution_rows=list(recent_execution_rows),
    )


def load_secrets_encryption_summary() -> SecurityPlatformSecretsEncryptionSummary:
    encrypted_columns: list[str] = []
    for mapper in Base.registry.mappers:
        if not isinstance(mapper, Mapper):
            continue
        table_name = getattr(mapper.class_, "__tablename__", None)
        if not table_name:
            continue
        for prop in mapper.column_attrs:
            for column in prop.columns:
                if isinstance(column.type, (EncryptedString, EncryptedJson)):
                    encrypted_columns.append(f"{table_name}.{prop.key}")

    rotation_script_available = (
        ROOT_PATH / "backend" / "onyx" / "db" / "rotate_encryption_key.py"
    ).exists()
    return build_secrets_encryption_summary(
        enabled=bool(ENCRYPTION_KEY_SECRET.strip()),
        encrypted_columns=encrypted_columns,
        rotation_script_available=rotation_script_available,
    )


def build_custom_theming_snapshot(
    settings: Any | None = None,
) -> dict[str, Any]:
    settings = settings or load_enterprise_settings()
    application_name = (
        str(settings.application_name).strip()
        if settings.application_name is not None
        else ONYX_DEFAULT_APPLICATION_NAME
    )
    if not application_name:
        application_name = ONYX_DEFAULT_APPLICATION_NAME
    use_custom_logo = bool(settings.use_custom_logo)
    use_custom_logotype = bool(settings.use_custom_logotype)
    custom_nav_item_count = len(settings.custom_nav_items)
    custom_header_content_enabled = bool(
        str(settings.custom_header_content or "").strip()
    )
    custom_lower_disclaimer_enabled = bool(
        str(settings.custom_lower_disclaimer_content or "").strip()
    )
    first_visit_notice_enabled = bool(settings.show_first_visit_notice)
    popup_header_configured = bool(str(settings.custom_popup_header or "").strip())
    popup_content_configured = bool(str(settings.custom_popup_content or "").strip())
    custom_popup_enabled = popup_header_configured and popup_content_configured
    consent_screen_enabled = bool(settings.enable_consent_screen)
    consent_prompt_configured = bool(str(settings.consent_screen_prompt or "").strip())
    custom_greeting_enabled = bool(str(settings.custom_greeting_message or "").strip())
    branding_configured = any(
        [
            application_name != ONYX_DEFAULT_APPLICATION_NAME,
            use_custom_logo,
            use_custom_logotype,
            custom_nav_item_count > 0,
            custom_header_content_enabled,
            custom_lower_disclaimer_enabled,
            first_visit_notice_enabled,
            consent_screen_enabled,
            custom_greeting_enabled,
        ]
    )
    return {
        "branding_configured": branding_configured,
        "application_name": application_name,
        "application_name_is_default": application_name == ONYX_DEFAULT_APPLICATION_NAME,
        "use_custom_logo": use_custom_logo,
        "use_custom_logotype": use_custom_logotype,
        "logo_display_style": str(settings.logo_display_style or "logo_and_name"),
        "custom_nav_item_count": custom_nav_item_count,
        "custom_header_content_enabled": custom_header_content_enabled,
        "custom_lower_disclaimer_enabled": custom_lower_disclaimer_enabled,
        "first_visit_notice_enabled": first_visit_notice_enabled,
        "custom_popup_enabled": custom_popup_enabled,
        "consent_screen_enabled": consent_screen_enabled,
        "custom_greeting_enabled": custom_greeting_enabled,
        "consent_prompt_configured": consent_prompt_configured,
        "popup_content_configured": custom_popup_enabled,
    }


WHITE_LABELING_TRACE_FILES = [
    (
        ROOT_PATH / "web" / "src" / "refresh-components" / "Logo.tsx",
        "Powered by Onyx",
        False,
    ),
    (
        ROOT_PATH / "web" / "src" / "app" / "auth" / "signup" / "page.tsx",
        "Get started with Onyx",
        False,
    ),
    (
        ROOT_PATH / "web" / "src" / "sections" / "sidebar" / "AdminSidebar.tsx",
        "https://onyx.app",
        True,
    ),
]

DOCKER_COMPOSE_DIR = ROOT_PATH / "deployment" / "docker_compose"
HELM_VALUES_DIR = ROOT_PATH / "deployment" / "helm" / "charts" / "onyx"


def load_white_labeling_summary(
    custom_theming_snapshot: dict[str, Any],
) -> SecurityPlatformWhiteLabelingSummary:
    residual_branding_examples: list[str] = []
    residual_external_link_count = 0
    for path, pattern, is_external_link in WHITE_LABELING_TRACE_FILES:
        try:
            if pattern in path.read_text(encoding="utf-8"):
                residual_branding_examples.append(f"{path.name}: {pattern}")
                if is_external_link:
                    residual_external_link_count += 1
        except OSError:
            continue

    branding_configured = bool(custom_theming_snapshot.get("branding_configured", False))
    application_name_configured = not bool(
        custom_theming_snapshot.get("application_name_is_default", True)
    )
    custom_logo_enabled = bool(custom_theming_snapshot.get("use_custom_logo", False))
    custom_favicon_enabled = custom_logo_enabled
    residual_branding_count = len(residual_branding_examples)
    return SecurityPlatformWhiteLabelingSummary(
        branding_configured=branding_configured,
        custom_logo_enabled=custom_logo_enabled,
        custom_favicon_enabled=custom_favicon_enabled,
        application_name_configured=application_name_configured,
        white_label_ready=branding_configured and residual_branding_count == 0,
        residual_branding_count=residual_branding_count,
        residual_external_link_count=residual_external_link_count,
        residual_branding_examples=residual_branding_examples,
    )


def load_custom_deployment_summary() -> SecurityPlatformCustomDeploymentSummary:
    compose_files = sorted(DOCKER_COMPOSE_DIR.glob("docker-compose*.yml"))
    helm_value_files = sorted(HELM_VALUES_DIR.glob("values*.yaml"))
    has_install_script = (DOCKER_COMPOSE_DIR / "install.sh").exists()
    has_multitenant_compose = any(
        path.name == "docker-compose.multitenant-dev.yml" for path in compose_files
    )
    has_lite_compose = any(
        path.name == "docker-compose.onyx-lite.yml" for path in compose_files
    ) or any(path.name == "values-lite.yaml" for path in helm_value_files)
    has_prod_compose = any(
        path.name in {"docker-compose.prod.yml", "docker-compose.prod-cloud.yml"}
        for path in compose_files
    )
    has_security_platform_compose_overlay = (
        DOCKER_COMPOSE_DIR / "docker-compose.security-platform.override.yml"
    ).exists()
    has_security_platform_helm_overlay = any(
        path.name == "values.security-platform.yaml" for path in helm_value_files
    )
    supported_modes: list[str] = []
    if compose_files:
        supported_modes.append("docker-compose")
    if helm_value_files:
        supported_modes.append("helm")
    if has_multitenant_compose:
        supported_modes.append("multitenant")
    if has_lite_compose:
        supported_modes.append("lite")
    if has_prod_compose:
        supported_modes.append("production")
    overlay_examples = [
        path
        for path in [
            "deployment/docker_compose/docker-compose.security-platform.override.yml"
            if has_security_platform_compose_overlay
            else "",
            "deployment/helm/charts/onyx/values.security-platform.yaml"
            if has_security_platform_helm_overlay
            else "",
        ]
        if path
    ]
    return SecurityPlatformCustomDeploymentSummary(
        docker_compose_variant_count=len(compose_files),
        helm_values_variant_count=len(helm_value_files),
        has_install_script=has_install_script,
        has_multitenant_compose=has_multitenant_compose,
        has_lite_compose=has_lite_compose,
        has_prod_compose=has_prod_compose,
        has_security_platform_compose_overlay=has_security_platform_compose_overlay,
        has_security_platform_helm_overlay=has_security_platform_helm_overlay,
        supported_modes=supported_modes,
        overlay_examples=overlay_examples,
    )


def load_region_processing_summary() -> SecurityPlatformRegionProcessingSummary:
    hint_sources = [
        ROOT_PATH / "deployment" / "docker_compose" / "env.template",
        ROOT_PATH / "deployment" / "docker_compose" / "env.prod.template",
        ROOT_PATH / "deployment" / "helm" / "charts" / "onyx" / "values.yaml",
        ROOT_PATH
        / "deployment"
        / "docker_compose"
        / "docker-compose.prod.yml",
        ROOT_PATH
        / "deployment"
        / "docker_compose"
        / "docker-compose.prod-cloud.yml",
    ]
    patterns = [
        "AWS_REGION_NAME",
        "S3_ENDPOINT_URL",
        "WEB_DOMAIN",
        "MULTI_TENANT",
        "prod-cloud",
    ]
    region_hints: list[str] = []
    for path in hint_sources:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for pattern in patterns:
            if pattern in content:
                region_hints.append(f"{path.name}: {pattern}")
    unique_hints = sorted(set(region_hints))
    return SecurityPlatformRegionProcessingSummary(
        aws_region_supported=any("AWS_REGION_NAME" in hint for hint in unique_hints),
        object_store_endpoint_configurable=any(
            "S3_ENDPOINT_URL" in hint for hint in unique_hints
        ),
        web_domain_configurable=any("WEB_DOMAIN" in hint for hint in unique_hints),
        tenant_aware_deployment_supported=(
            (DOCKER_COMPOSE_DIR / "docker-compose.multitenant-dev.yml").exists()
        ),
        cloud_deployment_supported=(
            (DOCKER_COMPOSE_DIR / "docker-compose.prod-cloud.yml").exists()
        ),
        region_hint_count=len(unique_hints),
        region_hints=unique_hints,
    )


def _enumish_str(value: Any | None) -> str | None:
    if value is None:
        return None
    enum_value = getattr(value, "value", None)
    if enum_value is not None:
        return str(enum_value)
    text = str(value).strip()
    return text or None


def load_self_hosting_summary(
    db_session: Session | None = None,
) -> SecurityPlatformSelfHostingSummary:
    metadata = get_license_metadata(db_session) if db_session is not None else None
    return SecurityPlatformSelfHostingSummary(
        self_hosted_mode=not MULTI_TENANT,
        multi_tenant_mode=bool(MULTI_TENANT),
        enterprise_features_enabled=(
            os.environ.get("ENABLE_PAID_ENTERPRISE_EDITION_FEATURES", "").lower()
            == "true"
            or not LICENSE_ENFORCEMENT_ENABLED
        ),
        license_enforcement_enabled=LICENSE_ENFORCEMENT_ENABLED,
        has_license=metadata is not None,
        license_status=_enumish_str(getattr(metadata, "status", None)),
        license_source=_enumish_str(getattr(metadata, "source", None)),
        seat_count=getattr(metadata, "seats", None),
        used_seat_count=getattr(metadata, "used_seats", None),
        has_license_api=(
            ROOT_PATH / "backend" / "ee" / "onyx" / "server" / "license" / "api.py"
        ).exists(),
        has_admin_billing_page=(
            ROOT_PATH / "web" / "src" / "app" / "admin" / "billing" / "page.tsx"
        ).exists(),
        has_billing_service=(
            ROOT_PATH
            / "backend"
            / "ee"
            / "onyx"
            / "server"
            / "billing"
            / "service.py"
        ).exists(),
        has_cloud_proxy=(
            ROOT_PATH / "backend" / "ee" / "onyx" / "server" / "tenants" / "proxy.py"
        ).exists(),
        cloud_data_plane_url_configured=bool(str(CLOUD_DATA_PLANE_URL).strip()),
        has_install_script=(ROOT_PATH / "install.sh").exists(),
        has_docker_compose_path=(ROOT_PATH / "deployment" / "docker_compose").exists(),
        has_helm_install_path=(
            ROOT_PATH / "deployment" / "helm" / "charts" / "onyx" / "values.yaml"
        ).exists(),
    )


def load_custom_theming_summary() -> SecurityPlatformCustomThemingSummary:
    return SecurityPlatformCustomThemingSummary(
        **{
            key: value
            for key, value in build_custom_theming_snapshot().items()
            if key
            not in {
                "consent_prompt_configured",
                "popup_content_configured",
            }
        }
    )


def load_static_snapshot() -> dict[str, Any]:
    if not SNAPSHOT_PATH.exists():
        return {
            "threat_intel_sync": {
                "source_profile": "unknown",
                "last_sync_run_at": None,
                "due_status": "UNKNOWN",
                "due_feeds": [],
            },
            "threat_intel_corpus": {
                "governed": 0,
                "unmanaged": 0,
                "promotion_candidates": 0,
                "manual_review": 0,
                "keep_runtime_only": 0,
            },
            "permission_inheritance": {
                "sync_cc_pair_count": 0,
                "docs_with_external_acl_count": 0,
                "docs_with_user_acl_count": 0,
                "docs_with_group_acl_count": 0,
                "recent_doc_sync_failure_count": 0,
                "recent_group_sync_failure_count": 0,
                "recent_doc_sync_attempts": [],
                "recent_group_sync_attempts": [],
            },
            "service_accounts": {
                "api_key_count": 0,
                "service_account_user_count": 0,
                "ownerless_api_key_count": 0,
                "role_counts": {},
                "recent_accounts": [],
            },
            "scim": {
                "active_token_count": 0,
                "has_active_token": False,
                "token_last_used_at": None,
                "user_mapping_count": 0,
                "group_mapping_count": 0,
                "recent_group_sync_failure_count": 0,
            },
            "query_history_usage": {
                "query_history_type": "disabled",
                "query_history_enabled": False,
                "recent_query_count": 0,
                "recent_chat_session_count": 0,
                "recent_active_user_count": 0,
                "recent_like_count": 0,
                "recent_dislike_count": 0,
                "recent_export_count": 0,
                "recent_export_failure_count": 0,
                "recent_exports": [],
            },
            "custom_permissions": {
                "default_group_count": 0,
                "custom_group_count": 0,
                "stale_custom_group_count": 0,
                "groups_with_custom_grants_count": 0,
                "custom_permission_count": 0,
                "manual_grant_count": 0,
                "scim_grant_count": 0,
                "admin_override_group_count": 0,
                "permission_counts": {},
            },
            "usage_limits": {
                "enabled": False,
                "global_limit_count": 0,
                "enabled_global_limit_count": 0,
                "user_limit_count": 0,
                "enabled_user_limit_count": 0,
                "user_group_limit_count": 0,
                "enabled_user_group_limit_count": 0,
                "limited_user_group_count": 0,
            },
            "hooks": {
                "hooks_enabled": False,
                "supported_hook_point_count": 0,
                "configured_hook_count": 0,
                "active_hook_count": 0,
                "reachable_hook_count": 0,
                "recent_execution_count": 0,
                "recent_failure_count": 0,
                "hook_point_names": [],
                "recent_executions": [],
            },
            "custom_theming": {
                "branding_configured": False,
                "application_name": ONYX_DEFAULT_APPLICATION_NAME,
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
                "residual_branding_count": 0,
                "residual_external_link_count": 0,
                "residual_branding_examples": [],
            },
            "custom_deployments": {
                "docker_compose_variant_count": 0,
                "helm_values_variant_count": 0,
                "has_install_script": False,
                "has_multitenant_compose": False,
                "has_lite_compose": False,
                "has_prod_compose": False,
                "has_security_platform_compose_overlay": False,
                "has_security_platform_helm_overlay": False,
                "supported_modes": [],
                "overlay_examples": [],
            },
            "region_processing": {
                "aws_region_supported": False,
                "object_store_endpoint_configurable": False,
                "web_domain_configurable": False,
                "tenant_aware_deployment_supported": False,
                "cloud_deployment_supported": False,
                "region_hint_count": 0,
                "region_hints": [],
            },
            "self_hosting": {
                "self_hosted_mode": not MULTI_TENANT,
                "multi_tenant_mode": bool(MULTI_TENANT),
                "enterprise_features_enabled": not LICENSE_ENFORCEMENT_ENABLED,
                "license_enforcement_enabled": LICENSE_ENFORCEMENT_ENABLED,
                "has_license": False,
                "license_status": None,
                "license_source": None,
                "seat_count": None,
                "used_seat_count": None,
                "has_license_api": False,
                "has_admin_billing_page": False,
                "has_billing_service": False,
                "has_cloud_proxy": False,
                "cloud_data_plane_url_configured": False,
                "has_install_script": False,
                "has_docker_compose_path": False,
                "has_helm_install_path": False,
            },
            "secrets_encryption": {
                "enabled": False,
                "encrypted_model_count": 0,
                "encrypted_column_count": 0,
                "encrypted_columns": [],
                "rotation_script_available": False,
            },
            "historical_packages": {
                "package_count": 0,
                "total_item_count": 0,
                "total_size_bytes": 0,
                "package_ids": [],
                "packages": [],
                "consistency": {
                    "ok": True,
                    "summary": {
                        "package_count": 0,
                        "consistent_package_count": 0,
                        "issue_count": 0,
                    },
                    "issues": [],
                    "package_checks": [],
                },
            },
            "playbooks": {"count": 0, "with_examples": 0, "items": []},
        }
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


@router.get("/status")
def get_security_platform_status(
    db_session: Session = Depends(get_session),
    _: User = Depends(current_admin_user),
) -> SecurityPlatformRuntimeStatus:
    profile_name, profile = get_selected_profile()
    snapshot = load_static_snapshot()
    expected_threat_profile = str(profile["threat_intel_source_profile"])
    expected_tools_profile = str(profile["security_tools_profile"])
    required_env = [str(value) for value in profile["required_env"]]
    missing_required_env = get_missing_required_env(required_env)
    placeholder_required_env = get_placeholder_required_env(required_env)
    deployment_profile_issues = get_deployment_profile_issues(profile_name)
    if placeholder_required_env:
        deployment_profile_issues.extend(
            [
                "Required env vars still use placeholder/example values: "
                + ", ".join(sorted(placeholder_required_env))
            ]
        )

    threat_intel_source_profile = get_runtime_profile_value(
        "THREAT_INTEL_SOURCE_PROFILE", expected_threat_profile
    )
    security_tools_profile = get_runtime_profile_value(
        "SECURITY_TOOLS_PROFILE", expected_tools_profile
    )

    document_set = get_document_set_by_name(db_session, SECURITY_DOCUMENT_SET_NAME)
    document_set_status = SecurityPlatformDocumentSetStatus(
        id=document_set.id if document_set else None,
        name=SECURITY_DOCUMENT_SET_NAME,
        exists=document_set is not None,
        is_public=document_set.is_public if document_set else None,
        shared_user_count=len(document_set.users) if document_set else 0,
    )

    all_personas = get_personas(db_session)
    security_personas = [
        persona for persona in all_personas if persona.name in SECURITY_PERSONA_NAMES
    ]
    persona_ids = [persona.id for persona in security_personas]

    personas = [
        SecurityPlatformPersonaStatus(
            id=persona.id,
            name=persona.name,
            is_public=persona.is_public,
            tool_count=len(persona.tools),
            document_set_count=len(persona.document_sets),
            shared_user_count=len(persona.users),
        )
        for persona in sorted(security_personas, key=lambda persona: persona.id)
    ]

    all_tools = get_tools(db_session, only_openapi=True)
    security_tools = [
        tool for tool in all_tools if tool.name in SECURITY_TOOL_NAMES
    ]
    tools = [build_tool_status(tool) for tool in sorted(security_tools, key=lambda tool: tool.id)]
    security_tool_ids = [tool.id for tool in security_tools]
    tool_audit = load_tool_audit_summary(db_session, security_tool_ids)
    declared_tool_configs = load_declared_tool_configs(security_tools_profile)
    tool_drift = build_tool_drift_summary(declared_tool_configs, tools)
    failure_summary = load_failure_summary(db_session)
    permission_inheritance = load_permission_inheritance_summary(db_session)
    service_accounts = load_service_account_summary(db_session)
    scim = load_scim_summary(db_session)
    query_history_usage = load_query_history_usage_summary(db_session)
    custom_permissions = load_custom_permission_summary(db_session)
    usage_limits = load_usage_limit_summary(db_session)
    hooks = load_hook_summary(db_session)
    enterprise_settings = load_enterprise_settings()
    custom_theming_snapshot = build_custom_theming_snapshot(enterprise_settings)
    custom_theming = SecurityPlatformCustomThemingSummary(
        **{
            key: value
            for key, value in custom_theming_snapshot.items()
            if key
            not in {
                "consent_prompt_configured",
                "popup_content_configured",
            }
        }
    )
    white_labeling = load_white_labeling_summary(custom_theming_snapshot)
    custom_deployments = load_custom_deployment_summary()
    region_processing = load_region_processing_summary()
    self_hosting = load_self_hosting_summary(db_session)
    secrets_encryption = load_secrets_encryption_summary()

    users = list(
        db_session.execute(
            select(User).where(User.email.in_(SECURITY_USER_EMAILS))
        )
        .unique()
        .scalars()
        .all()
    )
    security_users = [
        SecurityPlatformUserStatus(
            email=user.email,
            role=str(user.role),
            is_active=user.is_active,
        )
        for user in sorted(users, key=lambda user: user.email)
    ]

    persona_user_links = 0
    if persona_ids:
        persona_user_links = int(
            db_session.scalar(
                select(func.count())
                .select_from(Persona__User)
                .where(Persona__User.persona_id.in_(persona_ids))
            )
            or 0
        )
    document_set_user_links = 0
    if document_set is not None:
        document_set_user_links = int(
            db_session.scalar(
                select(func.count())
                .select_from(DocumentSet__User)
                .where(DocumentSet__User.document_set_id == document_set.id)
            )
            or 0
        )
    rbac_summary = load_rbac_summary(
        db_session,
        security_users=security_users,
        persona_user_links=persona_user_links,
        document_set_user_links=document_set_user_links,
    )
    health = build_health_status(
        profile_name=profile_name,
        expected_threat_profile=expected_threat_profile,
        expected_tools_profile=expected_tools_profile,
        threat_intel_source_profile=threat_intel_source_profile,
        security_tools_profile=security_tools_profile,
        required_env=required_env,
        missing_required_env=missing_required_env,
        placeholder_required_env=placeholder_required_env,
        deployment_profile_issues=deployment_profile_issues,
        document_set_status=document_set_status,
        personas=personas,
        tools=tools,
        security_users=security_users,
        persona_user_links=persona_user_links,
        document_set_user_links=document_set_user_links,
        snapshot={
            **snapshot,
            "permission_inheritance": permission_inheritance.model_dump(),
            "service_accounts": service_accounts.model_dump(),
            "scim": scim.model_dump(),
            "query_history_usage": query_history_usage.model_dump(),
            "custom_permissions": custom_permissions.model_dump(),
            "usage_limits": usage_limits.model_dump(),
            "hooks": hooks.model_dump(),
            "custom_theming": custom_theming_snapshot,
            "white_labeling": white_labeling.model_dump(),
            "custom_deployments": custom_deployments.model_dump(),
            "region_processing": region_processing.model_dump(),
            "self_hosting": self_hosting.model_dump(),
            "secrets_encryption": secrets_encryption.model_dump(),
        },
    )
    recommended_next_actions = build_recommended_next_actions(health)
    remediation_commands = build_remediation_commands(
        health=health,
        profile_name=profile_name,
    )

    return SecurityPlatformRuntimeStatus(
        deployment_profile=profile_name,
        expected_profiles={
            "threat_intel_source_profile": expected_threat_profile,
            "security_tools_profile": expected_tools_profile,
        },
        required_env=required_env,
        missing_required_env=missing_required_env,
        placeholder_required_env=placeholder_required_env,
        deployment_profile_issues=deployment_profile_issues,
        threat_intel_source_profile=threat_intel_source_profile,
        security_tools_profile=security_tools_profile,
        threat_intel_sync=snapshot.get("threat_intel_sync", {}),
        threat_intel_corpus=snapshot.get("threat_intel_corpus", {}),
        historical_packages=snapshot.get("historical_packages", {}),
        playbooks=snapshot.get("playbooks", {}),
        health=health,
        recommended_next_actions=recommended_next_actions,
        remediation_commands=remediation_commands,
        document_set=document_set_status,
        personas=personas,
        tools=tools,
        tool_audit=tool_audit,
        tool_drift=tool_drift,
        failure_summary=failure_summary,
        permission_inheritance=permission_inheritance,
        service_accounts=service_accounts,
        scim=scim,
        query_history_usage=query_history_usage,
        custom_permissions=custom_permissions,
        usage_limits=usage_limits,
        hooks=hooks,
        custom_theming=custom_theming,
        white_labeling=white_labeling,
        custom_deployments=custom_deployments,
        region_processing=region_processing,
        self_hosting=self_hosting,
        secrets_encryption=secrets_encryption,
        security_users=security_users,
        rbac=rbac_summary,
    )
