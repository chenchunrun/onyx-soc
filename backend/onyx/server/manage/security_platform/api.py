from __future__ import annotations

from typing import Any
import json
from pathlib import Path

from fastapi import APIRouter
from fastapi import Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy.orm import Session

from onyx.auth.users import current_admin_user
from onyx.configs.constants import PUBLIC_API_TAGS
from onyx.db.document_set import get_document_set_by_name
from onyx.db.engine.sql_engine import get_session
from onyx.db.models import DocumentSet__User
from onyx.db.models import Persona
from onyx.db.models import Persona__User
from onyx.db.models import Tool
from onyx.db.models import User
from onyx.db.persona import get_personas
from onyx.db.tools import get_tools


router = APIRouter(prefix="/manage/admin/security-platform", tags=PUBLIC_API_TAGS)
SNAPSHOT_PATH = Path(__file__).resolve().parent / "static_snapshot.json"

SECURITY_DOCUMENT_SET_NAME = "安全知识库"
SECURITY_PERSONA_NAMES = {
    "安全事件分析师",
    "应急响应指挥官",
    "漏洞评估专家",
    "合规审计员",
}
SECURITY_USER_EMAILS = {
    "commander@security.local",
    "analyst@security.local",
    "vuln_expert@security.local",
    "auditor@security.local",
}
SECURITY_TOOL_NAMES = {
    "create_security_ticket",
    "send_security_alert",
    "threat_intel_lookup",
    "search_security_alerts",
    "isolate_endpoint_host",
    "lookup_asset_context",
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


class SecurityPlatformRuntimeStatus(BaseModel):
    deployment_profile: str
    expected_profiles: dict[str, str]
    required_env: list[str]
    missing_required_env: list[str]
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
    security_users: list[SecurityPlatformUserStatus]
    rbac: dict[str, int]


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
            status="failing" if (missing_required_env or deployment_issues) else "healthy",
            summary=f"profile={profile_name}, required_env={len(required_env)}, missing_env={len(missing_required_env)}",
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
    import os

    return [
        env_name
        for env_name in required_env
        if not str(os.environ.get(env_name, "")).strip()
    ]


def get_deployment_profile_issues(profile_name: str) -> list[str]:
    import os

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
    deployment_profile_issues = get_deployment_profile_issues(profile_name)

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
    health = build_health_status(
        profile_name=profile_name,
        expected_threat_profile=expected_threat_profile,
        expected_tools_profile=expected_tools_profile,
        threat_intel_source_profile=threat_intel_source_profile,
        security_tools_profile=security_tools_profile,
        required_env=required_env,
        missing_required_env=missing_required_env,
        deployment_profile_issues=deployment_profile_issues,
        document_set_status=document_set_status,
        personas=personas,
        tools=tools,
        security_users=security_users,
        persona_user_links=persona_user_links,
        document_set_user_links=document_set_user_links,
        snapshot=snapshot,
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
        security_users=security_users,
        rbac={
            "persona_user_links": persona_user_links,
            "document_set_user_links": document_set_user_links,
        },
    )
