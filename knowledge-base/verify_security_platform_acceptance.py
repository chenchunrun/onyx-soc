#!/usr/bin/env python3
"""
Minimal acceptance verification for the Onyx security platform customization.

Examples:
    python verify_security_platform_acceptance.py
    python verify_security_platform_acceptance.py --json
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import psycopg2
import requests
from sqlalchemy.orm import Mapper
import yaml
from ee.onyx.server.enterprise_settings.store import load_settings as load_enterprise_settings

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
REPO_ROOT = MODULE_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
BACKEND_ROOT = MODULE_DIR.parent / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from curate_threat_intel_corpus import build_unmanaged_report
from onyx.server.manage.security_platform.api import SecurityPlatformDocumentSetStatus
from onyx.server.manage.security_platform.api import SecurityPlatformPersonaStatus
from onyx.server.manage.security_platform.api import SecurityPlatformToolStatus
from onyx.server.manage.security_platform.api import SecurityPlatformUserStatus
from onyx.server.manage.security_platform.api import build_custom_theming_snapshot
from onyx.server.manage.security_platform.api import build_secrets_encryption_summary as build_runtime_secrets_encryption_summary
from onyx.server.manage.security_platform.api import build_health_status
from onyx.server.manage.security_platform.api import load_custom_deployment_summary
from onyx.server.manage.security_platform.api import load_region_processing_summary
from onyx.server.manage.security_platform.api import load_self_hosting_summary
from onyx.server.manage.security_platform.api import load_white_labeling_summary
from onyx.server.manage.security_platform.api import build_recommended_next_actions
from onyx.configs.constants import ONYX_DEFAULT_APPLICATION_NAME
from onyx.db.models import Base
from onyx.db.models import EncryptedJson
from onyx.db.models import EncryptedString

from assess_threat_intel_lifecycle import build_lifecycle_report
from check_threat_intel_historical_package_consistency import (
    evaluate_catalog_consistency,
)


SECURITY_DOCUMENT_SET_NAME = "安全知识库"
ROOT = MODULE_DIR
THREAT_INTEL_SYNC_PLAN_PATH = ROOT / "threat-intelligence" / "sync_plan.yaml"
THREAT_INTEL_SYNC_STATE_PATH = ROOT / "threat-intelligence" / "sync_state.json"
THREAT_INTEL_MANIFEST_PATH = ROOT / "threat-intelligence" / "feed_manifest.json"
THREAT_INTEL_CURATION_REPORT_PATH = ROOT / "threat-intelligence" / "unmanaged_feed_report.json"
SECURITY_TOOL_INTEGRATIONS_DIR = (
    ROOT.parent
    / "backend"
    / "onyx"
    / "server"
    / "manage"
    / "security_platform"
    / "tool_configs"
)
SECURITY_TOOL_PROFILES_PATH = SECURITY_TOOL_INTEGRATIONS_DIR / "profiles.yaml"
DEPLOYMENT_PROFILES_PATH = ROOT.parent / "docs" / "security-platform" / "deployment-profiles.yaml"
PLAYBOOKS_DIR = ROOT.parent / "docs" / "security-platform" / "playbooks"
HISTORICAL_PACKAGE_INDEX_PATH = (
    ROOT / "threat-intelligence" / "historical_packages" / "index.json"
)
ARCHIVE_BATCHES_PATH = ROOT / "threat-intelligence" / "archive_batches.json"
ARCHIVE_WORKLIST_DIR = ROOT / "threat-intelligence" / "archive_worklists"
ARCHIVE_PATCH_PREVIEW_DIR = ROOT / "threat-intelligence" / "archive_patch_previews"
ARCHIVE_ACTION_SCRIPT_DIR = ROOT / "threat-intelligence" / "archive_action_scripts"
ARCHIVE_EXECUTION_PLAN_DIR = ROOT / "threat-intelligence" / "archive_execution_plans"
ARCHIVE_EXECUTION_RECORD_DIR = ROOT / "threat-intelligence" / "archive_execution_records"
ARCHIVE_EXECUTION_RESULT_DIR = ROOT / "threat-intelligence" / "archive_execution_results"

SECURITY_PERSONA_BUILTIN_REQUIREMENTS = {
    "安全事件分析师": {"Internal Search", "Web Search", "Open URL"},
    "应急响应指挥官": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
    "漏洞评估专家": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
    "合规审计员": {"Internal Search", "Web Search", "Open URL"},
    "威胁狩猎工程师": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
    "恶意软件分析师": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
    "检测工程师": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
}

SECURITY_USERS = {
    "commander@security.local",
    "analyst@security.local",
    "vuln_expert@security.local",
    "auditor@security.local",
    "hunter@security.local",
    "malware@security.local",
    "detection@security.local",
}

USER_PERSONA_BY_EMAIL = {
    "commander@security.local": "应急响应指挥官",
    "analyst@security.local": "安全事件分析师",
    "vuln_expert@security.local": "漏洞评估专家",
    "auditor@security.local": "合规审计员",
    "hunter@security.local": "威胁狩猎工程师",
    "malware@security.local": "恶意软件分析师",
    "detection@security.local": "检测工程师",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def resolve_env_value(
    env_name: str,
    default: str,
    deployment_profile_summary: dict[str, Any] | None = None,
) -> str:
    explicit_value = os.environ.get(env_name, "").strip()
    if explicit_value:
        return explicit_value
    if deployment_profile_summary:
        profile_env = deployment_profile_summary.get("profile_env", {})
        if isinstance(profile_env, dict):
            derived_value = str(profile_env.get(env_name, "")).strip()
            if derived_value:
                return derived_value
    return default


def load_threat_intel_sync_summary(
    deployment_profile_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile = resolve_env_value(
        "THREAT_INTEL_SOURCE_PROFILE",
        "live",
        deployment_profile_summary,
    )
    last_sync_run_at = None
    due_feeds: list[str] = []

    try:
        with open(THREAT_INTEL_SYNC_PLAN_PATH, "r", encoding="utf-8") as handle:
            plan = yaml.safe_load(handle) or {}
    except Exception:
        plan = {}

    try:
        with open(THREAT_INTEL_SYNC_STATE_PATH, "r", encoding="utf-8") as handle:
            state = json.load(handle) or {}
    except Exception:
        state = {}

    if isinstance(state, dict):
        last_sync_run_at = state.get("last_sync_run_at")

    feeds = plan.get("feeds") if isinstance(plan, dict) else None
    feed_state_map = state.get("feeds", {}) if isinstance(state, dict) else {}
    if isinstance(feeds, list):
        now = _utc_now()
        for feed_config in feeds:
            if not isinstance(feed_config, dict):
                continue
            feed_name = str(feed_config.get("name", "")).strip()
            interval_hours = feed_config.get("min_refresh_interval_hours")
            if not feed_name or not isinstance(interval_hours, int) or interval_hours <= 0:
                continue
            last_success_at = None
            if isinstance(feed_state_map, dict):
                feed_state = feed_state_map.get(feed_name, {})
                if isinstance(feed_state, dict):
                    last_success_at = feed_state.get("last_success_at")
            parsed_last_success = (
                _parse_iso_datetime(str(last_success_at)) if last_success_at else None
            )
            if parsed_last_success is None:
                due_feeds.append(feed_name)
                continue
            if now - parsed_last_success >= timedelta(hours=interval_hours):
                due_feeds.append(feed_name)

    return {
        "source_profile": profile,
        "last_sync_run_at": last_sync_run_at,
        "due_feeds": due_feeds,
        "due_status": "DUE" if due_feeds else "WAIT",
    }


def load_threat_intel_curation_summary() -> dict[str, Any]:
    manifest_summary: dict[str, Any] = {}
    curation_summary: dict[str, Any] = {}
    lifecycle_summary: dict[str, Any] = {}

    try:
        with open(THREAT_INTEL_MANIFEST_PATH, "r", encoding="utf-8") as handle:
            manifest_doc = json.load(handle) or {}
    except Exception:
        manifest_doc = {}

    if isinstance(manifest_doc, dict):
        manifest_summary = manifest_doc.get("summary", {}) or {}

    try:
        curation_doc = build_unmanaged_report(THREAT_INTEL_MANIFEST_PATH)
    except Exception:
        curation_doc = {}

    if isinstance(curation_doc, dict):
        curation_summary = curation_doc.get("summary", {}) or {}

    try:
        lifecycle_doc = build_lifecycle_report(THREAT_INTEL_MANIFEST_PATH)
    except Exception:
        lifecycle_doc = {}

    if isinstance(lifecycle_doc, dict):
        lifecycle_summary = lifecycle_doc.get("summary", {}) or {}

    return {
        "governed_feeds": int(manifest_summary.get("total_feeds", 0) or 0),
        "governed_source_counts": manifest_summary.get("source_counts", {}) or {},
        "unmanaged_local_feeds": int(curation_summary.get("unmanaged_total", 0) or 0),
        "promotion_candidates": int(curation_summary.get("promotion_candidate_total", 0) or 0),
        "manual_review": int(curation_summary.get("manual_review_total", 0) or 0),
        "keep_runtime_only": int(curation_summary.get("keep_runtime_only_total", 0) or 0),
        "active_feeds": int(lifecycle_summary.get("active_total", 0) or 0),
        "archive_candidates": int(lifecycle_summary.get("archive_candidate_total", 0) or 0),
        "retained_historical": int(lifecycle_summary.get("retained_historical_total", 0) or 0),
        "quality_counts": lifecycle_summary.get("quality_counts", {}) or {},
    }


def load_security_tool_configs() -> list[dict[str, Any]]:
    configs: list[dict[str, Any]] = []
    if not SECURITY_TOOL_INTEGRATIONS_DIR.exists():
        return configs

    for config_path in sorted(SECURITY_TOOL_INTEGRATIONS_DIR.glob("*.yaml")):
        if config_path.name == SECURITY_TOOL_PROFILES_PATH.name:
            continue
        try:
            with open(config_path, "r", encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}
        except Exception:
            continue
        if isinstance(config, dict) and config.get("name"):
            configs.append(config)
    return configs


def load_playbook_definitions_summary() -> dict[str, Any]:
    playbooks: list[dict[str, Any]] = []
    invalid_files: list[str] = []
    if not PLAYBOOKS_DIR.exists():
        return {
            "count": 0,
            "names": [],
            "playbooks_with_examples": [],
            "invalid_files": [],
        }

    for path in sorted(PLAYBOOKS_DIR.glob("*.yaml")):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except Exception:
            invalid_files.append(path.name)
            continue
        if not isinstance(data, dict) or not str(data.get("name", "")).strip():
            invalid_files.append(path.name)
            continue
        playbooks.append(data)

    names = [str(playbook["name"]).strip() for playbook in playbooks]
    playbooks_with_examples = [
        str(playbook["name"]).strip()
        for playbook in playbooks
        if isinstance(playbook.get("example_inputs"), dict) and playbook.get("example_inputs")
    ]
    return {
        "count": len(names),
        "names": names,
        "playbooks_with_examples": playbooks_with_examples,
        "invalid_files": invalid_files,
    }


def load_historical_package_summary() -> dict[str, Any]:
    try:
        with open(HISTORICAL_PACKAGE_INDEX_PATH, "r", encoding="utf-8") as handle:
            index_doc = json.load(handle) or {}
    except Exception:
        index_doc = {}

    summary = index_doc.get("summary", {}) if isinstance(index_doc, dict) else {}
    packages = index_doc.get("packages", []) if isinstance(index_doc, dict) else []
    if not isinstance(summary, dict):
        summary = {}
    if not isinstance(packages, list):
        packages = []
    try:
        consistency_result = evaluate_catalog_consistency()
    except Exception:
        consistency_result = {
            "ok": False,
            "summary": {
                "package_count": len(packages),
                "consistent_package_count": 0,
                "issue_count": 1,
            },
            "issues": ["Failed to evaluate historical package consistency"],
        }

    return {
        "package_count": int(summary.get("package_count", 0) or 0),
        "total_item_count": int(summary.get("total_item_count", 0) or 0),
        "total_size_bytes": int(summary.get("total_size_bytes", 0) or 0),
        "package_ids": [
            str(package.get("batch_id")).strip()
            for package in packages
            if isinstance(package, dict) and str(package.get("batch_id", "")).strip()
        ],
        "packages": [
            {
                "batch_id": str(package.get("batch_id", "")).strip(),
                "description": str(package.get("description", "")).strip(),
                "item_count": int(package.get("item_count", 0) or 0),
                "total_size_bytes": int(package.get("total_size_bytes", 0) or 0),
                "manifest_path": str(package.get("manifest_path", "")).strip(),
                "readme_path": str(package.get("readme_path", "")).strip(),
                "recommended_action": str(
                    package.get("recommended_action", "")
                ).strip(),
                "source_counts": package.get("source_counts", {}) or {},
                "quality_counts": package.get("quality_counts", {}) or {},
                "year_counts": package.get("year_counts", {}) or {},
            }
            for package in packages
            if isinstance(package, dict) and str(package.get("batch_id", "")).strip()
        ],
        "consistency_ok": bool(consistency_result.get("ok")),
        "consistent_package_count": int(
            (consistency_result.get("summary", {}) or {}).get(
                "consistent_package_count", 0
            )
            or 0
        ),
        "consistency_issue_count": int(
            (consistency_result.get("summary", {}) or {}).get("issue_count", 0) or 0
        ),
        "consistency_issues": [
            str(issue).strip()
            for issue in consistency_result.get("issues", [])
            if str(issue).strip()
        ],
    }


def load_archive_execution_summary() -> dict[str, Any]:
    try:
        with open(ARCHIVE_BATCHES_PATH, "r", encoding="utf-8") as handle:
            archive_batches_doc = json.load(handle) or {}
    except Exception:
        archive_batches_doc = {}

    batches = archive_batches_doc.get("batches", []) if isinstance(archive_batches_doc, dict) else []
    if not isinstance(batches, list):
        batches = []

    artifact_counts = {
        "worklist": 0,
        "patch_preview": 0,
        "action_script": 0,
        "execution_plan": 0,
        "execution_record": 0,
        "execution_result": 0,
    }
    issues: list[str] = []
    batch_summaries: list[dict[str, Any]] = []

    for batch in batches:
        if not isinstance(batch, dict):
            continue
        batch_id = str(batch.get("batch_id", "")).strip()
        if not batch_id:
            continue

        artifact_paths = {
            "worklist": ARCHIVE_WORKLIST_DIR / f"{batch_id}.json",
            "patch_preview": ARCHIVE_PATCH_PREVIEW_DIR / f"{batch_id}.json",
            "action_script": ARCHIVE_ACTION_SCRIPT_DIR / f"{batch_id}.sh",
            "execution_plan": ARCHIVE_EXECUTION_PLAN_DIR / f"{batch_id}.md",
            "execution_record": ARCHIVE_EXECUTION_RECORD_DIR / f"{batch_id}.md",
            "execution_result": ARCHIVE_EXECUTION_RESULT_DIR / f"{batch_id}.json",
        }
        present_artifacts = {
            artifact_name: artifact_path.exists()
            for artifact_name, artifact_path in artifact_paths.items()
        }
        for artifact_name, exists in present_artifacts.items():
            if exists:
                artifact_counts[artifact_name] += 1
            else:
                issues.append(f"Archive batch {batch_id} missing artifact: {artifact_name}")

        result_issue_count = 0
        if present_artifacts["execution_result"]:
            try:
                with open(artifact_paths["execution_result"], "r", encoding="utf-8") as handle:
                    result_doc = json.load(handle) or {}
            except Exception:
                result_doc = {}
                issues.append(f"Archive batch {batch_id} has unreadable execution_result")
            if str(result_doc.get("batch_id", "")).strip() != batch_id:
                issues.append(
                    f"Archive batch {batch_id} execution_result batch_id mismatch"
                )
            result_issue_count = int(
                (result_doc.get("summary", {}) or {}).get("consistency_issue_count", 0) or 0
            )
            if result_issue_count > 0:
                issues.append(
                    f"Archive batch {batch_id} execution_result consistency issues: {result_issue_count}"
                )

        batch_summaries.append(
            {
                "batch_id": batch_id,
                "present_artifacts": present_artifacts,
                "execution_result_issue_count": result_issue_count,
            }
        )

    return {
        "batch_count": len(batch_summaries),
        "artifact_counts": artifact_counts,
        "fully_materialized_batch_count": sum(
            1
            for batch_summary in batch_summaries
            if all(batch_summary["present_artifacts"].values())
        ),
        "consistency_issue_count": len(issues),
        "consistency_issues": issues,
        "batches": batch_summaries,
    }


def build_expected_openapi_tools(configs: list[dict[str, Any]]) -> set[str]:
    return {
        str(config.get("name", "")).strip()
        for config in configs
        if str(config.get("name", "")).strip()
    }


def build_persona_tool_requirements(
    configs: list[dict[str, Any]],
) -> dict[str, dict[str, set[str]]]:
    requirements = {
        persona_name: {
            "builtin_tools": set(builtin_tools),
            "custom_tools": set(),
        }
        for persona_name, builtin_tools in SECURITY_PERSONA_BUILTIN_REQUIREMENTS.items()
    }

    for config in configs:
        tool_name = str(config.get("name", "")).strip()
        if not tool_name:
            continue
        for persona_name in config.get("persona_bindings", []):
            if persona_name not in requirements:
                continue
            requirements[persona_name]["custom_tools"].add(tool_name)

    return requirements


def load_security_tool_profile_summary(
    openapi_tools: list[dict[str, Any]],
    deployment_profile_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile_name = resolve_env_value(
        "SECURITY_TOOLS_PROFILE",
        "live",
        deployment_profile_summary,
    )
    configs = load_security_tool_configs()

    try:
        with open(SECURITY_TOOL_PROFILES_PATH, "r", encoding="utf-8") as handle:
            profiles_doc = yaml.safe_load(handle) or {}
    except Exception:
        profiles_doc = {}

    profiles = profiles_doc.get("profiles", {}) if isinstance(profiles_doc, dict) else {}
    profile = profiles.get(profile_name, {}) if isinstance(profiles, dict) else {}
    env_overrides = profile.get("env_overrides", {}) if isinstance(profile, dict) else {}
    if not isinstance(env_overrides, dict):
        env_overrides = {}

    openapi_tool_map = {
        str(tool.get("name")): tool for tool in openapi_tools if tool.get("name")
    }
    tool_summaries: dict[str, dict[str, Any]] = {}
    mismatches: list[str] = []

    for config in configs:
        tool_name = str(config.get("name", "")).strip()
        if not tool_name:
            continue
        tool = openapi_tool_map.get(tool_name, {})
        definition = tool.get("definition", {}) if isinstance(tool, dict) else {}
        servers = definition.get("servers", []) if isinstance(definition, dict) else []
        configured_server_url = None
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            configured_server_url = servers[0].get("url")

        custom_headers = tool.get("custom_headers", []) if isinstance(tool, dict) else []
        configured_header_keys = sorted(
            str(header.get("key"))
            for header in custom_headers
            if isinstance(header, dict) and header.get("key")
        )

        expected_server_url = None
        if config.get("webhook_url_env"):
            resolved_env_name = str(
                env_overrides.get(config["webhook_url_env"], config["webhook_url_env"])
            )
            expected_server_url = os.environ.get(resolved_env_name) or None
        elif config.get("api_url_env"):
            resolved_env_name = str(
                env_overrides.get(config["api_url_env"], config["api_url_env"])
            )
            expected_server_url = os.environ.get(resolved_env_name) or None

        expected_header_keys: list[str] = []
        if config.get("template") in {
            "security_ticket_api",
            "siem_search_api",
            "edr_response_api",
            "asset_inventory_api",
        }:
            expected_header_keys = ["Authorization"]
        elif config.get("template") == "threat_intel_api":
            expected_header_keys = ["x-apikey"]

        if expected_server_url and configured_server_url and expected_server_url != configured_server_url:
            mismatches.append(
                f"Tool {tool_name} server_url mismatch: expected {expected_server_url}, got {configured_server_url}"
            )

        if expected_header_keys and tool and configured_header_keys != expected_header_keys:
            mismatches.append(
                f"Tool {tool_name} header mismatch: expected {expected_header_keys}, got {configured_header_keys}"
            )

        tool_summaries[tool_name] = {
            "configured_server_url": configured_server_url,
            "configured_header_keys": configured_header_keys,
            "expected_server_url": expected_server_url,
            "expected_header_keys": expected_header_keys,
        }

    return {
        "profile": profile_name,
        "tools": tool_summaries,
        "mismatches": mismatches,
    }


def load_deployment_profile_summary() -> dict[str, Any]:
    deployment_profile = os.environ.get("SECURITY_PLATFORM_DEPLOYMENT_PROFILE", "live")
    try:
        with open(DEPLOYMENT_PROFILES_PATH, "r", encoding="utf-8") as handle:
            profiles_doc = yaml.safe_load(handle) or {}
    except Exception:
        profiles_doc = {}

    profiles = profiles_doc.get("profiles", {}) if isinstance(profiles_doc, dict) else {}
    profile = profiles.get(deployment_profile, {}) if isinstance(profiles, dict) else {}
    expectations = profile.get("expectations", {}) if isinstance(profile, dict) else {}
    if not isinstance(expectations, dict):
        expectations = {}
    required_env = profile.get("required_env", []) if isinstance(profile, dict) else []
    if not isinstance(required_env, list):
        required_env = []

    return {
        "deployment_profile": deployment_profile,
        "expected_threat_intel_source_profile": expectations.get(
            "threat_intel_source_profile"
        ),
        "expected_security_tools_profile": expectations.get("security_tools_profile"),
        "required_env": [str(env_name) for env_name in required_env if str(env_name).strip()],
        "profile_env": profile.get("env", {}) if isinstance(profile, dict) else {},
    }


def validate_deployment_profile_runtime(
    deployment_profile_summary: dict[str, Any],
) -> list[str]:
    issues: list[str] = []
    deployment_profile = str(
        deployment_profile_summary.get("deployment_profile", "live")
    ).strip()
    mock_server_url = resolve_env_value(
        "SECURITY_TOOLS_MOCK_SERVER_URL",
        "",
        deployment_profile_summary,
    )
    if (
        deployment_profile == "demo"
        and mock_server_url
        and (
            "localhost" in mock_server_url.lower()
            or "127.0.0.1" in mock_server_url
        )
    ):
        issues.append(
            "Deployment profile demo requires SECURITY_TOOLS_MOCK_SERVER_URL to be "
            "reachable from Docker containers; use host.docker.internal instead of "
            f"{mock_server_url}"
        )
    required_env = [
        str(env_name)
        for env_name in deployment_profile_summary.get("required_env", [])
        if str(env_name).strip()
    ]
    placeholder_env = get_placeholder_required_env(required_env, deployment_profile_summary)
    if placeholder_env:
        issues.append(
            "Required env vars still use placeholder/example values: "
            + ", ".join(sorted(placeholder_env))
        )
    return issues


def looks_like_placeholder_value(env_name: str, env_value: str) -> bool:
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


def get_placeholder_required_env(
    required_env: list[str],
    deployment_profile_summary: dict[str, Any] | None = None,
) -> list[str]:
    placeholders: list[str] = []
    for env_name in required_env:
        env_value = resolve_env_value(env_name, "", deployment_profile_summary)
        if looks_like_placeholder_value(env_name, env_value):
            placeholders.append(env_name)
    return placeholders


def get_cookie(base_url: str, email: str, password: str) -> str | None:
    try:
        response = requests.post(
            f"{base_url}/auth/login",
            data={"username": email, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        if response.status_code == 204:
            cookie = response.headers.get("set-cookie", "")
            for part in cookie.split(","):
                part = part.strip()
                if "fastapiusersauth=" in part:
                    return part.split(";")[0].split("=")[1]
    except Exception as exc:
        print(f"  [WARN] Login failed: {exc}")
    return None


def list_document_sets(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/manage/document-set?get_editable=true",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def list_personas(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/persona",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def get_persona(base_url: str, cookie: str, persona_id: int) -> dict[str, Any]:
    response = requests.get(
        f"{base_url}/persona/{persona_id}",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def list_openapi_tools(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/tool/openapi",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def list_ingestion_documents(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/onyx-api/ingestion",
        cookies={"fastapiusersauth": cookie},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def get_db_connection(password: str | None = None):
    if password is None:
        for pwd in [
            os.environ.get("POSTGRES_PASSWORD", ""),
            "password",
            "postgres",
            "onyx",
            "",
        ]:
            if not pwd:
                continue
            try:
                conn = psycopg2.connect(
                    host="localhost",
                    port=5432,
                    database="postgres",
                    user="postgres",
                    password=pwd,
                    connect_timeout=3,
                )
                conn.close()
                password = pwd
                break
            except Exception:
                continue

        if password is None:
            raise RuntimeError("Could not connect to PostgreSQL with known passwords")

    return psycopg2.connect(
        host="localhost",
        port=5432,
        database="postgres",
        user="postgres",
        password=password,
    )


def _sql_quote(value: str) -> str:
    return value.replace("'", "''")


def _detect_relational_db_container() -> str:
    """Auto-detect the relational DB container name."""
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    for name in result.stdout.splitlines():
        if "relational_db" in name or "postgres" in name or "database" in name:
            return name
    return "onyx-relational_db-1"


def run_docker_psql_query(sql: str) -> list[list[str]]:
    container = _detect_relational_db_container()
    result = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "psql",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-q",
            "-At",
            "-F",
            "\t",
            "-c",
            sql,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    return [line.split("\t") for line in lines]


def fetch_db_state_via_docker() -> dict[str, Any]:
    persona_names = list(SECURITY_PERSONA_BUILTIN_REQUIREMENTS.keys())
    persona_name_sql = ", ".join(f"'{_sql_quote(name)}'" for name in persona_names)
    security_user_sql = ", ".join(f"'{_sql_quote(email)}'" for email in SECURITY_USERS)

    persona_rows_result = run_docker_psql_query(
        "SELECT id, name, is_public::text FROM persona "
        f"WHERE name IN ({persona_name_sql});"
    )
    persona_rows = {
        row[1]: {"id": int(row[0]), "is_public": row[2] == "t"}
        for row in persona_rows_result
    }

    document_set_result = run_docker_psql_query(
        "SELECT id FROM document_set "
        f"WHERE name = '{_sql_quote(SECURITY_DOCUMENT_SET_NAME)}' LIMIT 1;"
    )
    document_set_id = int(document_set_result[0][0]) if document_set_result else None

    user_rows_result = run_docker_psql_query(
        'SELECT id::text, email FROM "user" '
        f"WHERE email IN ({security_user_sql});"
    )
    user_rows = {row[1]: row[0] for row in user_rows_result}

    persona_ids = [row["id"] for row in persona_rows.values()]
    if persona_ids:
        persona_ids_sql = ", ".join(str(persona_id) for persona_id in persona_ids)
        persona_user_links = {
            (int(row[0]), row[1])
            for row in run_docker_psql_query(
                "SELECT persona_id, user_id::text FROM persona__user "
                f"WHERE persona_id IN ({persona_ids_sql});"
            )
        }
    else:
        persona_user_links = set()

    if document_set_id and user_rows:
        user_ids_sql = ", ".join(f"'{_sql_quote(user_id)}'" for user_id in user_rows.values())
        document_set_links = {
            (int(row[0]), row[1])
            for row in run_docker_psql_query(
                "SELECT document_set_id, user_id::text FROM document_set__user "
                f"WHERE document_set_id = {document_set_id} AND user_id::text IN ({user_ids_sql});"
            )
        }
    else:
        document_set_links = set()

    sync_cc_pair_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM connector_credential_pair WHERE access_type = 'SYNC';"
    )
    sync_cc_pair_count = (
        int(sync_cc_pair_count_result[0][0]) if sync_cc_pair_count_result else 0
    )
    docs_with_user_acl_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM document WHERE cardinality(external_user_emails) > 0;"
    )
    docs_with_user_acl_count = (
        int(docs_with_user_acl_result[0][0]) if docs_with_user_acl_result else 0
    )
    docs_with_group_acl_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM document WHERE cardinality(external_user_group_ids) > 0;"
    )
    docs_with_group_acl_count = (
        int(docs_with_group_acl_result[0][0]) if docs_with_group_acl_result else 0
    )
    docs_with_external_acl_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM document "
        "WHERE cardinality(external_user_emails) > 0 "
        "OR cardinality(external_user_group_ids) > 0;"
    )
    docs_with_external_acl_count = (
        int(docs_with_external_acl_result[0][0])
        if docs_with_external_acl_result
        else 0
    )
    recent_doc_sync_failure_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM doc_permission_sync_attempt "
        "WHERE error_message IS NOT NULL;"
    )
    recent_doc_sync_failure_count = (
        int(recent_doc_sync_failure_result[0][0])
        if recent_doc_sync_failure_result
        else 0
    )
    recent_group_sync_failure_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM external_group_permission_sync_attempt "
        "WHERE error_message IS NOT NULL;"
    )
    recent_group_sync_failure_count = (
        int(recent_group_sync_failure_result[0][0])
        if recent_group_sync_failure_result
        else 0
    )
    query_history_type = os.environ.get("ONYX_QUERY_HISTORY_TYPE", "normal").strip().lower()
    query_history_enabled = query_history_type != "disabled"
    recent_query_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM chat_message "
        "WHERE message_type = 'ASSISTANT' "
        "AND time_sent >= NOW() - INTERVAL '30 days';"
    )
    recent_query_count = int(recent_query_count_result[0][0]) if recent_query_count_result else 0
    recent_chat_session_count_result = run_docker_psql_query(
        "SELECT COUNT(DISTINCT chat_session_id) FROM chat_message "
        "WHERE message_type = 'ASSISTANT' "
        "AND time_sent >= NOW() - INTERVAL '30 days';"
    )
    recent_chat_session_count = (
        int(recent_chat_session_count_result[0][0])
        if recent_chat_session_count_result
        else 0
    )
    recent_active_user_count_result = run_docker_psql_query(
        "SELECT COUNT(DISTINCT chat_session.user_id) "
        "FROM chat_message "
        "JOIN chat_session ON chat_session.id = chat_message.chat_session_id "
        "WHERE chat_message.message_type = 'ASSISTANT' "
        "AND chat_message.time_sent >= NOW() - INTERVAL '30 days' "
        "AND chat_session.user_id IS NOT NULL;"
    )
    recent_active_user_count = (
        int(recent_active_user_count_result[0][0])
        if recent_active_user_count_result
        else 0
    )
    recent_like_count_result = run_docker_psql_query(
        "SELECT COUNT(*) "
        "FROM chat_feedback "
        "JOIN chat_message ON chat_message.id = chat_feedback.chat_message_id "
        "WHERE chat_message.message_type = 'ASSISTANT' "
        "AND chat_message.time_sent >= NOW() - INTERVAL '30 days' "
        "AND chat_feedback.is_positive = true;"
    )
    recent_like_count = int(recent_like_count_result[0][0]) if recent_like_count_result else 0
    recent_dislike_count_result = run_docker_psql_query(
        "SELECT COUNT(*) "
        "FROM chat_feedback "
        "JOIN chat_message ON chat_message.id = chat_feedback.chat_message_id "
        "WHERE chat_message.message_type = 'ASSISTANT' "
        "AND chat_message.time_sent >= NOW() - INTERVAL '30 days' "
        "AND chat_feedback.is_positive = false;"
    )
    recent_dislike_count = (
        int(recent_dislike_count_result[0][0]) if recent_dislike_count_result else 0
    )
    recent_export_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM task_queue_jobs "
        "WHERE task_name LIKE 'export_query_history_task_%';"
    )
    recent_export_count = int(recent_export_count_result[0][0]) if recent_export_count_result else 0
    recent_export_failure_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM task_queue_jobs "
        "WHERE task_name LIKE 'export_query_history_task_%' "
        "AND status = 'FAILED';"
    )
    recent_export_failure_count = (
        int(recent_export_failure_count_result[0][0])
        if recent_export_failure_count_result
        else 0
    )
    default_group_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM user_group WHERE is_default = true;"
    )
    default_group_count = int(default_group_count_result[0][0]) if default_group_count_result else 0
    custom_group_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM user_group WHERE is_default = false;"
    )
    custom_group_count = int(custom_group_count_result[0][0]) if custom_group_count_result else 0
    stale_custom_group_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM user_group "
        "WHERE is_default = false AND is_up_to_date = false AND is_up_for_deletion = false;"
    )
    stale_custom_group_count = (
        int(stale_custom_group_count_result[0][0])
        if stale_custom_group_count_result
        else 0
    )
    groups_with_custom_grants_count_result = run_docker_psql_query(
        "SELECT COUNT(DISTINCT permission_grant.group_id) "
        "FROM permission_grant "
        "JOIN user_group ON user_group.id = permission_grant.group_id "
        "WHERE user_group.is_default = false "
        "AND permission_grant.is_deleted = false "
        "AND permission_grant.permission <> 'basic';"
    )
    groups_with_custom_grants_count = (
        int(groups_with_custom_grants_count_result[0][0])
        if groups_with_custom_grants_count_result
        else 0
    )
    custom_permission_rows = run_docker_psql_query(
        "SELECT permission, COUNT(*) "
        "FROM permission_grant "
        "JOIN user_group ON user_group.id = permission_grant.group_id "
        "WHERE user_group.is_default = false "
        "AND permission_grant.is_deleted = false "
        "AND permission_grant.permission <> 'basic' "
        "GROUP BY permission;"
    )
    permission_counts = {
        str(row[0]): int(row[1]) for row in custom_permission_rows if row and row[0]
    }
    manual_grant_count_result = run_docker_psql_query(
        "SELECT COUNT(*) "
        "FROM permission_grant "
        "JOIN user_group ON user_group.id = permission_grant.group_id "
        "WHERE user_group.is_default = false "
        "AND permission_grant.is_deleted = false "
        "AND permission_grant.permission <> 'basic' "
        "AND permission_grant.grant_source = 'USER';"
    )
    manual_grant_count = int(manual_grant_count_result[0][0]) if manual_grant_count_result else 0
    scim_grant_count_result = run_docker_psql_query(
        "SELECT COUNT(*) "
        "FROM permission_grant "
        "JOIN user_group ON user_group.id = permission_grant.group_id "
        "WHERE user_group.is_default = false "
        "AND permission_grant.is_deleted = false "
        "AND permission_grant.permission <> 'basic' "
        "AND permission_grant.grant_source = 'SCIM';"
    )
    scim_grant_count = int(scim_grant_count_result[0][0]) if scim_grant_count_result else 0
    admin_override_group_count_result = run_docker_psql_query(
        "SELECT COUNT(DISTINCT permission_grant.group_id) "
        "FROM permission_grant "
        "JOIN user_group ON user_group.id = permission_grant.group_id "
        "WHERE user_group.is_default = false "
        "AND permission_grant.is_deleted = false "
        "AND permission_grant.permission = 'admin';"
    )
    admin_override_group_count = (
        int(admin_override_group_count_result[0][0])
        if admin_override_group_count_result
        else 0
    )
    usage_limits_enabled = (
        os.environ.get("USAGE_LIMITS_ENABLED", "").strip().lower() == "true"
    )
    global_limit_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM token_rate_limit WHERE scope = 'global';"
    )
    global_limit_count = int(global_limit_count_result[0][0]) if global_limit_count_result else 0
    enabled_global_limit_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM token_rate_limit WHERE scope = 'global' AND enabled = true;"
    )
    enabled_global_limit_count = (
        int(enabled_global_limit_count_result[0][0])
        if enabled_global_limit_count_result
        else 0
    )
    user_limit_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM token_rate_limit WHERE scope = 'user';"
    )
    user_limit_count = int(user_limit_count_result[0][0]) if user_limit_count_result else 0
    enabled_user_limit_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM token_rate_limit WHERE scope = 'user' AND enabled = true;"
    )
    enabled_user_limit_count = (
        int(enabled_user_limit_count_result[0][0])
        if enabled_user_limit_count_result
        else 0
    )
    user_group_limit_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM token_rate_limit WHERE scope = 'user_group';"
    )
    user_group_limit_count = (
        int(user_group_limit_count_result[0][0])
        if user_group_limit_count_result
        else 0
    )
    enabled_user_group_limit_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM token_rate_limit WHERE scope = 'user_group' AND enabled = true;"
    )
    enabled_user_group_limit_count = (
        int(enabled_user_group_limit_count_result[0][0])
        if enabled_user_group_limit_count_result
        else 0
    )
    limited_user_group_count_result = run_docker_psql_query(
        "SELECT COUNT(DISTINCT token_rate_limit__user_group.user_group_id) "
        "FROM token_rate_limit__user_group "
        "JOIN token_rate_limit ON token_rate_limit.id = token_rate_limit__user_group.rate_limit_id "
        "WHERE token_rate_limit.enabled = true;"
    )
    limited_user_group_count = (
        int(limited_user_group_count_result[0][0])
        if limited_user_group_count_result
        else 0
    )
    hooks_enabled = os.environ.get("MULTI_TENANT", "").strip().lower() not in {
        "true",
        "1",
        "yes",
    }
    custom_theming = build_custom_theming_snapshot(load_enterprise_settings())
    white_labeling = load_white_labeling_summary(custom_theming).model_dump()
    custom_deployments = load_custom_deployment_summary().model_dump()
    region_processing = load_region_processing_summary().model_dump()
    self_hosting = load_self_hosting_summary().model_dump()
    user_group_count_result = run_docker_psql_query("SELECT COUNT(*) FROM user_group;")
    user_group_count = int(user_group_count_result[0][0]) if user_group_count_result else 0
    permission_grant_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM permission_grant WHERE is_deleted = false;"
    )
    permission_grant_count = (
        int(permission_grant_count_result[0][0]) if permission_grant_count_result else 0
    )
    users_with_effective_permissions_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM \"user\" WHERE jsonb_array_length(effective_permissions) > 0;"
    )
    users_with_effective_permissions_count = (
        int(users_with_effective_permissions_result[0][0])
        if users_with_effective_permissions_result
        else 0
    )
    curator_membership_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM user__user_group WHERE is_curator = true;"
    )
    curator_membership_count = (
        int(curator_membership_count_result[0][0])
        if curator_membership_count_result
        else 0
    )
    api_key_count_result = run_docker_psql_query("SELECT COUNT(*) FROM api_key;")
    api_key_count = int(api_key_count_result[0][0]) if api_key_count_result else 0
    service_account_user_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM \"user\" WHERE account_type = 'SERVICE_ACCOUNT';"
    )
    service_account_user_count = (
        int(service_account_user_count_result[0][0])
        if service_account_user_count_result
        else 0
    )
    ownerless_api_key_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM api_key WHERE owner_id IS NULL;"
    )
    ownerless_api_key_count = (
        int(ownerless_api_key_count_result[0][0])
        if ownerless_api_key_count_result
        else 0
    )
    active_scim_token_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM scim_token WHERE is_active = true;"
    )
    active_scim_token_count = (
        int(active_scim_token_count_result[0][0])
        if active_scim_token_count_result
        else 0
    )
    scim_user_mapping_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM scim_user_mapping;"
    )
    scim_user_mapping_count = (
        int(scim_user_mapping_count_result[0][0])
        if scim_user_mapping_count_result
        else 0
    )
    scim_group_mapping_count_result = run_docker_psql_query(
        "SELECT COUNT(*) FROM scim_group_mapping;"
    )
    scim_group_mapping_count = (
        int(scim_group_mapping_count_result[0][0])
        if scim_group_mapping_count_result
        else 0
    )

    return {
        "persona_rows": persona_rows,
        "document_set_id": document_set_id,
        "user_rows": user_rows,
        "persona_user_links": persona_user_links,
        "document_set_links": document_set_links,
        "rbac": {
            "user_group_count": user_group_count,
            "permission_grant_count": permission_grant_count,
            "users_with_effective_permissions_count": users_with_effective_permissions_count,
            "curator_membership_count": curator_membership_count,
        },
        "service_accounts": {
            "api_key_count": api_key_count,
            "service_account_user_count": service_account_user_count,
            "ownerless_api_key_count": ownerless_api_key_count,
        },
        "scim": {
            "active_token_count": active_scim_token_count,
            "user_mapping_count": scim_user_mapping_count,
            "group_mapping_count": scim_group_mapping_count,
            "recent_group_sync_failure_count": recent_group_sync_failure_count,
        },
        "permission_inheritance": {
            "sync_cc_pair_count": sync_cc_pair_count,
            "docs_with_external_acl_count": docs_with_external_acl_count,
            "docs_with_user_acl_count": docs_with_user_acl_count,
            "docs_with_group_acl_count": docs_with_group_acl_count,
            "recent_doc_sync_failure_count": recent_doc_sync_failure_count,
            "recent_group_sync_failure_count": recent_group_sync_failure_count,
        },
        "query_history_usage": {
            "query_history_type": query_history_type,
            "query_history_enabled": query_history_enabled,
            "recent_query_count": recent_query_count,
            "recent_chat_session_count": recent_chat_session_count,
            "recent_active_user_count": recent_active_user_count,
            "recent_like_count": recent_like_count,
            "recent_dislike_count": recent_dislike_count,
            "recent_export_count": recent_export_count,
            "recent_export_failure_count": recent_export_failure_count,
            "recent_exports": [],
        },
        "custom_permissions": {
            "default_group_count": default_group_count,
            "custom_group_count": custom_group_count,
            "stale_custom_group_count": stale_custom_group_count,
            "groups_with_custom_grants_count": groups_with_custom_grants_count,
            "custom_permission_count": len(permission_counts),
            "manual_grant_count": manual_grant_count,
            "scim_grant_count": scim_grant_count,
            "admin_override_group_count": admin_override_group_count,
            "permission_counts": permission_counts,
        },
        "usage_limits": {
            "enabled": usage_limits_enabled,
            "global_limit_count": global_limit_count,
            "enabled_global_limit_count": enabled_global_limit_count,
            "user_limit_count": user_limit_count,
            "enabled_user_limit_count": enabled_user_limit_count,
            "user_group_limit_count": user_group_limit_count,
            "enabled_user_group_limit_count": enabled_user_group_limit_count,
            "limited_user_group_count": limited_user_group_count,
        },
        "hooks": {
            "hooks_enabled": hooks_enabled,
            "supported_hook_point_count": 2,
            "configured_hook_count": 0,
            "active_hook_count": 0,
            "reachable_hook_count": 0,
            "recent_execution_count": 0,
            "recent_failure_count": 0,
            "hook_point_names": [
                "document_ingestion",
                "query_processing",
            ],
            "recent_executions": [],
        },
        "custom_theming": custom_theming,
        "white_labeling": white_labeling,
        "custom_deployments": custom_deployments,
        "region_processing": region_processing,
        "self_hosting": self_hosting,
    }


def fetch_db_state(db_password: str | None = None) -> dict[str, Any]:
    try:
        conn = get_db_connection(password=db_password)
        try:
            with conn.cursor() as cur:
                persona_names = list(SECURITY_PERSONA_BUILTIN_REQUIREMENTS.keys())
                cur.execute(
                    "SELECT id, name, is_public FROM persona WHERE name = ANY(%s)",
                    (persona_names,),
                )
                persona_rows = {
                    row[1]: {"id": row[0], "is_public": row[2]} for row in cur.fetchall()
                }

                cur.execute(
                    "SELECT id FROM document_set WHERE name = %s",
                    (SECURITY_DOCUMENT_SET_NAME,),
                )
                row = cur.fetchone()
                document_set_id = row[0] if row else None

                cur.execute(
                    'SELECT id::text, email FROM "user" WHERE email = ANY(%s)',
                    (list(SECURITY_USERS),),
                )
                user_rows = {row[1]: row[0] for row in cur.fetchall()}

                cur.execute(
                    "SELECT persona_id, user_id::text FROM persona__user "
                    "WHERE persona_id = ANY(%s)",
                    ([persona["id"] for persona in persona_rows.values()],),
                )
                persona_user_links = {(row[0], row[1]) for row in cur.fetchall()}

                if document_set_id and user_rows:
                    cur.execute(
                        "SELECT document_set_id, user_id::text FROM document_set__user "
                        "WHERE document_set_id = %s AND user_id::text = ANY(%s)",
                        (document_set_id, list(user_rows.values())),
                    )
                    document_set_links = {(row[0], row[1]) for row in cur.fetchall()}
                else:
                    document_set_links = set()

                cur.execute(
                    "SELECT COUNT(*) FROM connector_credential_pair WHERE access_type = 'SYNC'"
                )
                sync_cc_pair_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM document WHERE cardinality(external_user_emails) > 0"
                )
                docs_with_user_acl_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM document WHERE cardinality(external_user_group_ids) > 0"
                )
                docs_with_group_acl_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM document "
                    "WHERE cardinality(external_user_emails) > 0 "
                    "OR cardinality(external_user_group_ids) > 0"
                )
                docs_with_external_acl_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM doc_permission_sync_attempt "
                    "WHERE error_message IS NOT NULL"
                )
                recent_doc_sync_failure_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM external_group_permission_sync_attempt "
                    "WHERE error_message IS NOT NULL"
                )
                recent_group_sync_failure_count = int(cur.fetchone()[0])

                cur.execute("SELECT COUNT(*) FROM user_group")
                user_group_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM permission_grant WHERE is_deleted = false"
                )
                permission_grant_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM \"user\" "
                    "WHERE jsonb_array_length(effective_permissions) > 0"
                )
                users_with_effective_permissions_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM user__user_group WHERE is_curator = true"
                )
                curator_membership_count = int(cur.fetchone()[0])

                cur.execute("SELECT COUNT(*) FROM api_key")
                api_key_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM \"user\" WHERE account_type = 'SERVICE_ACCOUNT'"
                )
                service_account_user_count = int(cur.fetchone()[0])

                cur.execute("SELECT COUNT(*) FROM api_key WHERE owner_id IS NULL")
                ownerless_api_key_count = int(cur.fetchone()[0])

                cur.execute("SELECT COUNT(*) FROM scim_token WHERE is_active = true")
                active_scim_token_count = int(cur.fetchone()[0])

                cur.execute("SELECT COUNT(*) FROM scim_user_mapping")
                scim_user_mapping_count = int(cur.fetchone()[0])

                cur.execute("SELECT COUNT(*) FROM scim_group_mapping")
                scim_group_mapping_count = int(cur.fetchone()[0])

                query_history_type = os.environ.get(
                    "ONYX_QUERY_HISTORY_TYPE", "normal"
                ).strip().lower()
                query_history_enabled = query_history_type != "disabled"
                cur.execute(
                    "SELECT COUNT(*) FROM chat_message "
                    "WHERE message_type = 'ASSISTANT' "
                    "AND time_sent >= NOW() - INTERVAL '30 days'"
                )
                recent_query_count = int(cur.fetchone()[0])
                cur.execute(
                    "SELECT COUNT(DISTINCT chat_session_id) FROM chat_message "
                    "WHERE message_type = 'ASSISTANT' "
                    "AND time_sent >= NOW() - INTERVAL '30 days'"
                )
                recent_chat_session_count = int(cur.fetchone()[0])
                cur.execute(
                    "SELECT COUNT(DISTINCT chat_session.user_id) "
                    "FROM chat_message "
                    "JOIN chat_session ON chat_session.id = chat_message.chat_session_id "
                    "WHERE chat_message.message_type = 'ASSISTANT' "
                    "AND chat_message.time_sent >= NOW() - INTERVAL '30 days' "
                    "AND chat_session.user_id IS NOT NULL"
                )
                recent_active_user_count = int(cur.fetchone()[0])
                cur.execute(
                    "SELECT COUNT(*) "
                    "FROM chat_feedback "
                    "JOIN chat_message ON chat_message.id = chat_feedback.chat_message_id "
                    "WHERE chat_message.message_type = 'ASSISTANT' "
                    "AND chat_message.time_sent >= NOW() - INTERVAL '30 days' "
                    "AND chat_feedback.is_positive = true"
                )
                recent_like_count = int(cur.fetchone()[0])
                cur.execute(
                    "SELECT COUNT(*) "
                    "FROM chat_feedback "
                    "JOIN chat_message ON chat_message.id = chat_feedback.chat_message_id "
                    "WHERE chat_message.message_type = 'ASSISTANT' "
                    "AND chat_message.time_sent >= NOW() - INTERVAL '30 days' "
                    "AND chat_feedback.is_positive = false"
                )
                recent_dislike_count = int(cur.fetchone()[0])
                cur.execute(
                    "SELECT COUNT(*) FROM task_queue_jobs "
                    "WHERE task_name LIKE 'export_query_history_task_%'"
                )
                recent_export_count = int(cur.fetchone()[0])
                cur.execute(
                    "SELECT COUNT(*) FROM task_queue_jobs "
                    "WHERE task_name LIKE 'export_query_history_task_%' "
                    "AND status = 'FAILED'"
                )
                recent_export_failure_count = int(cur.fetchone()[0])

                cur.execute("SELECT COUNT(*) FROM user_group WHERE is_default = true")
                default_group_count = int(cur.fetchone()[0])

                cur.execute("SELECT COUNT(*) FROM user_group WHERE is_default = false")
                custom_group_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM user_group "
                    "WHERE is_default = false AND is_up_to_date = false AND is_up_for_deletion = false"
                )
                stale_custom_group_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(DISTINCT permission_grant.group_id) "
                    "FROM permission_grant "
                    "JOIN user_group ON user_group.id = permission_grant.group_id "
                    "WHERE user_group.is_default = false "
                    "AND permission_grant.is_deleted = false "
                    "AND permission_grant.permission <> 'basic'"
                )
                groups_with_custom_grants_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT permission, COUNT(*) "
                    "FROM permission_grant "
                    "JOIN user_group ON user_group.id = permission_grant.group_id "
                    "WHERE user_group.is_default = false "
                    "AND permission_grant.is_deleted = false "
                    "AND permission_grant.permission <> 'basic' "
                    "GROUP BY permission"
                )
                permission_counts = {
                    str(row[0]): int(row[1]) for row in cur.fetchall() if row[0]
                }

                cur.execute(
                    "SELECT COUNT(*) "
                    "FROM permission_grant "
                    "JOIN user_group ON user_group.id = permission_grant.group_id "
                    "WHERE user_group.is_default = false "
                    "AND permission_grant.is_deleted = false "
                    "AND permission_grant.permission <> 'basic' "
                    "AND permission_grant.grant_source = 'USER'"
                )
                manual_grant_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) "
                    "FROM permission_grant "
                    "JOIN user_group ON user_group.id = permission_grant.group_id "
                    "WHERE user_group.is_default = false "
                    "AND permission_grant.is_deleted = false "
                    "AND permission_grant.permission <> 'basic' "
                    "AND permission_grant.grant_source = 'SCIM'"
                )
                scim_grant_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(DISTINCT permission_grant.group_id) "
                    "FROM permission_grant "
                    "JOIN user_group ON user_group.id = permission_grant.group_id "
                    "WHERE user_group.is_default = false "
                    "AND permission_grant.is_deleted = false "
                    "AND permission_grant.permission = 'admin'"
                )
                admin_override_group_count = int(cur.fetchone()[0])

                usage_limits_enabled = (
                    os.environ.get("USAGE_LIMITS_ENABLED", "").strip().lower()
                    == "true"
                )
                cur.execute(
                    "SELECT COUNT(*) FROM token_rate_limit WHERE scope = 'global'"
                )
                global_limit_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM token_rate_limit "
                    "WHERE scope = 'global' AND enabled = true"
                )
                enabled_global_limit_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM token_rate_limit WHERE scope = 'user'"
                )
                user_limit_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM token_rate_limit "
                    "WHERE scope = 'user' AND enabled = true"
                )
                enabled_user_limit_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM token_rate_limit WHERE scope = 'user_group'"
                )
                user_group_limit_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM token_rate_limit "
                    "WHERE scope = 'user_group' AND enabled = true"
                )
                enabled_user_group_limit_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(DISTINCT token_rate_limit__user_group.user_group_id) "
                    "FROM token_rate_limit__user_group "
                    "JOIN token_rate_limit ON token_rate_limit.id = token_rate_limit__user_group.rate_limit_id "
                    "WHERE token_rate_limit.enabled = true"
                )
                limited_user_group_count = int(cur.fetchone()[0])

                hooks_enabled = os.environ.get("MULTI_TENANT", "").strip().lower() not in {
                    "true",
                    "1",
                    "yes",
                }

                cur.execute(
                    "SELECT COUNT(*) FROM hook WHERE deleted = false"
                )
                configured_hook_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM hook WHERE deleted = false AND is_active = true"
                )
                active_hook_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM hook "
                    "WHERE deleted = false AND is_active = true AND is_reachable = true"
                )
                reachable_hook_count = int(cur.fetchone()[0])

                cur.execute("SELECT COUNT(*) FROM hook_execution_log")
                recent_hook_execution_count = int(cur.fetchone()[0])

                cur.execute(
                    "SELECT COUNT(*) FROM hook_execution_log WHERE is_success = false"
                )
                recent_hook_failure_count = int(cur.fetchone()[0])
        finally:
            conn.close()

        custom_theming = build_custom_theming_snapshot(load_enterprise_settings())
        white_labeling = load_white_labeling_summary(custom_theming).model_dump()
        custom_deployments = load_custom_deployment_summary().model_dump()
        region_processing = load_region_processing_summary().model_dump()
        self_hosting = load_self_hosting_summary().model_dump()

        return {
            "persona_rows": persona_rows,
            "document_set_id": document_set_id,
            "user_rows": user_rows,
            "persona_user_links": persona_user_links,
            "document_set_links": document_set_links,
            "rbac": {
                "user_group_count": user_group_count,
                "permission_grant_count": permission_grant_count,
                "users_with_effective_permissions_count": users_with_effective_permissions_count,
                "curator_membership_count": curator_membership_count,
            },
            "service_accounts": {
                "api_key_count": api_key_count,
                "service_account_user_count": service_account_user_count,
                "ownerless_api_key_count": ownerless_api_key_count,
            },
            "scim": {
                "active_token_count": active_scim_token_count,
                "user_mapping_count": scim_user_mapping_count,
                "group_mapping_count": scim_group_mapping_count,
                "recent_group_sync_failure_count": recent_group_sync_failure_count,
            },
            "permission_inheritance": {
                "sync_cc_pair_count": sync_cc_pair_count,
                "docs_with_external_acl_count": docs_with_external_acl_count,
                "docs_with_user_acl_count": docs_with_user_acl_count,
                "docs_with_group_acl_count": docs_with_group_acl_count,
                "recent_doc_sync_failure_count": recent_doc_sync_failure_count,
                "recent_group_sync_failure_count": recent_group_sync_failure_count,
            },
            "query_history_usage": {
                "query_history_type": query_history_type,
                "query_history_enabled": query_history_enabled,
                "recent_query_count": recent_query_count,
                "recent_chat_session_count": recent_chat_session_count,
                "recent_active_user_count": recent_active_user_count,
                "recent_like_count": recent_like_count,
                "recent_dislike_count": recent_dislike_count,
                "recent_export_count": recent_export_count,
                "recent_export_failure_count": recent_export_failure_count,
                "recent_exports": [],
            },
            "custom_permissions": {
                "default_group_count": default_group_count,
                "custom_group_count": custom_group_count,
                "stale_custom_group_count": stale_custom_group_count,
                "groups_with_custom_grants_count": groups_with_custom_grants_count,
                "custom_permission_count": len(permission_counts),
                "manual_grant_count": manual_grant_count,
                "scim_grant_count": scim_grant_count,
                "admin_override_group_count": admin_override_group_count,
                "permission_counts": permission_counts,
            },
            "usage_limits": {
                "enabled": usage_limits_enabled,
                "global_limit_count": global_limit_count,
                "enabled_global_limit_count": enabled_global_limit_count,
                "user_limit_count": user_limit_count,
                "enabled_user_limit_count": enabled_user_limit_count,
                "user_group_limit_count": user_group_limit_count,
                "enabled_user_group_limit_count": enabled_user_group_limit_count,
                "limited_user_group_count": limited_user_group_count,
            },
            "hooks": {
                "hooks_enabled": hooks_enabled,
                "supported_hook_point_count": 2,
                "configured_hook_count": configured_hook_count,
                "active_hook_count": active_hook_count,
                "reachable_hook_count": reachable_hook_count,
                "recent_execution_count": recent_hook_execution_count,
                "recent_failure_count": recent_hook_failure_count,
                "hook_point_names": [
                    "document_ingestion",
                    "query_processing",
                ],
                "recent_executions": [],
            },
            "custom_theming": custom_theming,
            "white_labeling": white_labeling,
            "custom_deployments": custom_deployments,
            "region_processing": region_processing,
            "self_hosting": self_hosting,
        }
    except Exception:
        return fetch_db_state_via_docker()


def build_permission_inheritance_summary(
    db_state: dict[str, Any],
) -> dict[str, int]:
    summary = db_state.get("permission_inheritance", {})
    return {
        "sync_cc_pair_count": int(summary.get("sync_cc_pair_count", 0) or 0),
        "docs_with_external_acl_count": int(
            summary.get("docs_with_external_acl_count", 0) or 0
        ),
        "docs_with_user_acl_count": int(
            summary.get("docs_with_user_acl_count", 0) or 0
        ),
        "docs_with_group_acl_count": int(
            summary.get("docs_with_group_acl_count", 0) or 0
        ),
        "recent_doc_sync_failure_count": int(
            summary.get("recent_doc_sync_failure_count", 0) or 0
        ),
        "recent_group_sync_failure_count": int(
            summary.get("recent_group_sync_failure_count", 0) or 0
        ),
    }


def build_query_history_usage_summary(db_state: dict[str, Any]) -> dict[str, Any]:
    summary = db_state.get("query_history_usage", {})
    recent_exports = summary.get("recent_exports", [])
    if not isinstance(recent_exports, list):
        recent_exports = []
    return {
        "query_history_type": str(summary.get("query_history_type", "disabled")).lower(),
        "query_history_enabled": bool(summary.get("query_history_enabled", False)),
        "recent_query_count": int(summary.get("recent_query_count", 0) or 0),
        "recent_chat_session_count": int(
            summary.get("recent_chat_session_count", 0) or 0
        ),
        "recent_active_user_count": int(
            summary.get("recent_active_user_count", 0) or 0
        ),
        "recent_like_count": int(summary.get("recent_like_count", 0) or 0),
        "recent_dislike_count": int(summary.get("recent_dislike_count", 0) or 0),
        "recent_export_count": int(summary.get("recent_export_count", 0) or 0),
        "recent_export_failure_count": int(
            summary.get("recent_export_failure_count", 0) or 0
        ),
        "recent_exports": recent_exports,
    }


def build_custom_permission_summary(db_state: dict[str, Any]) -> dict[str, Any]:
    summary = db_state.get("custom_permissions", {})
    permission_counts = summary.get("permission_counts", {})
    if not isinstance(permission_counts, dict):
        permission_counts = {}
    return {
        "default_group_count": int(summary.get("default_group_count", 0) or 0),
        "custom_group_count": int(summary.get("custom_group_count", 0) or 0),
        "stale_custom_group_count": int(
            summary.get("stale_custom_group_count", 0) or 0
        ),
        "groups_with_custom_grants_count": int(
            summary.get("groups_with_custom_grants_count", 0) or 0
        ),
        "custom_permission_count": int(summary.get("custom_permission_count", 0) or 0),
        "manual_grant_count": int(summary.get("manual_grant_count", 0) or 0),
        "scim_grant_count": int(summary.get("scim_grant_count", 0) or 0),
        "admin_override_group_count": int(
            summary.get("admin_override_group_count", 0) or 0
        ),
        "permission_counts": permission_counts,
    }


def build_usage_limit_summary(db_state: dict[str, Any]) -> dict[str, Any]:
    summary = db_state.get("usage_limits", {})
    return {
        "enabled": bool(summary.get("enabled", False)),
        "global_limit_count": int(summary.get("global_limit_count", 0) or 0),
        "enabled_global_limit_count": int(
            summary.get("enabled_global_limit_count", 0) or 0
        ),
        "user_limit_count": int(summary.get("user_limit_count", 0) or 0),
        "enabled_user_limit_count": int(
            summary.get("enabled_user_limit_count", 0) or 0
        ),
        "user_group_limit_count": int(
            summary.get("user_group_limit_count", 0) or 0
        ),
        "enabled_user_group_limit_count": int(
            summary.get("enabled_user_group_limit_count", 0) or 0
        ),
        "limited_user_group_count": int(
            summary.get("limited_user_group_count", 0) or 0
        ),
    }


def build_hook_summary(db_state: dict[str, Any]) -> dict[str, Any]:
    summary = db_state.get("hooks", {})
    recent_executions = summary.get("recent_executions", [])
    if not isinstance(recent_executions, list):
        recent_executions = []
    hook_point_names = summary.get("hook_point_names", [])
    if not isinstance(hook_point_names, list):
        hook_point_names = []
    return {
        "hooks_enabled": bool(summary.get("hooks_enabled", False)),
        "supported_hook_point_count": int(
            summary.get("supported_hook_point_count", 0) or 0
        ),
        "configured_hook_count": int(summary.get("configured_hook_count", 0) or 0),
        "active_hook_count": int(summary.get("active_hook_count", 0) or 0),
        "reachable_hook_count": int(summary.get("reachable_hook_count", 0) or 0),
        "recent_execution_count": int(summary.get("recent_execution_count", 0) or 0),
        "recent_failure_count": int(summary.get("recent_failure_count", 0) or 0),
        "hook_point_names": hook_point_names,
        "recent_executions": recent_executions,
    }


def build_custom_theming_summary(db_state: dict[str, Any]) -> dict[str, Any]:
    summary = db_state.get("custom_theming", {})
    return {
        "branding_configured": bool(summary.get("branding_configured", False)),
        "application_name": str(
            summary.get("application_name", ONYX_DEFAULT_APPLICATION_NAME)
            or ONYX_DEFAULT_APPLICATION_NAME
        ),
        "application_name_is_default": bool(
            summary.get("application_name_is_default", True)
        ),
        "use_custom_logo": bool(summary.get("use_custom_logo", False)),
        "use_custom_logotype": bool(summary.get("use_custom_logotype", False)),
        "logo_display_style": str(
            summary.get("logo_display_style", "logo_and_name") or "logo_and_name"
        ),
        "custom_nav_item_count": int(summary.get("custom_nav_item_count", 0) or 0),
        "custom_header_content_enabled": bool(
            summary.get("custom_header_content_enabled", False)
        ),
        "custom_lower_disclaimer_enabled": bool(
            summary.get("custom_lower_disclaimer_enabled", False)
        ),
        "first_visit_notice_enabled": bool(
            summary.get("first_visit_notice_enabled", False)
        ),
        "custom_popup_enabled": bool(summary.get("custom_popup_enabled", False)),
        "consent_screen_enabled": bool(summary.get("consent_screen_enabled", False)),
        "custom_greeting_enabled": bool(
            summary.get("custom_greeting_enabled", False)
        ),
        "consent_prompt_configured": bool(
            summary.get("consent_prompt_configured", False)
        ),
        "popup_content_configured": bool(
            summary.get("popup_content_configured", False)
        ),
    }


def build_white_labeling_summary(db_state: dict[str, Any]) -> dict[str, Any]:
    summary = db_state.get("white_labeling", {})
    residual_examples = summary.get("residual_branding_examples", [])
    if not isinstance(residual_examples, list):
        residual_examples = []
    return {
        "branding_configured": bool(summary.get("branding_configured", False)),
        "custom_logo_enabled": bool(summary.get("custom_logo_enabled", False)),
        "custom_favicon_enabled": bool(summary.get("custom_favicon_enabled", False)),
        "application_name_configured": bool(
            summary.get("application_name_configured", False)
        ),
        "white_label_ready": bool(summary.get("white_label_ready", False)),
        "residual_branding_count": int(
            summary.get("residual_branding_count", 0) or 0
        ),
        "residual_external_link_count": int(
            summary.get("residual_external_link_count", 0) or 0
        ),
        "residual_branding_examples": residual_examples,
    }


def build_custom_deployment_summary(db_state: dict[str, Any]) -> dict[str, Any]:
    summary = db_state.get("custom_deployments", {})
    supported_modes = summary.get("supported_modes", [])
    if not isinstance(supported_modes, list):
        supported_modes = []
    overlay_examples = summary.get("overlay_examples", [])
    if not isinstance(overlay_examples, list):
        overlay_examples = []
    return {
        "docker_compose_variant_count": int(
            summary.get("docker_compose_variant_count", 0) or 0
        ),
        "helm_values_variant_count": int(
            summary.get("helm_values_variant_count", 0) or 0
        ),
        "has_install_script": bool(summary.get("has_install_script", False)),
        "has_multitenant_compose": bool(
            summary.get("has_multitenant_compose", False)
        ),
        "has_lite_compose": bool(summary.get("has_lite_compose", False)),
        "has_prod_compose": bool(summary.get("has_prod_compose", False)),
        "has_security_platform_compose_overlay": bool(
            summary.get("has_security_platform_compose_overlay", False)
        ),
        "has_security_platform_helm_overlay": bool(
            summary.get("has_security_platform_helm_overlay", False)
        ),
        "supported_modes": supported_modes,
        "overlay_examples": overlay_examples,
    }


def build_region_processing_summary(db_state: dict[str, Any]) -> dict[str, Any]:
    summary = db_state.get("region_processing", {})
    region_hints = summary.get("region_hints", [])
    if not isinstance(region_hints, list):
        region_hints = []
    return {
        "aws_region_supported": bool(summary.get("aws_region_supported", False)),
        "object_store_endpoint_configurable": bool(
            summary.get("object_store_endpoint_configurable", False)
        ),
        "web_domain_configurable": bool(
            summary.get("web_domain_configurable", False)
        ),
        "tenant_aware_deployment_supported": bool(
            summary.get("tenant_aware_deployment_supported", False)
        ),
        "cloud_deployment_supported": bool(
            summary.get("cloud_deployment_supported", False)
        ),
        "region_hint_count": int(summary.get("region_hint_count", 0) or 0),
        "region_hints": region_hints,
    }


def build_self_hosting_summary(db_state: dict[str, Any]) -> dict[str, Any]:
    summary = db_state.get("self_hosting", {})
    return {
        "self_hosted_mode": bool(summary.get("self_hosted_mode", False)),
        "multi_tenant_mode": bool(summary.get("multi_tenant_mode", False)),
        "enterprise_features_enabled": bool(
            summary.get("enterprise_features_enabled", False)
        ),
        "license_enforcement_enabled": bool(
            summary.get("license_enforcement_enabled", False)
        ),
        "has_license": bool(summary.get("has_license", False)),
        "license_status": summary.get("license_status"),
        "license_source": summary.get("license_source"),
        "seat_count": summary.get("seat_count"),
        "used_seat_count": summary.get("used_seat_count"),
        "has_license_api": bool(summary.get("has_license_api", False)),
        "has_admin_billing_page": bool(
            summary.get("has_admin_billing_page", False)
        ),
        "has_billing_service": bool(summary.get("has_billing_service", False)),
        "has_cloud_proxy": bool(summary.get("has_cloud_proxy", False)),
        "cloud_data_plane_url_configured": bool(
            summary.get("cloud_data_plane_url_configured", False)
        ),
        "has_install_script": bool(summary.get("has_install_script", False)),
        "has_docker_compose_path": bool(
            summary.get("has_docker_compose_path", False)
        ),
        "has_helm_install_path": bool(
            summary.get("has_helm_install_path", False)
        ),
    }


def build_rbac_summary(db_state: dict[str, Any]) -> dict[str, int]:
    summary = db_state.get("rbac", {})
    return {
        "user_group_count": int(summary.get("user_group_count", 0) or 0),
        "permission_grant_count": int(summary.get("permission_grant_count", 0) or 0),
        "users_with_effective_permissions_count": int(
            summary.get("users_with_effective_permissions_count", 0) or 0
        ),
        "curator_membership_count": int(
            summary.get("curator_membership_count", 0) or 0
        ),
    }


def build_service_account_summary(db_state: dict[str, Any]) -> dict[str, int]:
    summary = db_state.get("service_accounts", {})
    return {
        "api_key_count": int(summary.get("api_key_count", 0) or 0),
        "service_account_user_count": int(
            summary.get("service_account_user_count", 0) or 0
        ),
        "ownerless_api_key_count": int(
            summary.get("ownerless_api_key_count", 0) or 0
        ),
    }


def build_scim_summary(db_state: dict[str, Any]) -> dict[str, int]:
    summary = db_state.get("scim", {})
    return {
        "active_token_count": int(summary.get("active_token_count", 0) or 0),
        "user_mapping_count": int(summary.get("user_mapping_count", 0) or 0),
        "group_mapping_count": int(summary.get("group_mapping_count", 0) or 0),
        "recent_group_sync_failure_count": int(
            summary.get("recent_group_sync_failure_count", 0) or 0
        ),
    }


def build_secrets_encryption_summary(
    deployment_profile_summary: dict[str, Any],
) -> dict[str, Any]:
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

    profile_env = deployment_profile_summary.get("profile_env", {})
    encryption_key = str(profile_env.get("ENCRYPTION_KEY_SECRET", "") or "").strip()
    return build_runtime_secrets_encryption_summary(
        enabled=bool(encryption_key),
        encrypted_columns=encrypted_columns,
        rotation_script_available=(
            ROOT.parent / "backend" / "onyx" / "db" / "rotate_encryption_key.py"
        ).exists(),
    ).model_dump()


def build_persona_tool_aliases(persona: dict[str, Any]) -> set[str]:
    aliases: set[str] = set()
    for tool in persona.get("tools", []):
        for field in ("name", "display_name", "in_code_tool_id"):
            value = tool.get(field)
            if value:
                aliases.add(value)
    return aliases


def build_runtime_health_summary(
    *,
    document_set: dict[str, Any] | None,
    personas: list[dict[str, Any]],
    openapi_tools: list[dict[str, Any]],
    db_state: dict[str, Any],
    threat_intel_sync_summary: dict[str, Any],
    threat_intel_curation_summary: dict[str, Any],
    historical_package_summary: dict[str, Any],
    archive_execution_summary: dict[str, Any],
    security_tool_profile_summary: dict[str, Any],
    deployment_profile_summary: dict[str, Any],
    playbook_definitions_summary: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    permission_inheritance = build_permission_inheritance_summary(db_state)
    query_history_usage = build_query_history_usage_summary(db_state)
    custom_permissions = build_custom_permission_summary(db_state)
    usage_limits = build_usage_limit_summary(db_state)
    hooks = build_hook_summary(db_state)
    custom_theming = build_custom_theming_summary(db_state)
    white_labeling = build_white_labeling_summary(db_state)
    custom_deployments = build_custom_deployment_summary(db_state)
    region_processing = build_region_processing_summary(db_state)
    self_hosting = build_self_hosting_summary(db_state)
    rbac_summary = build_rbac_summary(db_state)
    service_account_summary = build_service_account_summary(db_state)
    scim_summary = build_scim_summary(db_state)
    secrets_encryption_summary = build_secrets_encryption_summary(
        deployment_profile_summary
    )
    tool_map = {
        str(tool.get("name", "")).strip(): tool
        for tool in openapi_tools
        if str(tool.get("name", "")).strip()
    }

    health = build_health_status(
        profile_name=str(deployment_profile_summary.get("deployment_profile", "live")),
        expected_threat_profile=str(
            deployment_profile_summary.get(
                "expected_threat_intel_source_profile", "live"
            )
            or "live"
        ),
        expected_tools_profile=str(
            deployment_profile_summary.get("expected_security_tools_profile", "live")
            or "live"
        ),
        threat_intel_source_profile=str(
            threat_intel_sync_summary.get("source_profile", "unknown") or "unknown"
        ),
        security_tools_profile=str(
            security_tool_profile_summary.get("profile", "unknown") or "unknown"
        ),
        required_env=[
            str(env_name)
            for env_name in deployment_profile_summary.get("required_env", [])
            if str(env_name).strip()
        ],
        missing_required_env=[
            str(env_name)
            for env_name in deployment_profile_summary.get("required_env", [])
            if str(env_name).strip()
            and not resolve_env_value(str(env_name), "", deployment_profile_summary)
        ],
        placeholder_required_env=get_placeholder_required_env(
            [
                str(env_name)
                for env_name in deployment_profile_summary.get("required_env", [])
                if str(env_name).strip()
            ],
            deployment_profile_summary,
        ),
        deployment_profile_issues=validate_deployment_profile_runtime(
            deployment_profile_summary
        ),
        document_set_status=SecurityPlatformDocumentSetStatus(
            id=document_set.get("id") if document_set else None,
            name=SECURITY_DOCUMENT_SET_NAME,
            exists=document_set is not None,
            is_public=document_set.get("is_public") if document_set else None,
            shared_user_count=len(db_state.get("document_set_links", set())),
        ),
        personas=[
            SecurityPlatformPersonaStatus(
                id=int(
                    persona.get("id")
                    or db_state.get("persona_rows", {})
                    .get(str(persona.get("name")), {})
                    .get("id", index)
                ),
                name=str(persona.get("name")),
                is_public=bool(
                    persona.get(
                        "is_public",
                        db_state.get("persona_rows", {})
                        .get(str(persona.get("name")), {})
                        .get("is_public", False),
                    )
                ),
                tool_count=len(persona.get("tools", [])),
                document_set_count=len(persona.get("document_sets", [])),
                shared_user_count=len(persona.get("users", [])),
            )
            for index, persona in enumerate(personas, start=1)
            if persona.get("name")
        ],
        tools=[
            SecurityPlatformToolStatus(
                id=int(tool.get("id", index)),
                name=str(tool.get("name")),
                enabled=bool(tool.get("is_visible", True)),
                server_url=(
                    (
                        tool.get("definition", {}).get("servers", [{}])[0].get("url")
                        if isinstance(tool.get("definition"), dict)
                        and isinstance(tool.get("definition", {}).get("servers"), list)
                        and tool.get("definition", {}).get("servers")
                        and isinstance(tool.get("definition", {}).get("servers")[0], dict)
                        else None
                    )
                ),
                header_keys=sorted(
                    str(header.get("key"))
                    for header in tool.get("custom_headers", [])
                    if isinstance(header, dict) and header.get("key")
                ),
                persona_names=sorted(
                    str(persona_name)
                    for persona_name in next(
                        (
                            config.get("persona_bindings", [])
                            for config in load_security_tool_configs()
                            if str(config.get("name", "")).strip()
                            == str(tool.get("name", "")).strip()
                        ),
                        [],
                    )
                    if str(persona_name).strip()
                ),
            )
            for index, tool in enumerate(tool_map.values(), start=1)
            if tool.get("name")
        ],
        security_users=[
            SecurityPlatformUserStatus(
                email=str(email),
                role="present",
                is_active=True,
            )
            for email in sorted(db_state.get("user_rows", {}).keys())
        ],
        persona_user_links=len(db_state.get("persona_user_links", set())),
        document_set_user_links=len(db_state.get("document_set_links", set())),
        snapshot={
            "threat_intel_sync": threat_intel_sync_summary,
            "threat_intel_corpus": {
                "governed": threat_intel_curation_summary.get("governed_feeds", 0),
                "unmanaged": threat_intel_curation_summary.get(
                    "unmanaged_local_feeds", 0
                ),
                "promotion_candidates": threat_intel_curation_summary.get(
                    "promotion_candidates", 0
                ),
                "manual_review": threat_intel_curation_summary.get("manual_review", 0),
                "keep_runtime_only": threat_intel_curation_summary.get(
                    "keep_runtime_only", 0
                ),
                "historical_package_count": historical_package_summary.get(
                    "package_count", 0
                ),
                "historical_package_items": historical_package_summary.get(
                    "total_item_count", 0
                ),
                "archive_execution_batches": archive_execution_summary.get(
                    "batch_count", 0
                ),
                "archive_execution_fully_materialized_batches": archive_execution_summary.get(
                    "fully_materialized_batch_count", 0
                ),
            },
            "permission_inheritance": permission_inheritance,
            "service_accounts": service_account_summary,
            "scim": {
                "active_token_count": scim_summary["active_token_count"],
                "has_active_token": scim_summary["active_token_count"] > 0,
                "token_last_used_at": None,
                "user_mapping_count": scim_summary["user_mapping_count"],
                "group_mapping_count": scim_summary["group_mapping_count"],
                "recent_group_sync_failure_count": scim_summary[
                    "recent_group_sync_failure_count"
                ],
            },
            "query_history_usage": query_history_usage,
            "custom_permissions": custom_permissions,
            "usage_limits": usage_limits,
            "hooks": hooks,
            "custom_theming": custom_theming,
            "white_labeling": white_labeling,
            "custom_deployments": custom_deployments,
            "region_processing": region_processing,
            "self_hosting": self_hosting,
            "secrets_encryption": secrets_encryption_summary,
            "playbooks": {
                "count": playbook_definitions_summary.get("count", 0),
                "with_examples": len(
                    playbook_definitions_summary.get("playbooks_with_examples", [])
                ),
                "items": [],
            },
        },
    )

    return health, build_recommended_next_actions(health)


def evaluate_acceptance(
    document_sets: list[dict[str, Any]],
    personas: list[dict[str, Any]],
    openapi_tools: list[dict[str, Any]],
    ingestion_docs: list[dict[str, Any]],
    db_state: dict[str, Any],
    threat_intel_sync_summary: dict[str, Any],
    threat_intel_curation_summary: dict[str, Any],
    historical_package_summary: dict[str, Any],
    archive_execution_summary: dict[str, Any],
    security_tool_profile_summary: dict[str, Any],
    deployment_profile_summary: dict[str, Any],
    playbook_definitions_summary: dict[str, Any],
) -> dict[str, Any]:
    failures: list[str] = []
    security_tool_configs = load_security_tool_configs()
    expected_openapi_tools = build_expected_openapi_tools(security_tool_configs)
    persona_tool_requirements = build_persona_tool_requirements(security_tool_configs)

    document_set = next(
        (document_set for document_set in document_sets if document_set["name"] == SECURITY_DOCUMENT_SET_NAME),
        None,
    )
    if document_set is None:
        failures.append(f"Missing document set: {SECURITY_DOCUMENT_SET_NAME}")

    openapi_tool_names = {tool["name"] for tool in openapi_tools}
    missing_openapi_tools = sorted(expected_openapi_tools - openapi_tool_names)
    if missing_openapi_tools:
        failures.append(f"Missing OpenAPI tools: {', '.join(missing_openapi_tools)}")
    tool_profile_mismatches = security_tool_profile_summary.get("mismatches", [])
    if tool_profile_mismatches:
        failures.extend(tool_profile_mismatches)
    expected_threat_profile = deployment_profile_summary.get(
        "expected_threat_intel_source_profile"
    )
    if (
        expected_threat_profile
        and threat_intel_sync_summary.get("source_profile") != expected_threat_profile
    ):
        failures.append(
            "Threat-intel source profile mismatch: "
            f"expected {expected_threat_profile}, got {threat_intel_sync_summary.get('source_profile')}"
        )
    expected_tools_profile = deployment_profile_summary.get(
        "expected_security_tools_profile"
    )
    if expected_tools_profile and security_tool_profile_summary.get("profile") != expected_tools_profile:
        failures.append(
            "Security tools profile mismatch: "
            f"expected {expected_tools_profile}, got {security_tool_profile_summary.get('profile')}"
        )
    deployment_profile_issues = validate_deployment_profile_runtime(
        deployment_profile_summary
    )
    if deployment_profile_issues:
        failures.extend(deployment_profile_issues)

    threat_intel_doc_ids = {
        str(doc.get("semantic_id") or doc.get("semantic_identifier") or "")
        for doc in ingestion_docs
        if str(doc.get("semantic_id") or doc.get("semantic_identifier") or "").endswith("_threat_intel")
    }
    if not threat_intel_doc_ids:
        failures.append("Missing threat-intel ingestion documents")
    if threat_intel_curation_summary.get("governed_feeds", 0) <= 0:
        failures.append("Threat-intel governed feed manifest is empty or missing")
    if threat_intel_curation_summary.get("promotion_candidates", 0) > 0:
        failures.append(
            "Threat-intel promotion candidates remain: "
            f"{threat_intel_curation_summary.get('promotion_candidates', 0)}"
        )
    if historical_package_summary.get("consistency_issue_count", 0) > 0:
        failures.append(
            "Historical package catalog consistency issues: "
            f"{historical_package_summary.get('consistency_issue_count', 0)}"
        )
        failures.extend(historical_package_summary.get("consistency_issues", []))
    if archive_execution_summary.get("consistency_issue_count", 0) > 0:
        failures.append(
            "Archive execution artifact consistency issues: "
            f"{archive_execution_summary.get('consistency_issue_count', 0)}"
        )
        failures.extend(archive_execution_summary.get("consistency_issues", []))
    if playbook_definitions_summary.get("count", 0) <= 0:
        failures.append("Missing security playbook definitions")
    if playbook_definitions_summary.get("invalid_files"):
        failures.append(
            "Invalid playbook definition files: "
            + ", ".join(playbook_definitions_summary["invalid_files"])
        )
    missing_playbook_examples = sorted(
        set(playbook_definitions_summary.get("names", []))
        - set(playbook_definitions_summary.get("playbooks_with_examples", []))
    )
    if missing_playbook_examples:
        failures.append(
            "Playbooks missing example_inputs: " + ", ".join(missing_playbook_examples)
        )

    persona_map = {persona["name"]: persona for persona in personas}
    missing_personas = sorted(
        set(persona_tool_requirements.keys()) - set(persona_map.keys())
    )
    if missing_personas:
        failures.append(f"Missing personas: {', '.join(missing_personas)}")

    persona_tool_summary: dict[str, list[str]] = {}
    for persona_name, expected in persona_tool_requirements.items():
        persona = persona_map.get(persona_name)
        if persona is None:
            continue

        actual_aliases = build_persona_tool_aliases(persona)
        missing_builtin = sorted(expected["builtin_tools"] - actual_aliases)
        missing_custom = sorted(expected["custom_tools"] - actual_aliases)
        if missing_builtin or missing_custom:
            failures.append(
                f"Persona {persona_name} missing tools: "
                f"builtin={missing_builtin or '[]'} custom={missing_custom or '[]'}"
            )
        persona_tool_summary[persona_name] = sorted(actual_aliases)

    user_rows = db_state["user_rows"]
    missing_users = sorted(SECURITY_USERS - set(user_rows.keys()))
    if missing_users:
        failures.append(f"Missing security users: {', '.join(missing_users)}")

    persona_rows = db_state["persona_rows"]
    non_private_personas = sorted(
        persona_name
        for persona_name, row in persona_rows.items()
        if row["is_public"]
    )
    if non_private_personas:
        failures.append(
            f"Security personas must be private: {', '.join(non_private_personas)}"
        )

    document_set_id = db_state["document_set_id"]
    if document_set_id is None:
        failures.append(f"Document set not found in DB: {SECURITY_DOCUMENT_SET_NAME}")

    persona_user_links = db_state["persona_user_links"]
    document_set_links = db_state["document_set_links"]
    expected_persona_user_links = set()
    expected_document_set_links = set()
    for email, user_id in user_rows.items():
        persona_name = USER_PERSONA_BY_EMAIL.get(email)
        if persona_name is None:
            continue
        persona_row = persona_rows.get(persona_name)
        if persona_row:
            expected_persona_user_links.add((persona_row["id"], user_id))
        if document_set_id:
            expected_document_set_links.add((document_set_id, user_id))

    missing_persona_user_links = sorted(expected_persona_user_links - persona_user_links)
    if missing_persona_user_links:
        failures.append(
            f"Missing persona__user links: {len(missing_persona_user_links)}"
        )

    missing_document_set_links = sorted(expected_document_set_links - document_set_links)
    if missing_document_set_links:
        failures.append(
            f"Missing document_set__user links: {len(missing_document_set_links)}"
        )

    health, recommended_next_actions = build_runtime_health_summary(
        document_set=document_set,
        personas=personas,
        openapi_tools=openapi_tools,
        db_state=db_state,
        threat_intel_sync_summary=threat_intel_sync_summary,
        threat_intel_curation_summary=threat_intel_curation_summary,
        historical_package_summary=historical_package_summary,
        archive_execution_summary=archive_execution_summary,
        security_tool_profile_summary=security_tool_profile_summary,
        deployment_profile_summary=deployment_profile_summary,
        playbook_definitions_summary=playbook_definitions_summary,
    )
    rbac_summary = build_rbac_summary(db_state)
    service_account_summary = build_service_account_summary(db_state)
    scim_summary = build_scim_summary(db_state)
    secrets_encryption_summary = build_secrets_encryption_summary(
        deployment_profile_summary
    )
    permission_inheritance = build_permission_inheritance_summary(db_state)
    query_history_usage = build_query_history_usage_summary(db_state)
    custom_permissions = build_custom_permission_summary(db_state)
    usage_limits = build_usage_limit_summary(db_state)
    hooks = build_hook_summary(db_state)
    custom_theming = build_custom_theming_summary(db_state)
    white_labeling = build_white_labeling_summary(db_state)
    custom_deployments = build_custom_deployment_summary(db_state)
    region_processing = build_region_processing_summary(db_state)
    self_hosting = build_self_hosting_summary(db_state)
    for check in health.get("checks", []):
        if not isinstance(check, dict) or check.get("status") != "failing":
            continue
        for issue in check.get("issues", []):
            issue_text = str(issue).strip()
            if issue_text and issue_text not in failures:
                failures.append(issue_text)

    return {
        "ok": not failures,
        "failures": failures,
        "health": health,
        "recommended_next_actions": recommended_next_actions,
        "summary": {
            "document_set": SECURITY_DOCUMENT_SET_NAME if document_set else None,
            "deployment_profile": deployment_profile_summary["deployment_profile"],
            "deployment_required_env": deployment_profile_summary["required_env"],
            "deployment_profile_issues": deployment_profile_issues,
            "openapi_tools_found": sorted(openapi_tool_names & expected_openapi_tools),
            "security_tools_profile": security_tool_profile_summary["profile"],
            "security_tools_summary": security_tool_profile_summary["tools"],
            "threat_intel_doc_count": len(threat_intel_doc_ids),
            "threat_intel_source_profile": threat_intel_sync_summary["source_profile"],
            "threat_intel_last_sync_run_at": threat_intel_sync_summary["last_sync_run_at"],
            "threat_intel_due_status": threat_intel_sync_summary["due_status"],
            "threat_intel_due_feeds": threat_intel_sync_summary["due_feeds"],
            "threat_intel_governed_feeds": threat_intel_curation_summary.get("governed_feeds", 0),
            "threat_intel_active_feeds": threat_intel_curation_summary.get("active_feeds", 0),
            "threat_intel_archive_candidates": threat_intel_curation_summary.get("archive_candidates", 0),
            "threat_intel_retained_historical": threat_intel_curation_summary.get("retained_historical", 0),
            "threat_intel_unmanaged_local_feeds": threat_intel_curation_summary.get("unmanaged_local_feeds", 0),
            "threat_intel_promotion_candidates": threat_intel_curation_summary.get("promotion_candidates", 0),
            "threat_intel_manual_review": threat_intel_curation_summary.get("manual_review", 0),
            "threat_intel_keep_runtime_only": threat_intel_curation_summary.get("keep_runtime_only", 0),
            "threat_intel_quality_counts": threat_intel_curation_summary.get("quality_counts", {}),
            "historical_package_count": historical_package_summary.get("package_count", 0),
            "historical_package_total_items": historical_package_summary.get("total_item_count", 0),
            "historical_package_total_size_bytes": historical_package_summary.get("total_size_bytes", 0),
            "historical_package_ids": historical_package_summary.get("package_ids", []),
            "historical_package_consistent_count": historical_package_summary.get(
                "consistent_package_count", 0
            ),
            "historical_package_consistency_issue_count": historical_package_summary.get(
                "consistency_issue_count", 0
            ),
            "archive_execution_batch_count": archive_execution_summary.get("batch_count", 0),
            "archive_execution_fully_materialized_batch_count": archive_execution_summary.get(
                "fully_materialized_batch_count", 0
            ),
            "archive_execution_consistency_issue_count": archive_execution_summary.get(
                "consistency_issue_count", 0
            ),
            "playbook_count": playbook_definitions_summary["count"],
            "playbook_names": playbook_definitions_summary["names"],
            "playbooks_with_examples": playbook_definitions_summary["playbooks_with_examples"],
            "personas_found": sorted(persona_map.keys() & set(persona_tool_requirements.keys())),
            "security_users_found": sorted(user_rows.keys() & SECURITY_USERS),
            "persona_tool_summary": persona_tool_summary,
            "persona_user_links": len(persona_user_links),
            "document_set_links": len(document_set_links),
            "rbac_user_group_count": rbac_summary["user_group_count"],
            "rbac_permission_grant_count": rbac_summary["permission_grant_count"],
            "rbac_users_with_effective_permissions_count": rbac_summary[
                "users_with_effective_permissions_count"
            ],
            "rbac_curator_membership_count": rbac_summary[
                "curator_membership_count"
            ],
            "service_account_api_key_count": service_account_summary["api_key_count"],
            "service_account_user_count": service_account_summary[
                "service_account_user_count"
            ],
            "service_account_ownerless_count": service_account_summary[
                "ownerless_api_key_count"
            ],
            "query_history_type": query_history_usage["query_history_type"],
            "query_history_enabled": query_history_usage["query_history_enabled"],
            "query_history_recent_query_count": query_history_usage["recent_query_count"],
            "query_history_recent_chat_session_count": query_history_usage[
                "recent_chat_session_count"
            ],
            "query_history_recent_active_user_count": query_history_usage[
                "recent_active_user_count"
            ],
            "query_history_recent_like_count": query_history_usage["recent_like_count"],
            "query_history_recent_dislike_count": query_history_usage[
                "recent_dislike_count"
            ],
            "query_history_export_count": query_history_usage["recent_export_count"],
            "query_history_export_failure_count": query_history_usage[
                "recent_export_failure_count"
            ],
            "custom_permission_default_group_count": custom_permissions[
                "default_group_count"
            ],
            "custom_permission_group_count": custom_permissions["custom_group_count"],
            "custom_permission_stale_group_count": custom_permissions[
                "stale_custom_group_count"
            ],
            "custom_permission_groups_with_grants_count": custom_permissions[
                "groups_with_custom_grants_count"
            ],
            "custom_permission_count": custom_permissions["custom_permission_count"],
            "custom_permission_manual_grant_count": custom_permissions[
                "manual_grant_count"
            ],
            "custom_permission_scim_grant_count": custom_permissions[
                "scim_grant_count"
            ],
            "custom_permission_admin_override_group_count": custom_permissions[
                "admin_override_group_count"
            ],
            "custom_permission_counts": custom_permissions["permission_counts"],
            "usage_limits_enabled": usage_limits["enabled"],
            "usage_limit_global_count": usage_limits["global_limit_count"],
            "usage_limit_enabled_global_count": usage_limits[
                "enabled_global_limit_count"
            ],
            "usage_limit_user_count": usage_limits["user_limit_count"],
            "usage_limit_enabled_user_count": usage_limits[
                "enabled_user_limit_count"
            ],
            "usage_limit_user_group_count": usage_limits["user_group_limit_count"],
            "usage_limit_enabled_user_group_count": usage_limits[
                "enabled_user_group_limit_count"
            ],
            "usage_limit_limited_user_group_count": usage_limits[
                "limited_user_group_count"
            ],
            "hooks_enabled": hooks["hooks_enabled"],
            "hook_supported_point_count": hooks["supported_hook_point_count"],
            "hook_configured_count": hooks["configured_hook_count"],
            "hook_active_count": hooks["active_hook_count"],
            "hook_reachable_count": hooks["reachable_hook_count"],
            "hook_recent_execution_count": hooks["recent_execution_count"],
            "hook_recent_failure_count": hooks["recent_failure_count"],
            "hook_point_names": hooks["hook_point_names"],
            "custom_theming_branding_configured": custom_theming[
                "branding_configured"
            ],
            "custom_theming_application_name": custom_theming["application_name"],
            "custom_theming_application_name_is_default": custom_theming[
                "application_name_is_default"
            ],
            "custom_theming_use_custom_logo": custom_theming["use_custom_logo"],
            "custom_theming_use_custom_logotype": custom_theming[
                "use_custom_logotype"
            ],
            "custom_theming_logo_display_style": custom_theming[
                "logo_display_style"
            ],
            "custom_theming_nav_item_count": custom_theming[
                "custom_nav_item_count"
            ],
            "custom_theming_custom_header_enabled": custom_theming[
                "custom_header_content_enabled"
            ],
            "custom_theming_custom_disclaimer_enabled": custom_theming[
                "custom_lower_disclaimer_enabled"
            ],
            "custom_theming_first_visit_notice_enabled": custom_theming[
                "first_visit_notice_enabled"
            ],
            "custom_theming_custom_popup_enabled": custom_theming[
                "custom_popup_enabled"
            ],
            "custom_theming_consent_screen_enabled": custom_theming[
                "consent_screen_enabled"
            ],
            "custom_theming_custom_greeting_enabled": custom_theming[
                "custom_greeting_enabled"
            ],
            "white_labeling_branding_configured": white_labeling[
                "branding_configured"
            ],
            "white_labeling_custom_logo_enabled": white_labeling[
                "custom_logo_enabled"
            ],
            "white_labeling_custom_favicon_enabled": white_labeling[
                "custom_favicon_enabled"
            ],
            "white_labeling_application_name_configured": white_labeling[
                "application_name_configured"
            ],
            "white_labeling_ready": white_labeling["white_label_ready"],
            "white_labeling_residual_branding_count": white_labeling[
                "residual_branding_count"
            ],
            "white_labeling_residual_external_link_count": white_labeling[
                "residual_external_link_count"
            ],
            "white_labeling_residual_branding_examples": white_labeling[
                "residual_branding_examples"
            ],
            "custom_deployment_compose_variant_count": custom_deployments[
                "docker_compose_variant_count"
            ],
            "custom_deployment_helm_values_variant_count": custom_deployments[
                "helm_values_variant_count"
            ],
            "custom_deployment_has_install_script": custom_deployments[
                "has_install_script"
            ],
            "custom_deployment_has_multitenant_compose": custom_deployments[
                "has_multitenant_compose"
            ],
            "custom_deployment_has_lite_compose": custom_deployments[
                "has_lite_compose"
            ],
            "custom_deployment_has_prod_compose": custom_deployments[
                "has_prod_compose"
            ],
            "custom_deployment_has_security_platform_compose_overlay": custom_deployments[
                "has_security_platform_compose_overlay"
            ],
            "custom_deployment_has_security_platform_helm_overlay": custom_deployments[
                "has_security_platform_helm_overlay"
            ],
            "custom_deployment_supported_modes": custom_deployments[
                "supported_modes"
            ],
            "custom_deployment_overlay_examples": custom_deployments[
                "overlay_examples"
            ],
            "region_processing_aws_region_supported": region_processing[
                "aws_region_supported"
            ],
            "region_processing_object_store_endpoint_configurable": region_processing[
                "object_store_endpoint_configurable"
            ],
            "region_processing_web_domain_configurable": region_processing[
                "web_domain_configurable"
            ],
            "region_processing_tenant_aware_supported": region_processing[
                "tenant_aware_deployment_supported"
            ],
            "region_processing_cloud_supported": region_processing[
                "cloud_deployment_supported"
            ],
            "region_processing_hint_count": region_processing["region_hint_count"],
            "region_processing_hints": region_processing["region_hints"],
            "self_hosting_self_hosted_mode": self_hosting["self_hosted_mode"],
            "self_hosting_multi_tenant_mode": self_hosting["multi_tenant_mode"],
            "self_hosting_enterprise_features_enabled": self_hosting[
                "enterprise_features_enabled"
            ],
            "self_hosting_license_enforcement_enabled": self_hosting[
                "license_enforcement_enabled"
            ],
            "self_hosting_has_license": self_hosting["has_license"],
            "self_hosting_license_status": self_hosting["license_status"],
            "self_hosting_license_source": self_hosting["license_source"],
            "self_hosting_seat_count": self_hosting["seat_count"],
            "self_hosting_used_seat_count": self_hosting["used_seat_count"],
            "self_hosting_has_license_api": self_hosting["has_license_api"],
            "self_hosting_has_admin_billing_page": self_hosting[
                "has_admin_billing_page"
            ],
            "self_hosting_has_billing_service": self_hosting["has_billing_service"],
            "self_hosting_has_cloud_proxy": self_hosting["has_cloud_proxy"],
            "self_hosting_cloud_data_plane_url_configured": self_hosting[
                "cloud_data_plane_url_configured"
            ],
            "self_hosting_has_install_script": self_hosting["has_install_script"],
            "self_hosting_has_docker_compose_path": self_hosting[
                "has_docker_compose_path"
            ],
            "self_hosting_has_helm_install_path": self_hosting[
                "has_helm_install_path"
            ],
            "scim_active_token_count": scim_summary["active_token_count"],
            "scim_user_mapping_count": scim_summary["user_mapping_count"],
            "scim_group_mapping_count": scim_summary["group_mapping_count"],
            "scim_group_sync_failure_count": scim_summary[
                "recent_group_sync_failure_count"
            ],
            "secrets_encryption_enabled": bool(
                secrets_encryption_summary.get("enabled", False)
            ),
            "secrets_encryption_column_count": int(
                secrets_encryption_summary.get("encrypted_column_count", 0) or 0
            ),
            "permission_sync_cc_pairs": permission_inheritance["sync_cc_pair_count"],
            "permission_docs_with_external_acl": permission_inheritance[
                "docs_with_external_acl_count"
            ],
            "permission_docs_with_user_acl": permission_inheritance[
                "docs_with_user_acl_count"
            ],
            "permission_docs_with_group_acl": permission_inheritance[
                "docs_with_group_acl_count"
            ],
            "permission_doc_sync_failures": permission_inheritance[
                "recent_doc_sync_failure_count"
            ],
            "permission_group_sync_failures": permission_inheritance[
                "recent_group_sync_failure_count"
            ],
        },
    }


def print_human_result(result: dict[str, Any]) -> None:
    print("=== Minimal Acceptance Check ===")
    health = result.get("health", {})
    print(
        "Health: "
        f"{health.get('overall_status', 'unknown')} "
        f"(failing={health.get('failing_checks', 0)}, warning={health.get('warning_checks', 0)})"
    )
    print(f"Document set: {result['summary']['document_set'] or 'MISSING'}")
    print(f"Deployment profile: {result['summary']['deployment_profile']}")
    print(
        "OpenAPI tools: "
        + ", ".join(result["summary"]["openapi_tools_found"])
        if result["summary"]["openapi_tools_found"]
        else "OpenAPI tools: MISSING"
    )
    print(f"Security tools profile: {result['summary']['security_tools_profile']}")
    for tool_name in sorted(result["summary"]["security_tools_summary"]):
        tool_summary = result["summary"]["security_tools_summary"][tool_name]
        server_url = tool_summary["configured_server_url"] or "unknown"
        header_keys = tool_summary["configured_header_keys"] or []
        print(
            f"  - {tool_name}: server={server_url}, headers={','.join(header_keys) or 'none'}"
        )
    print(f"Threat-intel docs: {result['summary']['threat_intel_doc_count']}")
    print(
        f"Threat-intel sync: profile={result['summary']['threat_intel_source_profile']}, "
        f"last_run={result['summary']['threat_intel_last_sync_run_at'] or 'never'}, "
        f"status={result['summary']['threat_intel_due_status']}"
    )
    print(
        "Threat-intel corpus: "
        f"governed={result['summary']['threat_intel_governed_feeds']}, "
        f"active={result['summary']['threat_intel_active_feeds']}, "
        f"archive_candidates={result['summary']['threat_intel_archive_candidates']}, "
        f"retained_historical={result['summary']['threat_intel_retained_historical']}, "
        f"unmanaged={result['summary']['threat_intel_unmanaged_local_feeds']}, "
        f"promotion_candidates={result['summary']['threat_intel_promotion_candidates']}, "
        f"manual_review={result['summary']['threat_intel_manual_review']}, "
        f"keep_runtime_only={result['summary']['threat_intel_keep_runtime_only']}"
    )
    print(
        "Threat-intel historical packages: "
        f"count={result['summary']['historical_package_count']}, "
        f"items={result['summary']['historical_package_total_items']}, "
        f"size={result['summary']['historical_package_total_size_bytes']}, "
        f"consistent={result['summary']['historical_package_consistent_count']}, "
        f"issues={result['summary']['historical_package_consistency_issue_count']}"
    )
    print(
        "Threat-intel archive execution artifacts: "
        f"batches={result['summary']['archive_execution_batch_count']}, "
        f"fully_materialized={result['summary']['archive_execution_fully_materialized_batch_count']}, "
        f"issues={result['summary']['archive_execution_consistency_issue_count']}"
    )
    if result["summary"]["historical_package_ids"]:
        print(
            "Historical package ids: "
            + ", ".join(result["summary"]["historical_package_ids"])
        )
    quality_counts = result["summary"].get("threat_intel_quality_counts", {})
    if quality_counts:
        print(
            "Threat-intel quality tiers: "
            + ", ".join(f"{name}={count}" for name, count in sorted(quality_counts.items()))
        )
    print(
        "Playbooks: "
        f"count={result['summary']['playbook_count']}, "
        f"with_examples={len(result['summary']['playbooks_with_examples'])}"
    )
    if result["summary"]["playbook_names"]:
        print("Playbook names: " + ", ".join(result["summary"]["playbook_names"]))
    if result["summary"]["threat_intel_due_feeds"]:
        print(
            "Threat-intel due feeds: "
            + ", ".join(result["summary"]["threat_intel_due_feeds"])
        )
    print("Personas:")
    for persona_name in sorted(SECURITY_PERSONA_BUILTIN_REQUIREMENTS):
        status = "OK" if persona_name in result["summary"]["personas_found"] else "MISSING"
        print(f"  - {persona_name}: {status}")
    print("Security users:")
    for email in sorted(SECURITY_USERS):
        status = "OK" if email in result["summary"]["security_users_found"] else "MISSING"
        print(f"  - {email}: {status}")
    print(f"Persona__user links: {result['summary']['persona_user_links']}")
    print(f"Document_set__user links: {result['summary']['document_set_links']}")
    print(
        "RBAC: "
        f"groups={result['summary']['rbac_user_group_count']}, "
        f"grants={result['summary']['rbac_permission_grant_count']}, "
        f"users_with_permissions={result['summary']['rbac_users_with_effective_permissions_count']}, "
        f"curators={result['summary']['rbac_curator_membership_count']}"
    )
    print(
        "Service accounts: "
        f"api_keys={result['summary']['service_account_api_key_count']}, "
        f"service_users={result['summary']['service_account_user_count']}, "
        f"ownerless={result['summary']['service_account_ownerless_count']}"
    )
    print(
        "Query history / usage: "
        f"type={result['summary']['query_history_type']}, "
        f"enabled={result['summary']['query_history_enabled']}, "
        f"queries_30d={result['summary']['query_history_recent_query_count']}, "
        f"sessions_30d={result['summary']['query_history_recent_chat_session_count']}, "
        f"active_users_30d={result['summary']['query_history_recent_active_user_count']}, "
        f"likes={result['summary']['query_history_recent_like_count']}, "
        f"dislikes={result['summary']['query_history_recent_dislike_count']}, "
        f"exports={result['summary']['query_history_export_count']}, "
        f"export_failures={result['summary']['query_history_export_failure_count']}"
    )
    print(
        "Custom permissions: "
        f"default_groups={result['summary']['custom_permission_default_group_count']}, "
        f"custom_groups={result['summary']['custom_permission_group_count']}, "
        f"stale_groups={result['summary']['custom_permission_stale_group_count']}, "
        f"groups_with_grants={result['summary']['custom_permission_groups_with_grants_count']}, "
        f"permissions={result['summary']['custom_permission_count']}, "
        f"manual_grants={result['summary']['custom_permission_manual_grant_count']}, "
        f"scim_grants={result['summary']['custom_permission_scim_grant_count']}, "
        f"admin_override_groups={result['summary']['custom_permission_admin_override_group_count']}"
    )
    print(
        "Usage limits: "
        f"enabled={result['summary']['usage_limits_enabled']}, "
        f"global={result['summary']['usage_limit_global_count']}/"
        f"{result['summary']['usage_limit_enabled_global_count']}, "
        f"user={result['summary']['usage_limit_user_count']}/"
        f"{result['summary']['usage_limit_enabled_user_count']}, "
        f"group={result['summary']['usage_limit_user_group_count']}/"
        f"{result['summary']['usage_limit_enabled_user_group_count']}, "
        f"limited_groups={result['summary']['usage_limit_limited_user_group_count']}"
    )
    print(
        "Hooks: "
        f"enabled={result['summary']['hooks_enabled']}, "
        f"points={result['summary']['hook_supported_point_count']}, "
        f"configured={result['summary']['hook_configured_count']}, "
        f"active={result['summary']['hook_active_count']}, "
        f"reachable={result['summary']['hook_reachable_count']}, "
        f"executions={result['summary']['hook_recent_execution_count']}, "
        f"failures={result['summary']['hook_recent_failure_count']}"
    )
    print(
        "Custom theming: "
        f"branding_configured={result['summary']['custom_theming_branding_configured']}, "
        f"application_name={result['summary']['custom_theming_application_name']}, "
        f"default_name={result['summary']['custom_theming_application_name_is_default']}, "
        f"logo={result['summary']['custom_theming_use_custom_logo']}, "
        f"logotype={result['summary']['custom_theming_use_custom_logotype']}, "
        f"style={result['summary']['custom_theming_logo_display_style']}, "
        f"nav_items={result['summary']['custom_theming_nav_item_count']}, "
        f"header={result['summary']['custom_theming_custom_header_enabled']}, "
        f"notice={result['summary']['custom_theming_first_visit_notice_enabled']}, "
        f"consent={result['summary']['custom_theming_consent_screen_enabled']}, "
        f"greeting={result['summary']['custom_theming_custom_greeting_enabled']}"
    )
    print(
        "White-labeling: "
        f"configured={result['summary']['white_labeling_branding_configured']}, "
        f"ready={result['summary']['white_labeling_ready']}, "
        f"custom_logo={result['summary']['white_labeling_custom_logo_enabled']}, "
        f"custom_favicon={result['summary']['white_labeling_custom_favicon_enabled']}, "
        f"named={result['summary']['white_labeling_application_name_configured']}, "
        f"residual_traces={result['summary']['white_labeling_residual_branding_count']}, "
        f"external_links={result['summary']['white_labeling_residual_external_link_count']}"
    )
    print(
        "Custom deployments: "
        f"compose={result['summary']['custom_deployment_compose_variant_count']}, "
        f"helm_values={result['summary']['custom_deployment_helm_values_variant_count']}, "
        f"install_script={result['summary']['custom_deployment_has_install_script']}, "
        f"multitenant={result['summary']['custom_deployment_has_multitenant_compose']}, "
        f"lite={result['summary']['custom_deployment_has_lite_compose']}, "
        f"prod={result['summary']['custom_deployment_has_prod_compose']}"
    )
    print(
        "Region-specific processing: "
        f"aws_region={result['summary']['region_processing_aws_region_supported']}, "
        f"s3_endpoint={result['summary']['region_processing_object_store_endpoint_configurable']}, "
        f"web_domain={result['summary']['region_processing_web_domain_configurable']}, "
        f"tenant_aware={result['summary']['region_processing_tenant_aware_supported']}, "
        f"cloud={result['summary']['region_processing_cloud_supported']}, "
        f"hints={result['summary']['region_processing_hint_count']}"
    )
    print(
        "Self-hosting: "
        f"self_hosted={result['summary']['self_hosting_self_hosted_mode']}, "
        f"multi_tenant={result['summary']['self_hosting_multi_tenant_mode']}, "
        f"ee={result['summary']['self_hosting_enterprise_features_enabled']}, "
        f"license_enforcement={result['summary']['self_hosting_license_enforcement_enabled']}, "
        f"has_license={result['summary']['self_hosting_has_license']}, "
        f"status={result['summary']['self_hosting_license_status'] or 'none'}, "
        f"source={result['summary']['self_hosting_license_source'] or 'none'}, "
        f"seats={result['summary']['self_hosting_seat_count'] or 0}, "
        f"used={result['summary']['self_hosting_used_seat_count'] or 0}, "
        f"license_api={result['summary']['self_hosting_has_license_api']}, "
        f"billing_page={result['summary']['self_hosting_has_admin_billing_page']}, "
        f"proxy={result['summary']['self_hosting_has_cloud_proxy']}, "
        f"install={result['summary']['self_hosting_has_install_script']}, "
        f"helm={result['summary']['self_hosting_has_helm_install_path']}"
    )
    print(
        "SCIM: "
        f"active_tokens={result['summary']['scim_active_token_count']}, "
        f"user_mappings={result['summary']['scim_user_mapping_count']}, "
        f"group_mappings={result['summary']['scim_group_mapping_count']}, "
        f"group_sync_failures={result['summary']['scim_group_sync_failure_count']}"
    )
    print(
        "Secrets encryption: "
        f"enabled={result['summary']['secrets_encryption_enabled']}, "
        f"columns={result['summary']['secrets_encryption_column_count']}"
    )
    print(
        "Permission inheritance: "
        f"sync_cc_pairs={result['summary']['permission_sync_cc_pairs']}, "
        f"docs_with_external_acl={result['summary']['permission_docs_with_external_acl']}, "
        f"doc_sync_failures={result['summary']['permission_doc_sync_failures']}, "
        f"group_sync_failures={result['summary']['permission_group_sync_failures']}"
    )
    if result.get("recommended_next_actions"):
        print("Recommended next actions:")
        for action in result["recommended_next_actions"]:
            print(f"  - {action}")

    if result["ok"]:
        print("\nResult: OK")
        return

    print("\nResult: FAILED")
    for failure in result["failures"]:
        print(f"  - {failure}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Minimal acceptance verification for the Onyx security platform"
    )
    parser.add_argument("--url", default=os.environ.get("ONYX_URL", "http://localhost:8080"))
    parser.add_argument(
        "--email",
        default=os.environ.get("ONYX_EMAIL", "security-admin@onyx.local"),
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("ONYX_PASSWORD", "admin123"),
    )
    parser.add_argument(
        "--db-password",
        default=os.environ.get("POSTGRES_PASSWORD"),
    )
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    args = parser.parse_args()

    cookie = get_cookie(args.url, args.email, args.password)
    if not cookie:
        print("[ERROR] Login failed. Check credentials.")
        return 1

    deployment_profile_summary = load_deployment_profile_summary()
    security_tool_configs = load_security_tool_configs()
    expected_personas = set(build_persona_tool_requirements(security_tool_configs))
    personas = [
        get_persona(args.url, cookie, persona["id"])
        for persona in list_personas(args.url, cookie)
        if persona["name"] in expected_personas
    ]
    openapi_tools = list_openapi_tools(args.url, cookie)
    result = evaluate_acceptance(
        document_sets=list_document_sets(args.url, cookie),
        personas=personas,
        openapi_tools=openapi_tools,
        ingestion_docs=list_ingestion_documents(args.url, cookie),
        db_state=fetch_db_state(db_password=args.db_password),
        threat_intel_sync_summary=load_threat_intel_sync_summary(deployment_profile_summary),
        threat_intel_curation_summary=load_threat_intel_curation_summary(),
        historical_package_summary=load_historical_package_summary(),
        archive_execution_summary=load_archive_execution_summary(),
        security_tool_profile_summary=load_security_tool_profile_summary(
            openapi_tools, deployment_profile_summary
        ),
        deployment_profile_summary=deployment_profile_summary,
        playbook_definitions_summary=load_playbook_definitions_summary(),
    )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print_human_result(result)

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
