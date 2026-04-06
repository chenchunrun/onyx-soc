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
import yaml

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from curate_threat_intel_corpus import build_unmanaged_report


SECURITY_DOCUMENT_SET_NAME = "安全知识库"
ROOT = MODULE_DIR
THREAT_INTEL_SYNC_PLAN_PATH = ROOT / "threat-intelligence" / "sync_plan.yaml"
THREAT_INTEL_SYNC_STATE_PATH = ROOT / "threat-intelligence" / "sync_state.json"
THREAT_INTEL_MANIFEST_PATH = ROOT / "threat-intelligence" / "feed_manifest.json"
THREAT_INTEL_CURATION_REPORT_PATH = ROOT / "threat-intelligence" / "unmanaged_feed_report.json"
SECURITY_TOOL_INTEGRATIONS_DIR = (
    ROOT.parent / "docs" / "security-platform" / "5-integrations"
)
SECURITY_TOOL_PROFILES_PATH = SECURITY_TOOL_INTEGRATIONS_DIR / "profiles.yaml"
DEPLOYMENT_PROFILES_PATH = ROOT.parent / "docs" / "security-platform" / "deployment-profiles.yaml"

SECURITY_PERSONA_TOOL_REQUIREMENTS = {
    "安全事件分析师": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL"},
        "custom_tools": {"threat_intel_lookup", "create_security_ticket"},
    },
    "应急响应指挥官": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
        "custom_tools": {"send_security_alert", "create_security_ticket"},
    },
    "漏洞评估专家": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
        "custom_tools": {"threat_intel_lookup", "create_security_ticket"},
    },
    "合规审计员": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL"},
        "custom_tools": {"create_security_ticket"},
    },
}

SECURITY_USERS = {
    "commander@security.local",
    "analyst@security.local",
    "vuln_expert@security.local",
    "auditor@security.local",
}

EXPECTED_OPENAPI_TOOLS = {
    "create_security_ticket",
    "send_security_alert",
    "threat_intel_lookup",
}

USER_PERSONA_BY_EMAIL = {
    "commander@security.local": "应急响应指挥官",
    "analyst@security.local": "安全事件分析师",
    "vuln_expert@security.local": "漏洞评估专家",
    "auditor@security.local": "合规审计员",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_threat_intel_sync_summary() -> dict[str, Any]:
    profile = os.environ.get("THREAT_INTEL_SOURCE_PROFILE", "live")
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

    return {
        "governed_feeds": int(manifest_summary.get("total_feeds", 0) or 0),
        "governed_source_counts": manifest_summary.get("source_counts", {}) or {},
        "unmanaged_local_feeds": int(curation_summary.get("unmanaged_total", 0) or 0),
        "promotion_candidates": int(curation_summary.get("promotion_candidate_total", 0) or 0),
        "manual_review": int(curation_summary.get("manual_review_total", 0) or 0),
        "keep_runtime_only": int(curation_summary.get("keep_runtime_only_total", 0) or 0),
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


def load_security_tool_profile_summary(
    openapi_tools: list[dict[str, Any]],
) -> dict[str, Any]:
    profile_name = os.environ.get("SECURITY_TOOLS_PROFILE", "live")
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
        if config.get("template") == "security_ticket_api":
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
    }


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


def run_docker_psql_query(sql: str) -> list[list[str]]:
    result = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            "onyx-relational_db-1",
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
    persona_names = list(SECURITY_PERSONA_TOOL_REQUIREMENTS.keys())
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

    return {
        "persona_rows": persona_rows,
        "document_set_id": document_set_id,
        "user_rows": user_rows,
        "persona_user_links": persona_user_links,
        "document_set_links": document_set_links,
    }


def fetch_db_state(db_password: str | None = None) -> dict[str, Any]:
    try:
        conn = get_db_connection(password=db_password)
        try:
            with conn.cursor() as cur:
                persona_names = list(SECURITY_PERSONA_TOOL_REQUIREMENTS.keys())
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
        finally:
            conn.close()

        return {
            "persona_rows": persona_rows,
            "document_set_id": document_set_id,
            "user_rows": user_rows,
            "persona_user_links": persona_user_links,
            "document_set_links": document_set_links,
        }
    except Exception:
        return fetch_db_state_via_docker()


def build_persona_tool_aliases(persona: dict[str, Any]) -> set[str]:
    aliases: set[str] = set()
    for tool in persona.get("tools", []):
        for field in ("name", "display_name", "in_code_tool_id"):
            value = tool.get(field)
            if value:
                aliases.add(value)
    return aliases


def evaluate_acceptance(
    document_sets: list[dict[str, Any]],
    personas: list[dict[str, Any]],
    openapi_tools: list[dict[str, Any]],
    ingestion_docs: list[dict[str, Any]],
    db_state: dict[str, Any],
    threat_intel_sync_summary: dict[str, Any],
    threat_intel_curation_summary: dict[str, Any],
    security_tool_profile_summary: dict[str, Any],
    deployment_profile_summary: dict[str, Any],
) -> dict[str, Any]:
    failures: list[str] = []

    document_set = next(
        (document_set for document_set in document_sets if document_set["name"] == SECURITY_DOCUMENT_SET_NAME),
        None,
    )
    if document_set is None:
        failures.append(f"Missing document set: {SECURITY_DOCUMENT_SET_NAME}")

    openapi_tool_names = {tool["name"] for tool in openapi_tools}
    missing_openapi_tools = sorted(EXPECTED_OPENAPI_TOOLS - openapi_tool_names)
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

    persona_map = {persona["name"]: persona for persona in personas}
    missing_personas = sorted(
        set(SECURITY_PERSONA_TOOL_REQUIREMENTS.keys()) - set(persona_map.keys())
    )
    if missing_personas:
        failures.append(f"Missing personas: {', '.join(missing_personas)}")

    persona_tool_summary: dict[str, list[str]] = {}
    for persona_name, expected in SECURITY_PERSONA_TOOL_REQUIREMENTS.items():
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

    return {
        "ok": not failures,
        "failures": failures,
        "summary": {
            "document_set": SECURITY_DOCUMENT_SET_NAME if document_set else None,
            "deployment_profile": deployment_profile_summary["deployment_profile"],
            "deployment_required_env": deployment_profile_summary["required_env"],
            "openapi_tools_found": sorted(openapi_tool_names & EXPECTED_OPENAPI_TOOLS),
            "security_tools_profile": security_tool_profile_summary["profile"],
            "security_tools_summary": security_tool_profile_summary["tools"],
            "threat_intel_doc_count": len(threat_intel_doc_ids),
            "threat_intel_source_profile": threat_intel_sync_summary["source_profile"],
            "threat_intel_last_sync_run_at": threat_intel_sync_summary["last_sync_run_at"],
            "threat_intel_due_status": threat_intel_sync_summary["due_status"],
            "threat_intel_due_feeds": threat_intel_sync_summary["due_feeds"],
            "threat_intel_governed_feeds": threat_intel_curation_summary["governed_feeds"],
            "threat_intel_unmanaged_local_feeds": threat_intel_curation_summary["unmanaged_local_feeds"],
            "threat_intel_promotion_candidates": threat_intel_curation_summary["promotion_candidates"],
            "threat_intel_manual_review": threat_intel_curation_summary["manual_review"],
            "threat_intel_keep_runtime_only": threat_intel_curation_summary["keep_runtime_only"],
            "personas_found": sorted(persona_map.keys() & set(SECURITY_PERSONA_TOOL_REQUIREMENTS.keys())),
            "security_users_found": sorted(user_rows.keys() & SECURITY_USERS),
            "persona_tool_summary": persona_tool_summary,
            "persona_user_links": len(persona_user_links),
            "document_set_links": len(document_set_links),
        },
    }


def print_human_result(result: dict[str, Any]) -> None:
    print("=== Minimal Acceptance Check ===")
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
        f"unmanaged={result['summary']['threat_intel_unmanaged_local_feeds']}, "
        f"promotion_candidates={result['summary']['threat_intel_promotion_candidates']}, "
        f"manual_review={result['summary']['threat_intel_manual_review']}, "
        f"keep_runtime_only={result['summary']['threat_intel_keep_runtime_only']}"
    )
    if result["summary"]["threat_intel_due_feeds"]:
        print(
            "Threat-intel due feeds: "
            + ", ".join(result["summary"]["threat_intel_due_feeds"])
        )
    print("Personas:")
    for persona_name in sorted(SECURITY_PERSONA_TOOL_REQUIREMENTS):
        status = "OK" if persona_name in result["summary"]["personas_found"] else "MISSING"
        print(f"  - {persona_name}: {status}")
    print("Security users:")
    for email in sorted(SECURITY_USERS):
        status = "OK" if email in result["summary"]["security_users_found"] else "MISSING"
        print(f"  - {email}: {status}")
    print(f"Persona__user links: {result['summary']['persona_user_links']}")
    print(f"Document_set__user links: {result['summary']['document_set_links']}")

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

    personas = [
        get_persona(args.url, cookie, persona["id"])
        for persona in list_personas(args.url, cookie)
        if persona["name"] in SECURITY_PERSONA_TOOL_REQUIREMENTS
    ]
    openapi_tools = list_openapi_tools(args.url, cookie)
    result = evaluate_acceptance(
        document_sets=list_document_sets(args.url, cookie),
        personas=personas,
        openapi_tools=openapi_tools,
        ingestion_docs=list_ingestion_documents(args.url, cookie),
        db_state=fetch_db_state(db_password=args.db_password),
        threat_intel_sync_summary=load_threat_intel_sync_summary(),
        threat_intel_curation_summary=load_threat_intel_curation_summary(),
        security_tool_profile_summary=load_security_tool_profile_summary(openapi_tools),
        deployment_profile_summary=load_deployment_profile_summary(),
    )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print_human_result(result)

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
