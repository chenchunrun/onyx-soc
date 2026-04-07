#!/usr/bin/env python3
"""
Security Tools Setup Script for Onyx Security Knowledge Base

Creates OpenAPI tools for security integrations and attaches them to security personas.

Usage:
    python setup_security_tools.py --list-templates
    python setup_security_tools.py --create-tool --template <name> --name <name> [options]
    python setup_security_tools.py --attach-tool --tool-name <name> --persona-id <id>
    python setup_security_tools.py --detach-tool --tool-name <name> --persona-id <id>
    python setup_security_tools.py --list-tools
    python setup_security_tools.py --delete-tool --tool-name <name>
    python setup_security_tools.py --apply  # Create all recommended tools + bindings
    python setup_security_tools.py --dry-run

Requirements:
    pip install requests
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

venv_path = Path(__file__).parent.parent / ".venv"
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "lib" / "python3.12" / "site-packages"))

import psycopg2
import psycopg2.extras
import requests
import yaml


INTEGRATIONS_DIR = (
    Path(__file__).resolve().parents[2] / "docs" / "security-platform" / "5-integrations"
)
INTEGRATION_PROFILES_PATH = INTEGRATIONS_DIR / "profiles.yaml"
SECURITY_PERSONA_NAMES = {
    "安全事件分析师",
    "应急响应指挥官",
    "漏洞评估专家",
    "合规审计员",
}
SUPPORTED_TEMPLATES = {
    "security_alert_webhook": {
        "required_fields": ["webhook_url_env"],
    },
    "security_ticket_api": {
        "required_fields": ["api_url_env", "api_key_env"],
        "header_key": "Authorization",
    },
    "threat_intel_api": {
        "required_fields": ["api_url_env", "api_key_env"],
        "header_key": "x-apikey",
    },
    "siem_search_api": {
        "required_fields": ["api_url_env", "api_key_env"],
        "header_key": "Authorization",
    },
    "edr_response_api": {
        "required_fields": ["api_url_env", "api_key_env"],
        "header_key": "Authorization",
    },
    "asset_inventory_api": {
        "required_fields": ["api_url_env", "api_key_env"],
        "header_key": "Authorization",
    },
}


def custom_headers_for_template(
    template_name: str,
    api_key: str | None,
) -> list[dict[str, str]] | None:
    if not api_key:
        return None

    header_key = SUPPORTED_TEMPLATES.get(template_name, {}).get("header_key")
    if not header_key:
        return None

    if header_key.lower() == "authorization":
        return [{"key": header_key, "value": f"Bearer {api_key}"}]
    return [{"key": header_key, "value": api_key}]


def get_cookie(base_url: str, email: str, password: str) -> str | None:
    """Login via API and return session cookie."""
    try:
        resp = requests.post(
            f"{base_url}/auth/login",
            data={"username": email, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        if resp.status_code == 204:
            cookie = resp.headers.get("set-cookie", "")
            for part in cookie.split(","):
                part = part.strip()
                if "fastapiusersauth=" in part:
                    return part.split(";")[0].split("=")[1]
        return None
    except Exception as e:
        print(f"  [WARN] Login failed: {e}")
        return None


def list_tools(base_url: str, cookie: str) -> list[dict]:
    """List all available tools."""
    resp = requests.get(
        f"{base_url}/tool/openapi",
        cookies={"fastapiusersauth": cookie},
        timeout=10
    )
    if resp.status_code == 200:
        return resp.json()
    print(f"  [ERROR] Failed to list tools: {resp.status_code}")
    return []


def list_personas(base_url: str, cookie: str) -> list[dict]:
    """List all personas with their tools."""
    resp = requests.get(
        f"{base_url}/persona",
        cookies={"fastapiusersauth": cookie},
        timeout=10
    )
    if resp.status_code == 200:
        return resp.json()
    print(f"  [ERROR] Failed to list personas: {resp.status_code}")
    return []


def get_persona_id_by_name(base_url: str, cookie: str, persona_name: str) -> int | None:
    for persona in list_personas(base_url, cookie):
        if persona["name"] == persona_name:
            return persona["id"]
    return None


def create_tool(base_url: str, cookie: str, name: str, description: str,
                definition: dict, custom_headers: list | None = None,
                passthrough_auth: bool = False) -> dict | None:
    """Create a new OpenAPI tool."""
    payload = {
        "name": name,
        "description": description,
        "passthrough_auth": passthrough_auth,
        "definition": definition,
    }
    if custom_headers:
        payload["custom_headers"] = custom_headers

    resp = requests.post(
        f"{base_url}/admin/tool/custom",
        json=payload,
        cookies={"fastapiusersauth": cookie},
        timeout=30
    )
    if resp.status_code == 200:
        result = resp.json()
        print(f"  [OK] Created tool: {name} (id={result['id']})")
        return result
    elif resp.status_code == 400:
        error = resp.json().get("detail", str(resp.json()))
        print(f"  [ERROR] {error}")
    else:
        print(f"  [ERROR] Failed to create tool: {resp.status_code} - {resp.text[:200]}")
    return None


def update_tool(
    base_url: str,
    cookie: str,
    tool_id: int,
    name: str,
    description: str,
    definition: dict,
    custom_headers: list | None = None,
    passthrough_auth: bool = False,
) -> dict | None:
    payload = {
        "name": name,
        "description": description,
        "definition": definition,
        "passthrough_auth": passthrough_auth,
        "custom_headers": custom_headers or [],
    }

    resp = requests.put(
        f"{base_url}/admin/tool/custom/{tool_id}",
        json=payload,
        cookies={"fastapiusersauth": cookie},
        timeout=30,
    )
    if resp.status_code == 200:
        result = resp.json()
        print(f"  [OK] Updated tool: {name} (id={result['id']})")
        return result
    elif resp.status_code == 400:
        error = resp.json().get("detail", str(resp.json()))
        print(f"  [ERROR] {error}")
    else:
        print(f"  [ERROR] Failed to update tool: {resp.status_code} - {resp.text[:200]}")
    return None


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


def get_db_connection(password: str | None = None):
    """Get database connection to Onyx PostgreSQL."""
    if password is None:
        for pwd in ["password", "postgres", "onyx", ""]:
            try:
                conn = psycopg2.connect(
                    host="localhost", port=5432, database="postgres",
                    user="postgres", password=pwd, connect_timeout=3
                )
                conn.close()
                password = pwd
                break
            except Exception:
                continue
        if password is None:
            raise RuntimeError("Could not connect to PostgreSQL with known passwords")
    return psycopg2.connect(
        host="localhost", port=5432, database="postgres",
        user="postgres", password=password
    )


def run_docker_psql(sql: str, capture_output: bool = True) -> str:
    stdout = subprocess.PIPE if capture_output else subprocess.DEVNULL
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
            "-c",
            sql,
        ],
        check=True,
        stdout=stdout,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip() if capture_output else ""


def attach_tools_to_persona_db(
    persona_id: int,
    tool_ids: list[int],
    db_password: str | None = None,
) -> None:
    if not tool_ids:
        return

    try:
        conn = get_db_connection(password=db_password)
        try:
            with conn.cursor() as cur:
                for tool_id in tool_ids:
                    cur.execute(
                        """
                        INSERT INTO persona__tool (persona_id, tool_id)
                        VALUES (%s, %s)
                        ON CONFLICT (persona_id, tool_id) DO NOTHING
                        """,
                        (persona_id, tool_id),
                    )
            conn.commit()
            return
        finally:
            conn.close()
    except Exception:
        values = ", ".join(f"({persona_id}, {tool_id})" for tool_id in tool_ids)
        run_docker_psql(
            "INSERT INTO persona__tool (persona_id, tool_id) "
            f"VALUES {values} "
            "ON CONFLICT (persona_id, tool_id) DO NOTHING;",
            capture_output=False,
        )


def delete_tool(base_url: str, cookie: str, tool_id: int) -> bool:
    """Delete a tool by ID."""
    resp = requests.delete(
        f"{base_url}/admin/tool/custom/{tool_id}",
        cookies={"fastapiusersauth": cookie},
        timeout=10
    )
    if resp.status_code in (200, 204):
        print(f"  [OK] Deleted tool id={tool_id}")
        return True
    print(f"  [ERROR] Failed to delete tool: {resp.status_code}")
    return False


def get_tool_id(base_url: str, cookie: str, tool_name: str) -> int | None:
    """Get tool ID by name."""
    tools = list_tools(base_url, cookie)
    for tool in tools:
        if tool["name"] == tool_name:
            return tool["id"]
    return None


def get_tool_by_name(base_url: str, cookie: str, tool_name: str) -> dict[str, Any] | None:
    tools = list_tools(base_url, cookie)
    for tool in tools:
        if tool["name"] == tool_name:
            return tool
    return None


def get_persona(base_url: str, cookie: str, persona_id: int) -> dict | None:
    """Get persona details."""
    resp = requests.get(
        f"{base_url}/persona/{persona_id}",
        cookies={"fastapiusersauth": cookie},
        timeout=10
    )
    if resp.status_code == 200:
        return resp.json()
    return None


def is_builtin_tool(tool: dict[str, Any] | None) -> bool:
    return bool(tool and tool.get("in_code_tool_id"))


def _normalize_reference_ids(values: list) -> list:
    normalized = []
    for value in values:
        if isinstance(value, dict):
            ref_id = value.get("id")
            if ref_id is not None:
                normalized.append(ref_id)
        else:
            normalized.append(value)
    return normalized


def build_persona_update_payload(persona: dict, tool_ids: list[int]) -> dict:
    return {
        "name": persona["name"],
        "description": persona["description"],
        "document_set_ids": [doc_set["id"] for doc_set in persona.get("document_sets", [])],
        "is_public": persona["is_public"],
        "llm_model_provider_override": persona.get("llm_model_provider_override"),
        "llm_model_version_override": persona.get("llm_model_version_override"),
        "starter_messages": persona.get("starter_messages"),
        "users": _normalize_reference_ids(persona.get("users", [])),
        "groups": _normalize_reference_ids(persona.get("groups", [])),
        "tool_ids": tool_ids,
        "remove_image": None,
        "uploaded_image_id": persona.get("uploaded_image_id"),
        "icon_name": persona.get("icon_name"),
        "search_start_date": persona.get("search_start_date"),
        "label_ids": _normalize_reference_ids(persona.get("labels", [])),
        "is_featured": persona.get("is_featured", False),
        "user_file_ids": persona.get("user_file_ids", []),
        "hierarchy_node_ids": _normalize_reference_ids(persona.get("hierarchy_nodes", [])),
        "document_ids": _normalize_reference_ids(persona.get("attached_documents", [])),
        "system_prompt": persona.get("system_prompt", ""),
        "replace_base_system_prompt": False,
        "task_prompt": persona.get("task_prompt", ""),
        "datetime_aware": persona.get("datetime_aware", True),
    }


def update_persona_tools(base_url: str, cookie: str, persona_id: int,
                        tool_ids: list[int]) -> bool:
    """Update persona's attached tools."""
    persona = get_persona(base_url, cookie, persona_id)
    if not persona:
        print(f"  [ERROR] Persona not found: {persona_id}")
        return False

    resp = requests.patch(
        f"{base_url}/persona/{persona_id}",
        json=build_persona_update_payload(persona, tool_ids),
        cookies={"fastapiusersauth": cookie},
        timeout=10
    )
    if resp.status_code == 200:
        return True
    print(f"  [ERROR] Failed to update persona {persona_id}: {resp.status_code} - {resp.text[:200]}")
    return False


def get_persona_tool_ids(base_url: str, cookie: str, persona_id: int) -> list[int]:
    """Get tool IDs attached to a persona."""
    persona = get_persona(base_url, cookie, persona_id)
    if persona:
        return [t["id"] for t in persona.get("tools", [])]
    return []


def split_persona_tool_ids(persona: dict[str, Any]) -> tuple[list[int], list[int]]:
    builtin_tool_ids: list[int] = []
    custom_tool_ids: list[int] = []
    for tool in persona.get("tools", []):
        tool_id = tool.get("id")
        if tool_id is None:
            continue
        if is_builtin_tool(tool):
            builtin_tool_ids.append(tool_id)
        else:
            custom_tool_ids.append(tool_id)
    return builtin_tool_ids, custom_tool_ids


def merge_tool_ids(existing_tool_ids: list[int], added_tool_ids: list[int]) -> list[int]:
    merged: list[int] = []
    seen: set[int] = set()
    for tool_id in existing_tool_ids + added_tool_ids:
        if tool_id not in seen:
            merged.append(tool_id)
            seen.add(tool_id)
    return merged


def tool_needs_update(
    existing_tool: dict[str, Any],
    description: str,
    definition: dict[str, Any],
    custom_headers: list | None,
    passthrough_auth: bool,
) -> bool:
    return any(
        [
            existing_tool.get("description") != description,
            existing_tool.get("definition") != definition,
            (existing_tool.get("custom_headers") or []) != (custom_headers or []),
            bool(existing_tool.get("passthrough_auth")) != passthrough_auth,
        ]
    )


def load_integration_configs() -> list[dict[str, Any]]:
    configs: list[dict[str, Any]] = []
    seen_tool_names: set[str] = set()
    for config_path in sorted(INTEGRATIONS_DIR.glob("*.yaml")):
        if config_path.name == INTEGRATION_PROFILES_PATH.name:
            continue
        with open(config_path, "r", encoding="utf-8") as handle:
            config = yaml.safe_load(handle)
        if not isinstance(config, dict):
            raise ValueError(f"Invalid integration config: {config_path}")
        validate_integration_config(config, config_path)
        tool_name = str(config["name"])
        if tool_name in seen_tool_names:
            raise ValueError(
                f"Duplicate integration tool name detected: {tool_name} ({config_path})"
            )
        seen_tool_names.add(tool_name)
        config["_config_path"] = str(config_path)
        configs.append(config)
    if not configs:
        raise ValueError(f"No integration configs found in {INTEGRATIONS_DIR}")
    return configs


def load_integration_profiles() -> dict[str, Any]:
    with open(INTEGRATION_PROFILES_PATH, "r", encoding="utf-8") as handle:
        profiles = yaml.safe_load(handle)
    if not isinstance(profiles, dict):
        raise ValueError(f"Invalid integration profiles: {INTEGRATION_PROFILES_PATH}")
    defined_profiles = profiles.get("profiles")
    if not isinstance(defined_profiles, dict) or not defined_profiles:
        raise ValueError(
            f"Integration profiles {INTEGRATION_PROFILES_PATH} must define profiles"
        )
    return profiles


def selected_profile_name(args: argparse.Namespace | None = None) -> str:
    if args is not None and getattr(args, "profile", None):
        return str(args.profile)
    return os.environ.get("SECURITY_TOOLS_PROFILE", "live")


def selected_profile(args: argparse.Namespace | None = None) -> dict[str, Any]:
    profiles = load_integration_profiles()["profiles"]
    profile_name = selected_profile_name(args)
    if profile_name not in profiles:
        supported = ", ".join(sorted(profiles))
        raise ValueError(
            f"Unsupported security tools profile: {profile_name}. Supported: {supported}"
        )
    profile = profiles[profile_name]
    if not isinstance(profile, dict):
        raise ValueError(f"Invalid profile config for {profile_name}")
    env_overrides = profile.get("env_overrides", {})
    if env_overrides is None:
        profile["env_overrides"] = {}
    elif not isinstance(env_overrides, dict):
        raise ValueError(f"Profile {profile_name} must define env_overrides as a mapping")
    return profile


def resolve_profile_env_name(
    logical_env_name: str | None,
    args: argparse.Namespace | None = None,
) -> str:
    if not logical_env_name:
        return ""
    profile = selected_profile(args)
    override_name = profile.get("env_overrides", {}).get(logical_env_name)
    return str(override_name or logical_env_name)


def resolve_profile_env_value(
    logical_env_name: str | None,
    args: argparse.Namespace | None = None,
) -> str:
    resolved_env_name = resolve_profile_env_name(logical_env_name, args)
    if not resolved_env_name:
        return ""
    return os.environ.get(resolved_env_name, "")


def validate_integration_config(config: dict[str, Any], config_path: Path) -> None:
    required_fields = ["name", "template", "description", "persona_bindings"]
    missing = [field for field in required_fields if not config.get(field)]
    if missing:
        raise ValueError(
            f"Integration config {config_path} missing required fields: {', '.join(missing)}"
        )

    template_name = str(config["template"])
    if template_name not in SUPPORTED_TEMPLATES:
        supported = ", ".join(sorted(SUPPORTED_TEMPLATES))
        raise ValueError(
            f"Integration config {config_path} uses unsupported template "
            f"{template_name}. Supported templates: {supported}"
        )

    persona_bindings = config["persona_bindings"]
    if not isinstance(persona_bindings, list) or not all(
        isinstance(persona_name, str) and persona_name.strip()
        for persona_name in persona_bindings
    ):
        raise ValueError(
            f"Integration config {config_path} must define non-empty persona_bindings"
        )
    invalid_personas = [
        persona_name
        for persona_name in persona_bindings
        if str(persona_name) not in SECURITY_PERSONA_NAMES
    ]
    if invalid_personas:
        raise ValueError(
            f"Integration config {config_path} references unsupported personas: "
            f"{', '.join(str(persona) for persona in invalid_personas)}"
        )

    template_requirements = SUPPORTED_TEMPLATES[template_name]["required_fields"]
    template_missing = [
        field for field in template_requirements if not str(config.get(field, "")).strip()
    ]
    if template_missing:
        raise ValueError(
            f"Integration config {config_path} missing template-specific fields: "
            f"{', '.join(template_missing)}"
        )


def validate_integration_directory(profile_name: str | None = None) -> list[dict[str, Any]]:
    configs = load_integration_configs()
    profiles = load_integration_profiles()["profiles"]
    print(f"Integration profile: {selected_profile_name(argparse.Namespace(profile=profile_name) if profile_name else None)}")
    print(f"Available profiles: {', '.join(sorted(profiles))}")
    print(f"Integration configs: {len(configs)}")
    for config in configs:
        print(
            f"  - {config['name']} ({config['template']}) -> "
            f"{', '.join(config['persona_bindings'])}"
        )
    print("[OK] Integration config validation passed")
    return configs


def build_persona_bindings(
    integration_configs: list[dict[str, Any]],
) -> dict[str, list[str]]:
    persona_bindings: dict[str, list[str]] = {}
    for config in integration_configs:
        tool_name = str(config["name"])
        for persona_name in config.get("persona_bindings", []):
            persona_bindings.setdefault(str(persona_name), []).append(tool_name)
    return persona_bindings


# ─── OpenAPI Template Definitions ─────────────────────────────────────────────

def load_template(template_name: str) -> dict | None:
    """Load an OpenAPI template from file."""
    templates_dir = Path(__file__).parent / "openapi_templates"
    template_file = templates_dir / f"{template_name}.json"
    if not template_file.exists():
        print(f"  [ERROR] Template not found: {template_name}")
        print(f"  Available templates: security_alert_webhook, security_ticket_api, threat_intel_api")
        return None
    with open(template_file, "r", encoding="utf-8") as f:
        return json.load(f)


def get_template_definitions() -> dict:
    """Return all tool definitions for --apply."""
    templates_dir = Path(__file__).parent / "openapi_templates"
    definitions = {}
    for json_file in templates_dir.glob("*.json"):
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            tool_name = json_file.stem
            definitions[tool_name] = data
    return definitions


def resolve_env(value: str, env_var: str, required: bool = False) -> str:
    """Resolve environment variable in value string."""
    if value.startswith("${") and value.endswith("}"):
        var_name = value[2:-1]
        env_value = os.environ.get(var_name)
        if env_value:
            return env_value
        if required:
            print(f"  [WARN] Environment variable {var_name} not set")
        return ""
    return value


def apply_tool_definitions(
    base_url: str,
    cookie: str,
    dry_run: bool = False,
    profile_name: str | None = None,
) -> dict:
    """Create all recommended security tools and attach to personas."""
    profile_args = argparse.Namespace(profile=profile_name) if profile_name else None
    integration_configs = load_integration_configs()
    persona_bindings = build_persona_bindings(integration_configs)
    results = {
        "tools_created": [],
        "tools_updated": [],
        "personas_updated": [],
        "errors": [],
    }

    # Step 1: Create tools
    tool_id_map = {}  # name -> id

    for config in integration_configs:
        tool_name = str(config["name"])
        template = load_template(str(config["template"]))
        if not template:
            results["errors"].append(f"Failed to load template: {config['template']}")
            continue

        # Replace variables in server URLs
        for server in template.get("servers", []):
            base_url_val = server.get("url", "")
            if "WEBHOOK_URL" in base_url_val:
                env_val = resolve_profile_env_value(config.get("webhook_url_env", ""), profile_args)
                if env_val:
                    server["url"] = env_val
            elif "API_BASE_URL" in base_url_val:
                env_val = resolve_profile_env_value(config.get("api_url_env", ""), profile_args)
                if env_val:
                    server["url"] = env_val

        api_key = resolve_profile_env_value(config.get("api_key_env", ""), profile_args)
        custom_headers = custom_headers_for_template(str(config["template"]), api_key)

        if dry_run:
            print(f"  [DRY RUN] Would create tool: {tool_name}")
            print(f"    Template: {config['template']}")
            print(f"    Description: {str(config['description'])[:100]}...")
            if config.get("webhook_url_env"):
                print(
                    f"    Env: {config['webhook_url_env']} -> "
                    f"{resolve_profile_env_name(config.get('webhook_url_env', ''), profile_args)}"
                )
            if config.get("api_url_env"):
                print(
                    f"    Env: {config['api_url_env']} -> "
                    f"{resolve_profile_env_name(config.get('api_url_env', ''), profile_args)}"
                )
            if config.get("api_key_env"):
                print(
                    f"    Env: {config['api_key_env']} -> "
                    f"{resolve_profile_env_name(config.get('api_key_env', ''), profile_args)}"
                )
            tool_id_map[tool_name] = f"DRY_RUN_{tool_name}"
            continue

        # Check if tool already exists
        existing_tool = get_tool_by_name(base_url, cookie, tool_name)
        if existing_tool:
            existing_id = existing_tool["id"]
            if tool_needs_update(
                existing_tool=existing_tool,
                description=str(config["description"]),
                definition=template,
                custom_headers=custom_headers,
                passthrough_auth=False,
            ):
                updated_tool = update_tool(
                    base_url=base_url,
                    cookie=cookie,
                    tool_id=existing_id,
                    name=tool_name,
                    description=str(config["description"]),
                    definition=template,
                    custom_headers=custom_headers,
                    passthrough_auth=False,
                )
                if not updated_tool:
                    results["errors"].append(f"Failed to update tool: {tool_name}")
                    continue
                tool_id_map[tool_name] = updated_tool["id"]
                results["tools_updated"].append(tool_name)
                continue

            print(f"  [SKIP] Tool already matches target profile: {tool_name} (id={existing_id})")
            tool_id_map[tool_name] = existing_id
            results["tools_updated"].append(tool_name)
            continue

        tool = create_tool(
            base_url=base_url,
            cookie=cookie,
            name=tool_name,
            description=str(config["description"]),
            definition=template,
            custom_headers=custom_headers,
            passthrough_auth=False,
        )
        if tool:
            tool_id_map[tool_name] = tool["id"]
            results["tools_created"].append(tool_name)
        else:
            results["errors"].append(f"Failed to create tool: {tool_name}")

    if dry_run:
        for persona_name, tool_names in persona_bindings.items():
            print(f"  [DRY RUN] Would attach to persona {persona_name}: {tool_names}")
        return results

    for persona_name, tool_names in persona_bindings.items():
        persona_id = get_persona_id_by_name(base_url, cookie, persona_name)
        if persona_id is None:
            results["errors"].append(f"Persona not found: {persona_name}")
            continue

        persona = get_persona(base_url, cookie, persona_id)
        if not persona:
            results["errors"].append(f"Persona not found: {persona_name}")
            continue

        builtin_tool_ids, existing_custom_tool_ids = split_persona_tool_ids(persona)
        desired_tool_ids = [
            tool_id_map[tool_name]
            for tool_name in tool_names
            if tool_name in tool_id_map and isinstance(tool_id_map[tool_name], int)
        ]
        merged_tool_ids = merge_tool_ids(existing_custom_tool_ids, desired_tool_ids)

        if merged_tool_ids == existing_custom_tool_ids:
            print(f"  [SKIP] Persona already has required tools: {persona_name} (id={persona_id})")
            continue

        if update_persona_tools(base_url, cookie, persona_id, merged_tool_ids):
            if builtin_tool_ids:
                try:
                    attach_tools_to_persona_db(persona_id, builtin_tool_ids)
                except Exception as exc:
                    results["errors"].append(
                        f"Failed to restore builtin tools for persona {persona_name}: {exc}"
                    )
                    continue
            print(
                f"  [OK] Attached tools to persona {persona_name} (id={persona_id}): "
                f"{desired_tool_ids}"
            )
            results["personas_updated"].append(persona_id)
        else:
            results["errors"].append(f"Failed to update persona tools: {persona_name}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Setup security integration tools for Onyx Security Knowledge Base"
    )
    parser.add_argument("--url", default=os.environ.get("ONYX_URL", "http://localhost:8080"))
    parser.add_argument("--email", default=os.environ.get("ONYX_EMAIL", "security-admin@onyx.local"))
    parser.add_argument("--password", default=os.environ.get("ONYX_PASSWORD", "admin123"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true",
                        help="Create all recommended tools and attach to personas")
    parser.add_argument("--list-templates", action="store_true")
    parser.add_argument("--validate-configs", action="store_true")
    parser.add_argument(
        "--profile",
        choices=["live", "mock"],
        default=os.environ.get("SECURITY_TOOLS_PROFILE", "live"),
        help="Security tools integration profile. 'mock' remaps env vars to the local mock tool server.",
    )
    parser.add_argument("--list-tools", action="store_true")
    parser.add_argument("--create-tool", action="store_true")
    parser.add_argument("--template", choices=sorted(SUPPORTED_TEMPLATES),
                        help="Template name")
    parser.add_argument("--name", help="Tool name (for --create-tool)")
    parser.add_argument("--description", help="Tool description (for --create-tool)")
    parser.add_argument("--webhook-url", help="Webhook URL (for security_alert_webhook)")
    parser.add_argument("--api-url", help="API base URL (for ticket/threat-intel)")
    parser.add_argument("--api-key", help="API key (for ticket/threat-intel)")
    parser.add_argument("--attach-tool", action="store_true")
    parser.add_argument("--detach-tool", action="store_true")
    parser.add_argument("--tool-name", help="Tool name")
    parser.add_argument("--persona-id", type=int, help="Persona ID")
    parser.add_argument("--delete-tool", action="store_true")
    args = parser.parse_args()

    if args.list_templates:
        print("Available templates:")
        for name in sorted(SUPPORTED_TEMPLATES):
            print(f"  - {name}")
        print(f"\nTemplates are located at: {Path(__file__).parent}/openapi_templates/")
        print(f"Integration configs are located at: {INTEGRATIONS_DIR}")
        print(f"Integration profiles are located at: {INTEGRATION_PROFILES_PATH}")
        print(f"Supported personas: {', '.join(sorted(SECURITY_PERSONA_NAMES))}")
        return

    if args.validate_configs:
        validate_integration_directory(profile_name=args.profile)
        return

    cookie = ""
    if not args.dry_run:
        print(f"Logging in as {args.email}...")
        cookie = get_cookie(args.url, args.email, args.password)
        if not cookie:
            print("[ERROR] Login failed. Check credentials.")
            sys.exit(1)
        print("[OK] Logged in.\n")

    if args.list_tools:
        persona_bindings = build_persona_bindings(load_integration_configs())
        tools = list_tools(args.url, cookie)
        print(f"Available OpenAPI Tools ({len(tools)}):")
        for tool in tools:
            print(f"  [{tool['id']}] {tool['name']}")
            print(f"       {tool.get('description', '')[:100]}")
        print()
        # Get full details for security personas
        for persona_name in persona_bindings:
            persona_id = get_persona_id_by_name(args.url, cookie, persona_name)
            if persona_id is None:
                print(f"  [MISSING] {persona_name}")
                continue
            p = get_persona(args.url, cookie, persona_id)
            if p:
                tool_ids = [t["id"] for t in p.get("tools", [])]
                print(f"  [{persona_id}] {p['name']}: tool_ids={tool_ids}")
        return

    if args.create_tool:
        if not args.name or not args.template:
            parser.print_help()
            return

        template = load_template(args.template)
        if not template:
            return

        # Override server URL
        if args.webhook_url:
            for server in template.get("servers", []):
                server["url"] = args.webhook_url
        elif args.api_url:
            for server in template.get("servers", []):
                server["url"] = args.api_url

        description = args.description or f"Security {args.template} tool"
        custom_headers = custom_headers_for_template(args.template, args.api_key)

        create_tool(
            args.url, cookie, args.name, description,
            template, custom_headers, passthrough_auth=False
        )
        return

    if args.attach_tool:
        if not args.tool_name or not args.persona_id:
            parser.print_help()
            return

        tool_id = get_tool_id(args.url, cookie, args.tool_name)
        if not tool_id:
            print(f"[ERROR] Tool not found: {args.tool_name}")
            return

        current = get_persona_tool_ids(args.url, cookie, args.persona_id)
        if tool_id in current:
            print(f"[SKIP] Tool {args.tool_name} already attached to persona {args.persona_id}")
            return

        updated = current + [tool_id]
        if update_persona_tools(args.url, cookie, args.persona_id, updated):
            print(f"[OK] Attached {args.tool_name} to persona {args.persona_id}")
        return

    if args.detach_tool:
        if not args.tool_name or not args.persona_id:
            parser.print_help()
            return

        tool_id = get_tool_id(args.url, cookie, args.tool_name)
        if not tool_id:
            print(f"[ERROR] Tool not found: {args.tool_name}")
            return

        current = get_persona_tool_ids(args.url, cookie, args.persona_id)
        if tool_id not in current:
            print(f"[SKIP] Tool {args.tool_name} not attached to persona {args.persona_id}")
            return

        updated = [t for t in current if t != tool_id]
        if update_persona_tools(args.url, cookie, args.persona_id, updated):
            print(f"[OK] Detached {args.tool_name} from persona {args.persona_id}")
        return

    if args.delete_tool:
        if not args.tool_name:
            parser.print_help()
            return

        tool_id = get_tool_id(args.url, cookie, args.tool_name)
        if not tool_id:
            print(f"[ERROR] Tool not found: {args.tool_name}")
            return

        if delete_tool(args.url, cookie, tool_id):
            print(f"[OK] Deleted tool: {args.tool_name}")
        return

    if args.apply or args.dry_run:
        if args.apply and args.dry_run:
            print("Dry run mode - showing what would be done...\n")
        elif args.apply:
            print("Applying security tool configurations...\n")
        results = apply_tool_definitions(
            args.url,
            cookie,
            dry_run=args.dry_run,
            profile_name=args.profile,
        )
        print()
        if results["errors"]:
            print(f"Errors: {len(results['errors'])}")
            for err in results["errors"]:
                print(f"  - {err}")
        else:
            print(f"[OK] Done!")
            print(f"  Tools created: {len(results['tools_created'])}")
            print(f"  Tools skipped (existing): {len(results['tools_updated'])}")
            print(f"  Personas updated: {len(results['personas_updated'])}")
            print()
            print("Environment variables to set:")
            print("  SECURITY_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...")
            print("  SECURITY_TICKET_API_URL=https://your-company.atlassian.net/rest/api/3")
            print("  SECURITY_TICKET_API_KEY=your-jira-api-token")
            print("  THREAT_INTEL_API_URL=https://www.virustotal.com/api/v3")
            print("  THREAT_INTEL_API_KEY=your-virustotal-api-key")
            print("  SECURITY_SIEM_API_URL=https://siem.example.com/api/v1")
            print("  SECURITY_SIEM_API_KEY=your-siem-api-token")
            print("  SECURITY_EDR_API_URL=https://edr.example.com/api/v1")
            print("  SECURITY_EDR_API_KEY=your-edr-api-token")
            print("  SECURITY_ASSET_API_URL=https://cmdb.example.com/api/v1")
            print("  SECURITY_ASSET_API_KEY=your-asset-api-token")
        return

    parser.print_help()
    print("\nExamples:")
    print("  python setup_security_tools.py --list-templates")
    print("  python setup_security_tools.py --list-tools")
    print("  python setup_security_tools.py --apply")
    print("  python setup_security_tools.py --apply --dry-run")
    print("  python setup_security_tools.py --attach-tool --tool-name send_security_alert --persona-id 3")


if __name__ == "__main__":
    main()
