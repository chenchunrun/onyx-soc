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
import sys
from pathlib import Path

venv_path = Path(__file__).parent.parent / ".venv"
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "lib" / "python3.12" / "site-packages"))

import psycopg2
import psycopg2.extras
import requests


PERSONA_BINDINGS = {
    "安全事件分析师": ["threat_intel_lookup", "create_security_ticket"],
    "应急响应指挥官": ["send_security_alert", "create_security_ticket"],
    "漏洞评估专家": ["threat_intel_lookup", "create_security_ticket"],
    "合规审计员": ["create_security_ticket"],
}


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


def attach_tool_to_persona(conn, persona_id: int, tool_id: int) -> bool:
    """Attach a tool to a persona via the junction table."""
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO persona__tool (persona_id, tool_id) VALUES (%s, %s) "
            "ON CONFLICT (persona_id, tool_id) DO NOTHING",
            (persona_id, tool_id)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"  [ERROR] Failed to attach tool {tool_id} to persona {persona_id}: {e}")
        conn.rollback()
        return False
    finally:
        cur.close()


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


def merge_tool_ids(existing_tool_ids: list[int], added_tool_ids: list[int]) -> list[int]:
    merged: list[int] = []
    seen: set[int] = set()
    for tool_id in existing_tool_ids + added_tool_ids:
        if tool_id not in seen:
            merged.append(tool_id)
            seen.add(tool_id)
    return merged


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


# ─── Tool Creation Configurations ─────────────────────────────────────────────

TOOL_CONFIGS = {
    "send_security_alert": {
        "template": "security_alert_webhook",
        "description": "Send security alerts to Slack, Teams, or PagerDuty. Use this when a security analyst detects a threat (phishing, malware, unauthorized access) and needs to notify the security team immediately. Required parameters: alert_type (PHISHING/MALWARE/DATA_BREACH/UNAUTHORIZED_ACCESS/DDoS/VULNERABILITY/COMPLIANCE_VIOLATION/INSIDER_THREAT), severity (P0/P1/P2/P3/P4), title, description, source_system. Optional: affected_assets, indicators (ips/domains/file_hashes/urls), recommended_actions.",
        "webhook_url_env": "SECURITY_ALERT_WEBHOOK_URL",
    },
    "create_security_ticket": {
        "template": "security_ticket_api",
        "description": "Create security incident tickets in Jira, Linear, or ServiceNow. Use this when a security analyst needs to document an incident, vulnerability, or compliance finding. Required: summary, description, priority (CRITICAL/HIGH/MEDIUM/LOW), project_key. Optional: labels, mitre_tactics, mitre_techniques, cvss_score, affected_systems.",
        "api_url_env": "SECURITY_TICKET_API_URL",
        "api_key_env": "SECURITY_TICKET_API_KEY",
    },
    "threat_intel_lookup": {
        "template": "threat_intel_api",
        "description": "Query threat intelligence databases (VirusTotal, AbuseIPDB, Shodan) for IP addresses, domains, and file hashes. Use this when you need to verify if an indicator (IP, domain, file hash) is known to be malicious. Required: the IP, domain, or hash parameter.",
        "api_url_env": "THREAT_INTEL_API_URL",
        "api_key_env": "THREAT_INTEL_API_KEY",
    },
}


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


def apply_tool_definitions(base_url: str, cookie: str, dry_run: bool = False) -> dict:
    """Create all recommended security tools and attach to personas."""
    results = {
        "tools_created": [],
        "tools_updated": [],
        "personas_updated": [],
        "errors": [],
    }

    # Step 1: Create tools
    tool_id_map = {}  # name -> id

    for tool_name, config in TOOL_CONFIGS.items():
        template = load_template(config["template"])
        if not template:
            results["errors"].append(f"Failed to load template: {config['template']}")
            continue

        # Replace variables in server URLs
        for server in template.get("servers", []):
            base_url_val = server.get("url", "")
            if "WEBHOOK_URL" in base_url_val:
                env_val = os.environ.get(config.get("webhook_url_env", ""), "")
                if env_val:
                    server["url"] = env_val
            elif "API_BASE_URL" in base_url_val:
                env_val = os.environ.get(config.get("api_url_env", ""), "")
                if env_val:
                    server["url"] = env_val

        # Add API key header for ticket API
        custom_headers = None
        if config["template"] == "security_ticket_api":
            api_key = os.environ.get(config.get("api_key_env", ""), "")
            if api_key:
                custom_headers = [{"key": "Authorization", "value": f"Bearer {api_key}"}]

        if dry_run:
            print(f"  [DRY RUN] Would create tool: {tool_name}")
            print(f"    Template: {config['template']}")
            print(f"    Description: {config['description'][:100]}...")
            tool_id_map[tool_name] = f"DRY_RUN_{tool_name}"
            continue

        # Check if tool already exists
        existing_id = get_tool_id(base_url, cookie, tool_name)
        if existing_id:
            print(f"  [SKIP] Tool already exists: {tool_name} (id={existing_id})")
            tool_id_map[tool_name] = existing_id
            results["tools_updated"].append(tool_name)
            continue

        tool = create_tool(
            base_url=base_url,
            cookie=cookie,
            name=tool_name,
            description=config["description"],
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
        for persona_name, tool_names in PERSONA_BINDINGS.items():
            print(f"  [DRY RUN] Would attach to persona {persona_name}: {tool_names}")
        return results

    for persona_name, tool_names in PERSONA_BINDINGS.items():
        persona_id = get_persona_id_by_name(base_url, cookie, persona_name)
        if persona_id is None:
            results["errors"].append(f"Persona not found: {persona_name}")
            continue

        current_tool_ids = get_persona_tool_ids(base_url, cookie, persona_id)
        desired_tool_ids = [
            tool_id_map[tool_name]
            for tool_name in tool_names
            if tool_name in tool_id_map and isinstance(tool_id_map[tool_name], int)
        ]
        merged_tool_ids = merge_tool_ids(current_tool_ids, desired_tool_ids)

        if merged_tool_ids == current_tool_ids:
            print(f"  [SKIP] Persona already has required tools: {persona_name} (id={persona_id})")
            continue

        if update_persona_tools(base_url, cookie, persona_id, merged_tool_ids):
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
    parser.add_argument("--list-tools", action="store_true")
    parser.add_argument("--create-tool", action="store_true")
    parser.add_argument("--template", choices=["security_alert_webhook", "security_ticket_api", "threat_intel_api"],
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

    cookie = ""
    if not args.dry_run:
        print(f"Logging in as {args.email}...")
        cookie = get_cookie(args.url, args.email, args.password)
        if not cookie:
            print("[ERROR] Login failed. Check credentials.")
            sys.exit(1)
        print("[OK] Logged in.\n")

    if args.list_templates:
        print("Available templates:")
        for name in ["security_alert_webhook", "security_ticket_api", "threat_intel_api"]:
            print(f"  - {name}")
        print(f"\nTemplates are located at: {Path(__file__).parent}/openapi_templates/")
        return

    if args.list_tools:
        tools = list_tools(args.url, cookie)
        print(f"Available OpenAPI Tools ({len(tools)}):")
        for tool in tools:
            print(f"  [{tool['id']}] {tool['name']}")
            print(f"       {tool.get('description', '')[:100]}")
        print()
        # Get full details for security personas
        for persona_name in PERSONA_BINDINGS:
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
        custom_headers = None
        if args.api_key:
            custom_headers = [{"key": "Authorization", "value": f"Bearer {args.api_key}"}]

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
        results = apply_tool_definitions(args.url, cookie, dry_run=args.dry_run)
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
