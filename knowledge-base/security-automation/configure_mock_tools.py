#!/usr/bin/env python3
"""
Configure mock server URLs for security tools.

Updates the openapi_schema and custom_headers of tools 11, 12, 13
to point to a mock server running on localhost:9999.

Usage:
    python configure_mock_tools.py [--port PORT] [--reset]
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

MOCK_SERVER = "http://localhost:9999"
API_KEY = "mock-api-key-for-testing"


def get_db_connection():
    """Get database connection with auto password detection."""
    for password in ["password", "postgres", "onyx", ""]:
        try:
            conn = psycopg2.connect(
                host="localhost", port=5432, database="postgres",
                user="postgres", password=password, connect_timeout=3
            )
            conn.close()
            return password
        except Exception:
            continue
    raise RuntimeError("Could not connect to database")


def load_schema(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def update_tool_schema(cur, tool_id: int, mock_url: str, api_key: str) -> bool:
    """Update a tool's openapi_schema to use mock server URL."""
    # Load the template
    template_map = {
        11: "openapi_templates/security_alert_webhook.json",
        12: "openapi_templates/security_ticket_api.json",
        13: "openapi_templates/threat_intel_api.json",
    }
    path = Path(__file__).parent / template_map[tool_id]
    if not path.exists():
        print(f"  [SKIP] Template not found: {path}")
        return False

    with open(path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Replace server URL
    if "servers" in schema and len(schema["servers"]) > 0:
        schema["servers"][0]["url"] = mock_url
        schema["servers"][0]["description"] = f"Mock Server ({mock_url})"

    # Add API key header for tools that need auth
    if tool_id in (12, 13):
        if "components" not in schema:
            schema["components"] = {}
        if "securitySchemes" not in schema["components"]:
            schema["components"]["securitySchemes"] = {}
        schema["components"]["securitySchemes"]["apiKeyAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": "x-apikey"
        }
        # Add to each operation
        for path_val in schema.get("paths", {}).values():
            for method_val in path_val.values():
                if isinstance(method_val, dict):
                    if "security" not in method_val:
                        method_val["security"] = [{"apiKeyAuth": []}]

    # Custom headers with API key (format: {"key": ..., "value": ...})
    if tool_id in (12, 13):
        custom_headers = json.dumps([{"key": "x-apikey", "value": api_key}])
    else:
        custom_headers = json.dumps([])

    # Update database
    cur.execute(
        """
        UPDATE tool
        SET openapi_schema = %s,
            custom_headers = %s::jsonb,
            description = %s
        WHERE id = %s
        """,
        (json.dumps(schema), custom_headers, f"[MOCK] {schema['info']['description']}", tool_id)
    )

    return cur.rowcount > 0


def main():
    parser = argparse.ArgumentParser(description="Configure mock server for security tools")
    parser.add_argument("--port", type=int, default=9999, help="Mock server port")
    parser.add_argument("--reset", action="store_true", help="Reset to original placeholder URLs")
    args = parser.parse_args()

    mock_url = f"http://localhost:{args.port}"

    # Get password
    try:
        pwd = get_db_connection()
    except RuntimeError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    conn = psycopg2.connect(
        host="localhost", port=5432, database="postgres",
        user="postgres", password=pwd
    )
    cur = conn.cursor()

    if args.reset:
        print("[RESET] Reverting tool URLs to placeholders...")
        placeholders = {
            11: ("{WEBHOOK_URL}", "[ACTIVE] Send security alerts to Slack, Teams, or PagerDuty"),
            12: ("{API_BASE_URL}", "[ACTIVE] Create security incident tickets in Jira, Linear, or ServiceNow"),
            13: ("{API_BASE_URL}", "[ACTIVE] Query threat intelligence databases for IPs, domains, hashes"),
        }
        for tool_id, (url, desc) in placeholders.items():
            schema = {
                "openapi": "3.0.3",
                "info": {"title": "placeholder", "version": "1.0.0"},
                "servers": [{"url": url}],
                "paths": {}
            }
            cur.execute(
                "UPDATE tool SET openapi_schema = %s, description = %s WHERE id = %s",
                (json.dumps(schema), desc, tool_id)
            )
            print(f"  Tool {tool_id}: reset to placeholder")
        conn.commit()
        print("[OK] Tools reset to placeholder URLs")
        cur.close()
        conn.close()
        return

    print(f"[CONFIG] Updating tools to use mock server: {mock_url}\n")

    tools = {
        11: ("send_security_alert", "Security Alert Webhook"),
        12: ("create_security_ticket", "Security Ticket API"),
        13: ("threat_intel_lookup", "Threat Intel Lookup"),
    }

    for tool_id, (name, desc) in tools.items():
        print(f"  Configuring tool {tool_id}: {name}...")
        try:
            updated = update_tool_schema(cur, tool_id, mock_url, API_KEY)
            if updated:
                conn.commit()
                print(f"    [OK] Updated: {mock_url}")
            else:
                print(f"    [SKIP] No changes")
        except Exception as e:
            print(f"    [ERROR] {e}")
            conn.rollback()

    # Verify
    print("\n[VERIFY] Current tool configurations:\n")
    cur.execute(
        "SELECT id, name, openapi_schema->'servers'->0->>'url' as url, custom_headers FROM tool WHERE id >= 11 ORDER BY id"
    )
    for row in cur.fetchall():
        tid, name, url, headers = row
        print(f"  [{tid}] {name}")
        print(f"       URL: {url}")
        print(f"       Headers: {headers}")
        print()

    cur.close()
    conn.close()
    print(f"[OK] Done. Start mock server with:")
    print(f"  python mock_tools_server.py --port {args.port} --verbose")
    print(f"\nThen test with:")
    print(f"  curl http://localhost:{args.port}/health")
    alert_body = '{"alert_type":"PHISHING","severity":"P1","title":"Test"}'
    print(f"  curl -X POST http://localhost:{args.port}/ -H 'Content-Type: application/json' -d '{alert_body}'")


if __name__ == "__main__":
    main()
