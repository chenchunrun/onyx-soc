#!/usr/bin/env python3
"""
Minimal acceptance verification for the Onyx security platform customization.

Examples:
    python verify_security_platform_acceptance.py
    python verify_security_platform_acceptance.py --json
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

import psycopg2
import requests


SECURITY_DOCUMENT_SET_NAME = "安全知识库"

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


def fetch_db_state(db_password: str | None = None) -> dict[str, Any]:
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
    db_state: dict[str, Any],
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
            "openapi_tools_found": sorted(openapi_tool_names & EXPECTED_OPENAPI_TOOLS),
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
    print(
        "OpenAPI tools: "
        + ", ".join(result["summary"]["openapi_tools_found"])
        if result["summary"]["openapi_tools_found"]
        else "OpenAPI tools: MISSING"
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
    result = evaluate_acceptance(
        document_sets=list_document_sets(args.url, cookie),
        personas=personas,
        openapi_tools=list_openapi_tools(args.url, cookie),
        db_state=fetch_db_state(db_password=args.db_password),
    )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print_human_result(result)

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
