#!/usr/bin/env python3
"""
Security Team Provisioning Script for Onyx Security Knowledge Base

Creates security team users, configures persona access control, and sets up
document set permissions.

Usage:
    python provision_security_team.py --dry-run [--url URL] [--email EMAIL] [--password PASSWORD]
    python provision_security_team.py --apply [--url URL] [--email EMAIL] [--password PASSWORD]
    python provision_security_team.py --verify
    python provision_security_team.py --list-users
    python provision_security_team.py --reset-persona-visibility
"""

import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
import uuid

import psycopg2
import psycopg2.extras
import requests
from passlib.context import CryptContext

venv_path = Path(__file__).parent.parent / ".venv"
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "lib" / "python3.12" / "site-packages"))


# Password hashing
pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

# Security team configuration
SECURITY_TEAM = [
    {
        "name": "应急响应指挥官",
        "email": "commander@security.local",
        "role": "ADMIN",
        "description": "应急响应指挥官 - Full admin access for crisis management",
    },
    {
        "name": "安全事件分析师",
        "email": "analyst@security.local",
        "role": "BASIC",
        "description": "安全事件分析师 - Standard analyst access",
    },
    {
        "name": "漏洞评估专家",
        "email": "vuln_expert@security.local",
        "role": "BASIC",
        "description": "漏洞评估专家 - Vulnerability assessment access",
    },
    {
        "name": "合规审计员",
        "email": "auditor@security.local",
        "role": "BASIC",
        "description": "合规审计员 - Compliance audit access",
    },
]

# Default password for initial setup (MUST be changed after first login)
DEFAULT_PASSWORD = "SecurityTeam123!"

SECURITY_DOCUMENT_SET_NAME = "安全知识库"


def get_db_connection(password: str | None = None):
    """Get database connection to Onyx PostgreSQL."""
    if password is None:
        # Try common passwords used by Onyx docker-compose
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
                    host="localhost", port=5432, database="postgres",
                    user="postgres", password=pwd, connect_timeout=3
                )
                conn.close()  # Test connection
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


def hash_password(password: str) -> str:
    """Hash a password using Argon2."""
    return pwd_ctx.hash(password)


def get_persona_map(cur: "psycopg2.extensions.cursor") -> dict[str, int]:
    persona_names = [member["name"] for member in SECURITY_TEAM]
    cur.execute(
        "SELECT id, name FROM persona WHERE name = ANY(%s)",
        (persona_names,),
    )
    return {row[1]: row[0] for row in cur.fetchall()}


def get_security_persona_rows(
    cur: "psycopg2.extensions.cursor",
) -> list[tuple[int, str, bool, bool]]:
    persona_names = [member["name"] for member in SECURITY_TEAM]
    cur.execute(
        "SELECT id, name, is_public, is_listed FROM persona WHERE name = ANY(%s) ORDER BY id",
        (persona_names,),
    )
    return cur.fetchall()


def get_security_document_set_id(cur: "psycopg2.extensions.cursor") -> int | None:
    cur.execute(
        "SELECT id FROM document_set WHERE name = %s",
        (SECURITY_DOCUMENT_SET_NAME,),
    )
    row = cur.fetchone()
    return row[0] if row else None


def check_persona_visibility(cur: "psycopg2.extensions.cursor") -> dict:
    """Check current persona visibility settings."""
    rows = get_security_persona_rows(cur)
    return {row[0]: {"name": row[1], "is_public": row[2], "is_listed": row[3]}
            for row in rows}


def check_persona_user_links(cur: "psycopg2.extensions.cursor") -> dict:
    """Check existing persona__user links."""
    cur.execute(
        "SELECT persona_id, user_id FROM persona__user ORDER BY persona_id"
    )
    return {(row[0], str(row[1])) for row in cur.fetchall()}


def check_existing_users(cur: "psycopg2.extensions.cursor") -> dict:
    """Check existing security team users."""
    emails = [m["email"] for m in SECURITY_TEAM]
    cur.execute(
        "SELECT id, email, role FROM \"user\" WHERE email = ANY(%s)",
        (emails,)
    )
    return {row[1]: {"id": str(row[0]), "role": row[2]} for row in cur.fetchall()}


def check_document_set_links(cur: "psycopg2.extensions.cursor", user_ids: list[str]) -> set:
    """Check existing document_set__user links."""
    if not user_ids:
        return set()
    cur.execute(
        "SELECT document_set_id, user_id FROM document_set__user WHERE user_id::text = ANY(%s)",
        (user_ids,)
    )
    return {(row[0], str(row[1])) for row in cur.fetchall()}


def check_visible_assistants(cur: "psycopg2.extensions.cursor", user_ids: list[str]) -> dict:
    """Check visible_assistants for users."""
    if not user_ids:
        return {}
    cur.execute(
        "SELECT id, email, visible_assistants FROM \"user\" WHERE id::text = ANY(%s)",
        (user_ids,)
    )
    return {str(row[0]): {"email": row[1], "visible_assistants": row[2]}
            for row in cur.fetchall()}


def reset_persona_visibility(conn, make_public: bool = True) -> dict:
    """
    Reset persona visibility: set security personas to private (is_public=False)
    so only linked users can access them.
    """
    cur = conn.cursor()
    persona_ids = list(get_persona_map(cur).values())
    if not persona_ids:
        cur.close()
        return {"is_public": make_public, "persona__user_links_removed": False}
    if make_public:
        # Make all security personas public (default state)
        cur.execute(
            "UPDATE persona SET is_public = true WHERE id = ANY(%s)",
            (persona_ids,),
        )
        # Remove all persona__user links
        cur.execute("DELETE FROM persona__user WHERE persona_id = ANY(%s)", (persona_ids,))
        conn.commit()
        cur.close()
        return {"is_public": True, "persona__user_links_removed": True}

    # Make security personas private (restricted access)
    cur.execute(
        "UPDATE persona SET is_public = false WHERE id = ANY(%s)",
        (persona_ids,),
    )
    conn.commit()
    cur.close()
    return {"is_public": False}


def provision_security_team(conn, dry_run: bool = False) -> dict:
    """
    Provision security team users with proper roles and persona access.

    Steps:
    1. Reset persona visibility (is_public=False for security personas)
    2. Create security team users
    3. Link users to 安全知识库 document set
    4. Set visible_assistants to pre-select security personas
    5. Create Persona__User links for access control
    """
    results = {
        "persona_visibility": None,
        "users_created": [],
        "users_updated": [],
        "document_set_links": [],
        "persona_user_links": [],
        "visible_assistants_set": [],
        "errors": [],
    }

    cur = conn.cursor()
    persona_map = get_persona_map(cur)
    missing_personas = [
        member["name"] for member in SECURITY_TEAM if member["name"] not in persona_map
    ]
    document_set_id = get_security_document_set_id(cur)

    # Step 0: Verify persona existence
    if missing_personas:
        results["errors"].append(f"Missing personas: {missing_personas}")
        return results
    if document_set_id is None:
        results["errors"].append(f"Missing document set: {SECURITY_DOCUMENT_SET_NAME}")
        return results

    if dry_run:
        print("  [DRY RUN] Would set persona visibility: is_public=False for configured security personas")
        results["persona_visibility"] = {"is_public": False, "dry_run": True}

        for member in SECURITY_TEAM:
            email = member["email"]
            persona_id = persona_map[member["name"]]
            cur.execute('SELECT id FROM "user" WHERE email = %s', (email,))
            row = cur.fetchone()
            if row:
                print(f"  [DRY RUN] Would update user {email} -> role={member['role']}, "
                      f"visible_assistants=[{persona_id}], "
                      f"chosen_assistants=[{persona_id}]")
                results["users_updated"].append(email)
            else:
                print(f"  [DRY RUN] Would create user {email} -> role={member['role']}")
                results["users_created"].append(email)

        print(f"  [DRY RUN] Would link all users to document_set_id={document_set_id}")
        print(f"  [DRY RUN] Would create persona__user links for all users")
        return results

    # Step 1: Reset persona visibility (private)
    cur.execute(
        "UPDATE persona SET is_public = false WHERE id = ANY(%s)",
        (list(persona_map.values()),),
    )
    results["persona_visibility"] = {"is_public": False}

    # Step 2: Create/update security team users
    for member in SECURITY_TEAM:
        email = member["email"]
        role = member["role"]
        persona_id = persona_map[member["name"]]
        hashed_pw = hash_password(DEFAULT_PASSWORD)

        cur.execute('SELECT id, role FROM "user" WHERE email = %s', (email,))
        row = cur.fetchone()

        now = datetime.now(timezone.utc)

        if row:
            # Update existing user
            user_id = str(row[0])
            current_role = row[1]
            if current_role != role:
                cur.execute(
                    'UPDATE "user" SET role = %s WHERE id = %s',
                    (role, user_id)
                )
                print(f"  [OK] Updated role for {email}: {current_role} -> {role}")
            results["users_updated"].append(email)

            # Update visible_assistants and chosen_assistants
            visible = [persona_id]
            chosen = [persona_id]

            cur.execute(
                'UPDATE "user" SET visible_assistants = %s, '
                'chosen_assistants = %s, updated_at = %s '
                'WHERE id = %s',
                (psycopg2.extras.Json(visible),
                 psycopg2.extras.Json(chosen),
                 now, user_id)
            )
            results["visible_assistants_set"].append(email)
        else:
            # Create new user
            user_id = str(uuid.uuid4())
            try:
                cur.execute(
                    'INSERT INTO "user" (id, email, hashed_password, is_active, '
                    'is_superuser, is_verified, role, visible_assistants, '
                    'hidden_assistants, chosen_assistants, shortcut_enabled, '
                    'default_app_mode, use_memories, created_at, updated_at) '
                    'VALUES (%s, %s, %s, true, false, true, %s, %s, %s, %s, '
                    'false, %s, true, %s, %s)',
                    (
                        user_id, email, hashed_pw, role,
                        psycopg2.extras.Json([persona_id]),  # visible_assistants
                        psycopg2.extras.Json([]),             # hidden_assistants
                        psycopg2.extras.Json([persona_id]),  # chosen_assistants
                        "CHAT",
                        now, now
                    )
                )
                print(f"  [OK] Created user: {email} (role={role}, persona_id={persona_id})")
                results["users_created"].append(email)
            except Exception as e:
                results["errors"].append(f"Failed to create {email}: {e}")
                print(f"  [ERROR] Failed to create {email}: {e}")
                continue

        # Step 3: Link user to document set
        cur.execute(
            'SELECT 1 FROM document_set__user WHERE document_set_id = %s AND user_id = %s',
            (document_set_id, user_id)
        )
        if not cur.fetchone():
            try:
                cur.execute(
                    'INSERT INTO document_set__user (document_set_id, user_id) VALUES (%s, %s)',
                    (document_set_id, user_id)
                )
                print(f"  [OK] Linked {email} to document_set_id={document_set_id}")
                results["document_set_links"].append(email)
            except psycopg2.IntegrityError:
                results["document_set_links"].append(f"{email} (already linked)")

        # Step 4: Create Persona__User link for access control
        cur.execute(
            'SELECT 1 FROM persona__user WHERE persona_id = %s AND user_id = %s',
            (persona_id, user_id)
        )
        if not cur.fetchone():
            try:
                cur.execute(
                    'INSERT INTO persona__user (persona_id, user_id) VALUES (%s, %s)',
                    (persona_id, user_id)
                )
                print(f"  [OK] Created persona__user link: persona_id={persona_id} -> user_id={user_id}")
                results["persona_user_links"].append(email)
            except psycopg2.IntegrityError:
                pass

    conn.commit()
    cur.close()
    return results


def list_security_users(conn) -> None:
    """List all security team users and their configuration."""
    cur = conn.cursor()
    emails = [m["email"] for m in SECURITY_TEAM]

    cur.execute(
        'SELECT id, email, role, visible_assistants, chosen_assistants, is_active '
        'FROM "user" WHERE email = ANY(%s) ORDER BY email',
        (emails,)
    )
    rows = cur.fetchall()

    if not rows:
        print("No security team users found.")
        return

    print("\nSecurity Team Users:")
    print(f"{'Email':<35} {'Role':<8} {'Active':<7} {'Visible':<12} {'Chosen':<12}")
    print("-" * 80)
    for row in rows:
        visible = str(row[3]) if row[3] else "[]"
        chosen = str(row[4]) if row[4] else "[]"
        print(f"{row[1]:<35} {row[2]:<8} {str(row[5]):<7} {visible:<12} {chosen:<12}")

    # Check persona visibility
    print("\nPersona Visibility:")
    persona_rows = get_security_persona_rows(cur)
    print(f"{'ID':<5} {'Name':<20} {'Public':<8} {'Listed':<8}")
    print("-" * 45)
    for row in persona_rows:
        print(f"{row[0]:<5} {row[1]:<20} {str(row[2]):<8} {str(row[3]):<8}")

    # Check document set links
    document_set_id = get_security_document_set_id(cur)
    print(f"\nDocument Set Links ({SECURITY_DOCUMENT_SET_NAME}):")
    user_ids = [str(row[0]) for row in rows]
    if user_ids and document_set_id is not None:
        cur.execute(
            'SELECT u.email, ds.name FROM document_set__user dsu '
            'JOIN "user" u ON u.id = dsu.user_id '
            'JOIN document_set ds ON ds.id = dsu.document_set_id '
            'WHERE dsu.user_id::text = ANY(%s) ORDER BY u.email',
            (user_ids,)
        )
        for row in cur.fetchall():
            print(f"  - {row[0]} -> {row[1]}")

    # Check persona__user links
    print("\nPersona__User Links:")
    persona_ids = list(get_persona_map(cur).values())
    cur.execute(
        'SELECT p.name, u.email FROM persona__user pu '
        'JOIN persona p ON p.id = pu.persona_id '
        'JOIN "user" u ON u.id = pu.user_id '
        'WHERE pu.persona_id = ANY(%s) '
        'ORDER BY pu.persona_id',
        (persona_ids,),
    )
    rows = cur.fetchall()
    if rows:
        for row in rows:
            print(f"  - {row[0]} <- {row[1]}")
    else:
        print("  (none - personas are public to all users)")

    cur.close()


def verify(conn) -> dict:
    """Verify the security team configuration."""
    cur = conn.cursor()
    result = {
        "personas_public": [],
        "personas_private": [],
        "users_found": [],
        "users_missing": [],
        "doc_set_links": 0,
        "persona_user_links": 0,
    }

    # Check personas
    for row in get_security_persona_rows(cur):
        if row[2]:
            result["personas_public"].append({"id": row[0], "name": row[1]})
        else:
            result["personas_private"].append({"id": row[0], "name": row[1]})

    # Check users
    emails = [m["email"] for m in SECURITY_TEAM]
    cur.execute('SELECT email, role FROM "user" WHERE email = ANY(%s)', (emails,))
    found = {row[0]: row[1] for row in cur.fetchall()}
    for member in SECURITY_TEAM:
        if member["email"] in found:
            result["users_found"].append({
                "email": member["email"],
                "role": found[member["email"]],
                "persona_name": member["name"],
            })
        else:
            result["users_missing"].append(member["email"])

    # Check document set links
    document_set_id = get_security_document_set_id(cur)
    if document_set_id is not None:
        cur.execute("SELECT COUNT(*) FROM document_set__user WHERE document_set_id = %s", (document_set_id,))
        result["doc_set_links"] = cur.fetchone()[0]

    # Check persona__user links
    persona_ids = list(get_persona_map(cur).values())
    if persona_ids:
        cur.execute("SELECT COUNT(*) FROM persona__user WHERE persona_id = ANY(%s)", (persona_ids,))
        result["persona_user_links"] = cur.fetchone()[0]

    cur.close()
    return result


def verify_via_docker() -> dict:
    persona_name_sql = ", ".join(f"'{_sql_quote(member['name'])}'" for member in SECURITY_TEAM)
    email_sql = ", ".join(f"'{_sql_quote(member['email'])}'" for member in SECURITY_TEAM)

    persona_rows = run_docker_psql_query(
        "SELECT id, name, is_public::text FROM persona "
        f"WHERE name IN ({persona_name_sql}) ORDER BY id;"
    )
    result = {
        "personas_public": [],
        "personas_private": [],
        "users_found": [],
        "users_missing": [],
        "doc_set_links": 0,
        "persona_user_links": 0,
    }
    persona_map: dict[str, int] = {}
    for row in persona_rows:
        persona_id = int(row[0])
        persona_name = row[1]
        persona_map[persona_name] = persona_id
        target = "personas_public" if row[2] == "t" else "personas_private"
        result[target].append({"id": persona_id, "name": persona_name})

    found_users = {
        row[0]: row[1]
        for row in run_docker_psql_query(
            'SELECT email, role FROM "user" '
            f"WHERE email IN ({email_sql});"
        )
    }
    for member in SECURITY_TEAM:
        if member["email"] in found_users:
            result["users_found"].append(
                {
                    "email": member["email"],
                    "role": found_users[member["email"]],
                    "persona_name": member["name"],
                }
            )
        else:
            result["users_missing"].append(member["email"])

    document_set_rows = run_docker_psql_query(
        "SELECT id FROM document_set "
        f"WHERE name = '{_sql_quote(SECURITY_DOCUMENT_SET_NAME)}' LIMIT 1;"
    )
    if document_set_rows:
        document_set_id = int(document_set_rows[0][0])
        count_rows = run_docker_psql_query(
            "SELECT COUNT(*) FROM document_set__user "
            f"WHERE document_set_id = {document_set_id};"
        )
        result["doc_set_links"] = int(count_rows[0][0]) if count_rows else 0

    if persona_map:
        persona_ids_sql = ", ".join(str(persona_id) for persona_id in persona_map.values())
        count_rows = run_docker_psql_query(
            "SELECT COUNT(*) FROM persona__user "
            f"WHERE persona_id IN ({persona_ids_sql});"
        )
        result["persona_user_links"] = int(count_rows[0][0]) if count_rows else 0

    return result


def precheck(conn) -> dict:
    """Check whether the environment is ready for RBAC provisioning."""
    cur = conn.cursor()
    result = {
        "document_set_exists": False,
        "document_set_name": None,
        "personas_found": [],
        "personas_missing": [],
        "security_users_found": [],
    }

    persona_map = get_persona_map(cur)
    for member in SECURITY_TEAM:
        persona_name = member["name"]
        if persona_name in persona_map:
            result["personas_found"].append(
                {"id": persona_map[persona_name], "name": persona_name}
            )
        else:
            result["personas_missing"].append(persona_name)

    document_set_id = get_security_document_set_id(cur)
    if document_set_id is not None:
        cur.execute(
            "SELECT name FROM document_set WHERE id = %s",
            (document_set_id,),
        )
        row = cur.fetchone()
        if row:
            result["document_set_exists"] = True
            result["document_set_name"] = row[0]

    emails = [member["email"] for member in SECURITY_TEAM]
    cur.execute(
        'SELECT email FROM "user" WHERE email = ANY(%s) ORDER BY email',
        (emails,),
    )
    result["security_users_found"] = [row[0] for row in cur.fetchall()]

    cur.close()
    return result


def precheck_via_docker() -> dict:
    persona_name_sql = ", ".join(f"'{_sql_quote(member['name'])}'" for member in SECURITY_TEAM)
    email_sql = ", ".join(f"'{_sql_quote(member['email'])}'" for member in SECURITY_TEAM)
    result = {
        "document_set_exists": False,
        "document_set_name": None,
        "personas_found": [],
        "personas_missing": [],
        "security_users_found": [],
    }

    persona_rows = run_docker_psql_query(
        "SELECT id, name FROM persona "
        f"WHERE name IN ({persona_name_sql});"
    )
    persona_map = {row[1]: int(row[0]) for row in persona_rows}
    for member in SECURITY_TEAM:
        if member["name"] in persona_map:
            result["personas_found"].append(
                {"id": persona_map[member["name"]], "name": member["name"]}
            )
        else:
            result["personas_missing"].append(member["name"])

    document_set_rows = run_docker_psql_query(
        "SELECT name FROM document_set "
        f"WHERE name = '{_sql_quote(SECURITY_DOCUMENT_SET_NAME)}' LIMIT 1;"
    )
    if document_set_rows:
        result["document_set_exists"] = True
        result["document_set_name"] = document_set_rows[0][0]

    result["security_users_found"] = [
        row[0]
        for row in run_docker_psql_query(
            'SELECT email FROM "user" '
            f"WHERE email IN ({email_sql}) ORDER BY email;"
        )
    ]
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Provision security team users and configure RBAC in Onyx"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without making changes")
    parser.add_argument("--apply", action="store_true",
                        help="Apply changes (creates users, configures access)")
    parser.add_argument("--verify", action="store_true",
                        help="Verify current security team configuration")
    parser.add_argument("--precheck", action="store_true",
                        help="Check DB, personas, and document set readiness without applying changes")
    parser.add_argument("--list-users", action="store_true",
                        help="List security team users and their configuration")
    parser.add_argument("--reset-persona-visibility", action="store_true",
                        help="Reset persona visibility (use --make-public to reverse)")
    parser.add_argument("--make-public", action="store_true",
                        help="Make personas public instead of private (use with --reset-persona-visibility)")
    parser.add_argument("--db-password", default=None,
                        help="PostgreSQL password (auto-detected if not provided)")
    args = parser.parse_args()

    # Try to connect
    try:
        conn = get_db_connection(password=args.db_password)
    except Exception as e:
        conn = None
        if args.verify:
            print("[WARN] Falling back to docker-based DB verification...")
            result = verify_via_docker()
            print(f"\nPersonas set to PUBLIC (visible to all users): {len(result['personas_public'])}")
            for p in result["personas_public"]:
                print(f"  - [{p['id']}] {p['name']}")
            print(f"\nPersonas set to PRIVATE (access controlled): {len(result['personas_private'])}")
            for p in result["personas_private"]:
                print(f"  - [{p['id']}] {p['name']}")
            print(f"\nSecurity team users: {len(result['users_found'])}/{len(SECURITY_TEAM)} found")
            for u in result["users_found"]:
                print(f"  - {u['email']} (role={u['role']}, persona={u['persona_name']})")
            if result["users_missing"]:
                print(f"\nMissing users:")
                for email in result["users_missing"]:
                    print(f"  - {email}")
            print(f"\nDocument set links ({SECURITY_DOCUMENT_SET_NAME}): {result['doc_set_links']}")
            print(f"Persona__user links: {result['persona_user_links']}")
            if result["personas_public"] and not result["personas_private"]:
                print("\n[NOTE] All security personas are PUBLIC. "
                      "Run with --reset-persona-visibility to restrict access.")
            elif result["personas_private"]:
                print("\n[OK] Security personas are PRIVATE and access-controlled.")
            return
        if args.precheck:
            print("[WARN] Falling back to docker-based DB precheck...")
            result = precheck_via_docker()
            print(f"\nDocument set ({SECURITY_DOCUMENT_SET_NAME}): ", end="")
            if result["document_set_exists"]:
                print(f"FOUND ({result['document_set_name']})")
            else:
                print("MISSING")

            print(f"\nPersonas found: {len(result['personas_found'])}/4")
            for persona in result["personas_found"]:
                print(f"  - [{persona['id']}] {persona['name']}")
            if result["personas_missing"]:
                print("Missing personas:")
                for persona_name in result["personas_missing"]:
                    print(f"  - {persona_name}")

            print(f"\nExisting security users: {len(result['security_users_found'])}/{len(SECURITY_TEAM)}")
            for email in result["security_users_found"]:
                print(f"  - {email}")

            if result["document_set_exists"] and not result["personas_missing"]:
                print("\n[OK] Environment is ready for security team provisioning.")
            else:
                print("\n[WARN] Environment is not fully ready for security team provisioning.")
            return
        print(f"[ERROR] Cannot connect to database: {e}")
        print("Make sure the Onyx PostgreSQL container is running:")
        print("  docker ps | grep onyx-relational_db")
        sys.exit(1)

    if args.list_users:
        print("Listing security team users...")
        list_security_users(conn)
        conn.close()
        return

    if args.verify:
        print("Verifying security team configuration...")
        result = verify(conn)
        print(f"\nPersonas set to PUBLIC (visible to all users): {len(result['personas_public'])}")
        for p in result["personas_public"]:
            print(f"  - [{p['id']}] {p['name']}")
        print(f"\nPersonas set to PRIVATE (access controlled): {len(result['personas_private'])}")
        for p in result["personas_private"]:
            print(f"  - [{p['id']}] {p['name']}")
        print(f"\nSecurity team users: {len(result['users_found'])}/{len(SECURITY_TEAM)} found")
        for u in result["users_found"]:
            print(f"  - {u['email']} (role={u['role']}, persona={u['persona_name']})")
        if result["users_missing"]:
            print(f"\nMissing users:")
            for email in result["users_missing"]:
                print(f"  - {email}")
        print(f"\nDocument set links ({SECURITY_DOCUMENT_SET_NAME}): {result['doc_set_links']}")
        print(f"Persona__user links: {result['persona_user_links']}")

        if result["personas_public"] and not result["personas_private"]:
            print("\n[NOTE] All security personas are PUBLIC. "
                  "Run with --reset-persona-visibility to restrict access.")
        elif result["personas_private"]:
            print("\n[OK] Security personas are PRIVATE and access-controlled.")

        conn.close()
        return

    if args.precheck:
        print("Running RBAC precheck...")
        result = precheck(conn)
        print(f"\nDocument set ({SECURITY_DOCUMENT_SET_NAME}): ", end="")
        if result["document_set_exists"]:
            print(f"FOUND ({result['document_set_name']})")
        else:
            print("MISSING")

        print(f"\nPersonas found: {len(result['personas_found'])}/4")
        for persona in result["personas_found"]:
            print(f"  - [{persona['id']}] {persona['name']}")
        if result["personas_missing"]:
            print("Missing personas:")
            for persona_name in result["personas_missing"]:
                print(f"  - {persona_name}")

        print(f"\nExisting security users: {len(result['security_users_found'])}/{len(SECURITY_TEAM)}")
        for email in result["security_users_found"]:
            print(f"  - {email}")

        if result["document_set_exists"] and not result["personas_missing"]:
            print("\n[OK] Environment is ready for security team provisioning.")
        else:
            print("\n[WARN] Environment is not fully ready for security team provisioning.")
        conn.close()
        return

    if args.reset_persona_visibility:
        print(f"Resetting persona visibility (make_public={args.make_public})...")
        result = reset_persona_visibility(conn, make_public=args.make_public)
        if args.make_public:
            print("[OK] Security personas are now PUBLIC (visible to all users)")
        else:
            print("[OK] Security personas are now PRIVATE (only linked users can access)")
        print("\nTo provision users, run: python provision_security_team.py --apply")
        conn.close()
        return

    if args.dry_run:
        print("Dry run - showing what would be done:\n")
        print("This script will:")
        print("  1. Set is_public=False for the configured security personas")
        print("  2. Create 4 security team users:")
        for m in SECURITY_TEAM:
            print(f"     - {m['email']} ({m['role']}) -> persona={m['name']}")
        print(f"  3. Link all users to document set '{SECURITY_DOCUMENT_SET_NAME}'")
        print("  4. Set visible_assistants and chosen_assistants for each user")
        print("  5. Create Persona__User links for access control")
        print()

        result = provision_security_team(conn, dry_run=True)
        print(f"\nWould have: {len(result['users_created'])} created, "
              f"{len(result['users_updated'])} updated")
        conn.close()
        return

    if args.apply:
        print("Provisioning security team...\n")
        result = provision_security_team(conn, dry_run=False)
        print()
        if result["errors"]:
            print(f"Errors: {len(result['errors'])}")
            for err in result["errors"]:
                print(f"  - {err}")
        else:
            print("[OK] Provisioning complete!")
            print(f"  Users created: {len(result['users_created'])}")
            print(f"  Users updated: {len(result['users_updated'])}")
            print(f"  Doc set links: {len(result['document_set_links'])}")
            print(f"  Persona links: {len(result['persona_user_links'])}")
            print(f"\n  Default password for all users: {DEFAULT_PASSWORD}")
            print("  [IMPORTANT] Change passwords after first login!")
        conn.close()
        return

    # Default: show help
    parser.print_help()
    print("\nExamples:")
    print("  python provision_security_team.py --dry-run")
    print("  python provision_security_team.py --apply")
    print("  python provision_security_team.py --verify")
    print("  python provision_security_team.py --list-users")
    print("  python provision_security_team.py --reset-persona-visibility")


if __name__ == "__main__":
    main()
