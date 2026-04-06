#!/usr/bin/env python3
"""
Onyx Security Knowledge Base Upload Script

Uploads all markdown files from the knowledge-base directory to Onyx
via the /onyx-api/ingestion endpoint.

Usage:
    python upload_to_onyx.py [--dry-run] [--verify] [--email EMAIL] [--password PASSWORD]
"""

import os
import sys
import argparse
from pathlib import Path

venv_path = Path(__file__).parent.parent / ".venv"
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "lib" / "python3.12" / "site-packages"))

import requests


def login(base_url: str, email: str, password: str) -> str | None:
    """Login and return the auth cookie value."""
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
        elif resp.status_code == 422:
            # Try email field
            resp = requests.post(
                f"{base_url}/auth/login",
                data={"email": email, "password": password},
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
        print(f"[ERROR] Login failed: {e}")
        return None


def upload_document(base_url: str, cookie: str, file_path: Path, dry_run: bool = False) -> dict:
    """Upload a single document."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Extract title from first heading or filename
    title = file_path.stem
    for line in content.split("\n"):
        if line.startswith("# "):
            title = line[2:].strip()
            break

    # Category from parent directory name
    category = file_path.parent.name

    doc = {
        "document": {
            "sections": [{"text": content, "link": ""}],
            "semantic_identifier": title,
            "metadata": {
                "category": category,
                "source": "security-knowledge-base",
                "file_path": str(file_path.relative_to(Path(__file__).parent))
            },
            "doc_updated_at": "2026-01-01T00:00:00Z",
            "primary_owners": [],
            "secondary_owners": [],
            "title": title
        }
    }

    if dry_run:
        print(f"  [DRY RUN] {title} ({len(content)} chars)")
        return {"status": "dry_run"}

    try:
        resp = requests.post(
            f"{base_url}/onyx-api/ingestion",
            json=doc,
            cookies={"fastapiusersauth": cookie},
            timeout=60
        )
        if resp.status_code == 200:
            result = resp.json()
            action = "updated" if result.get("already_existed") else "uploaded"
            print(f"  [OK] {title} - {action}")
            return result
        else:
            print(f"  [ERROR {resp.status_code}] {title}: {resp.text[:200]}")
            return {"status": "error", "code": resp.status_code, "msg": resp.text[:200]}
    except Exception as e:
        print(f"  [ERROR] {title}: {e}")
        return {"status": "error", "msg": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Upload security knowledge base to Onyx")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be uploaded")
    parser.add_argument("--verify", action="store_true", help="Verify existing uploads")
    parser.add_argument("--email", default=os.environ.get("ONYX_EMAIL", "security-admin@onyx.local"))
    parser.add_argument("--password", default=os.environ.get("ONYX_PASSWORD", "admin123"))
    parser.add_argument("--url", default=os.environ.get("ONYX_URL", "http://localhost:8080"))
    args = parser.parse_args()

    kb_dir = Path(__file__).parent

    # Find all markdown files
    md_files = []
    for root, dirs, files in os.walk(kb_dir):
        dirs[:] = [d for d in dirs if d not in [".venv", "__pycache__", ".git"]]
        for f in files:
            if f.endswith(".md") and not f.startswith("upload"):
                md_files.append(Path(root) / f)

    if not md_files:
        print("No markdown files found.")
        return

    print(f"Found {len(md_files)} markdown files.")
    print(f"Target: {args.url}")

    # Login
    print(f"\nLogging in as {args.email}...")
    cookie = login(args.url, args.email, args.password)
    if not cookie:
        print("[ERROR] Login failed. Check credentials.")
        sys.exit(1)
    print("[OK] Logged in successfully.")

    if args.verify:
        # List existing documents
        resp = requests.get(
            f"{args.url}/onyx-api/ingestion",
            cookies={"fastapiusersauth": cookie}
        )
        if resp.status_code == 200:
            docs = resp.json()
            print(f"\nExisting ingestion documents: {len(docs)}")
            for doc in docs:
                print(f"  - {doc.get('semantic_id', 'N/A')}")
        else:
            print(f"[ERROR] Could not list documents: {resp.status_code}")
        return

    # Upload files
    print(f"\nUploading {'(dry run)' if args.dry_run else ''}:\n")
    results = []
    for md_file in sorted(md_files):
        rel_path = md_file.relative_to(kb_dir)
        print(f"  {rel_path}")
        result = upload_document(args.url, cookie, md_file, dry_run=args.dry_run)
        results.append(result)

    print()
    if args.dry_run:
        print(f"Dry run complete: would have processed {len(results)} files.")
    else:
        success = sum(1 for r in results if r.get("status") != "error")
        updated = sum(1 for r in results if r.get("status") != "error" and r.get("already_existed"))
        new = success - updated
        print(f"Done: {success}/{len(results)} successful ({new} new, {updated} updated).")


if __name__ == "__main__":
    main()
