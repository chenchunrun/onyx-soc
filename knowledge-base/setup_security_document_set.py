#!/usr/bin/env python3
"""
Ensure the standard security document set exists.

Examples:
    python setup_security_document_set.py --dry-run
    python setup_security_document_set.py --apply
    python setup_security_document_set.py --verify
"""

from __future__ import annotations

import argparse
import os
from typing import Any

import requests


SECURITY_DOCUMENT_SET_NAME = "安全知识库"
SECURITY_DOCUMENT_SET_DESCRIPTION = "Onyx 智能安全底座使用的标准安全知识文档集。"


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


def get_document_set_by_name(
    base_url: str, cookie: str, document_set_name: str
) -> dict[str, Any] | None:
    for document_set in list_document_sets(base_url, cookie):
        if document_set["name"] == document_set_name:
            return document_set
    return None


def create_document_set(base_url: str, cookie: str) -> int:
    payload = {
        "name": SECURITY_DOCUMENT_SET_NAME,
        "description": SECURITY_DOCUMENT_SET_DESCRIPTION,
        "cc_pair_ids": [],
        "is_public": True,
        "users": [],
        "groups": [],
        "federated_connectors": [],
    }
    response = requests.post(
        f"{base_url}/manage/admin/document-set",
        json=payload,
        cookies={"fastapiusersauth": cookie},
        timeout=30,
    )
    response.raise_for_status()
    return int(response.json())


def verify_document_set(base_url: str, cookie: str) -> int:
    existing = get_document_set_by_name(base_url, cookie, SECURITY_DOCUMENT_SET_NAME)
    if existing is None:
        print(f"{SECURITY_DOCUMENT_SET_NAME}: MISSING")
        return 1
    print(f"{SECURITY_DOCUMENT_SET_NAME}: OK (id={existing['id']})")
    return 0


def ensure_document_set(base_url: str, cookie: str, dry_run: bool) -> int:
    existing = get_document_set_by_name(base_url, cookie, SECURITY_DOCUMENT_SET_NAME)
    if existing is not None:
        print(f"[SKIP] Document set already exists: {SECURITY_DOCUMENT_SET_NAME} (id={existing['id']})")
        return 0

    if dry_run:
        print(f"[DRY RUN] Would create document set: {SECURITY_DOCUMENT_SET_NAME}")
        return 0

    document_set_id = create_document_set(base_url, cookie)
    print(f"[OK] Created document set: {SECURITY_DOCUMENT_SET_NAME} (id={document_set_id})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify the standard security document set"
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--dry-run", action="store_true")
    mode_group.add_argument("--apply", action="store_true")
    mode_group.add_argument("--verify", action="store_true")
    parser.add_argument("--url", default=os.environ.get("ONYX_URL", "http://localhost:8080"))
    parser.add_argument(
        "--email",
        default=os.environ.get("ONYX_EMAIL", "security-admin@onyx.local"),
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("ONYX_PASSWORD", "admin123"),
    )
    args = parser.parse_args()

    print(f"Logging in as {args.email}...")
    cookie = get_cookie(args.url, args.email, args.password)
    if not cookie:
        print("[ERROR] Login failed. Check credentials.")
        return 1
    print("[OK] Logged in.\n")

    if args.verify:
        return verify_document_set(args.url, cookie)
    return ensure_document_set(args.url, cookie, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
