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
import json
import os
from pathlib import Path
from typing import IO
from typing import Any

import requests


SECURITY_DOCUMENT_SET_NAME = "安全知识库"
SECURITY_DOCUMENT_SET_DESCRIPTION = "Onyx 智能安全底座使用的标准安全知识文档集。"
SECURITY_CONNECTOR_NAME = "安全知识文件源"
MAX_FILES_PER_UPLOAD = 1000
ROOT = Path(__file__).resolve().parent


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


def list_connector_statuses(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/manage/admin/connector/status",
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


def get_connector_status_by_name(
    base_url: str, cookie: str, connector_name: str
) -> dict[str, Any] | None:
    for connector_status in list_connector_statuses(base_url, cookie):
        if connector_status["name"] == connector_name:
            return connector_status
    return None


def collect_markdown_files() -> list[Path]:
    markdown_files: list[Path] = []
    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in {".venv", "__pycache__", ".git"}]
        for file_name in files:
            if file_name.endswith(".md") and not file_name.startswith("upload"):
                markdown_files.append(Path(root) / file_name)
    return sorted(markdown_files)


def chunk_markdown_files(markdown_files: list[Path]) -> list[list[Path]]:
    return [
        markdown_files[index : index + MAX_FILES_PER_UPLOAD]
        for index in range(0, len(markdown_files), MAX_FILES_PER_UPLOAD)
    ]


def upload_markdown_files(
    base_url: str, cookie: str, markdown_files: list[Path]
) -> dict[str, Any]:
    if len(markdown_files) > MAX_FILES_PER_UPLOAD:
        raise ValueError(
            f"Too many files for a single upload: {len(markdown_files)} > {MAX_FILES_PER_UPLOAD}"
        )

    files: list[tuple[str, tuple[str, IO[bytes], str]]] = []
    opened_files: list[IO[bytes]] = []
    try:
        for markdown_file in markdown_files:
            file_handle = markdown_file.open("rb")
            opened_files.append(file_handle)
            files.append(
                (
                    "files",
                    (markdown_file.name, file_handle, "text/markdown"),
                )
            )

        response = requests.post(
            f"{base_url}/manage/admin/connector/file/upload",
            files=files,
            cookies={"fastapiusersauth": cookie},
            timeout=120,
        )
        response.raise_for_status()
        return response.json()
    finally:
        for file_handle in opened_files:
            file_handle.close()


def create_security_connector(
    base_url: str,
    cookie: str,
    upload_payload: dict[str, Any],
) -> int:
    payload = {
        "name": SECURITY_CONNECTOR_NAME,
        "source": "file",
        "input_type": "load_state",
        "connector_specific_config": {
            "file_locations": upload_payload["file_paths"],
            "file_names": upload_payload["file_names"],
            "zip_metadata_file_id": upload_payload.get("zip_metadata_file_id"),
        },
        "refresh_freq": None,
        "prune_freq": None,
        "indexing_start": None,
        "access_type": "public",
        "groups": [],
    }
    response = requests.post(
        f"{base_url}/manage/admin/connector-with-mock-credential",
        json=payload,
        cookies={"fastapiusersauth": cookie},
        timeout=120,
    )
    response.raise_for_status()
    response_json = response.json()
    cc_pair_id = response_json.get("data")
    if not isinstance(cc_pair_id, int):
        raise RuntimeError(
            f"Expected cc_pair_id in connector creation response, got: {response_json}"
        )
    return cc_pair_id


def list_connector_files(
    base_url: str, cookie: str, connector_id: int
) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/manage/admin/connector/{connector_id}/files",
        cookies={"fastapiusersauth": cookie},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["files"]


def replace_connector_files(
    base_url: str,
    cookie: str,
    connector_id: int,
    markdown_files: list[Path],
    file_ids_to_remove: list[str],
) -> None:
    files: list[tuple[str, tuple[str, IO[bytes], str]]] = []
    opened_files: list[IO[bytes]] = []
    try:
        for markdown_file in markdown_files:
            file_handle = markdown_file.open("rb")
            opened_files.append(file_handle)
            files.append(
                (
                    "files",
                    (markdown_file.name, file_handle, "text/markdown"),
                )
            )

        response = requests.post(
            f"{base_url}/manage/admin/connector/{connector_id}/files/update",
            data={"file_ids_to_remove": json.dumps(file_ids_to_remove)},
            files=files,
            cookies={"fastapiusersauth": cookie},
            timeout=180,
        )
        response.raise_for_status()
    finally:
        for file_handle in opened_files:
            file_handle.close()


def update_document_set_bindings(
    base_url: str,
    cookie: str,
    document_set: dict[str, Any],
    cc_pair_id: int,
) -> None:
    payload = {
        "id": document_set["id"],
        "description": document_set.get("description") or SECURITY_DOCUMENT_SET_DESCRIPTION,
        "cc_pair_ids": [cc_pair_id],
        "is_public": document_set.get("is_public", True),
        "users": document_set.get("users", []),
        "groups": document_set.get("groups", []),
        "federated_connectors": [
            {
                "federated_connector_id": connector["id"],
                "entities": connector.get("entities", {}),
            }
            for connector in document_set.get("federated_connector_summaries", [])
        ],
    }
    response = requests.patch(
        f"{base_url}/manage/admin/document-set",
        json=payload,
        cookies={"fastapiusersauth": cookie},
        timeout=60,
    )
    response.raise_for_status()


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
    if not existing.get("cc_pair_summaries"):
        print(f"{SECURITY_DOCUMENT_SET_NAME}: INVALID (no connector bindings)")
        return 1

    cc_pair_names = [summary["name"] for summary in existing["cc_pair_summaries"]]
    if "DefaultCCPair" in cc_pair_names:
        print(f"{SECURITY_DOCUMENT_SET_NAME}: INVALID (bound to DefaultCCPair)")
        return 1

    connector_status = get_connector_status_by_name(
        base_url, cookie, SECURITY_CONNECTOR_NAME
    )
    if connector_status is None:
        print(f"{SECURITY_DOCUMENT_SET_NAME}: INVALID (missing connector {SECURITY_CONNECTOR_NAME})")
        return 1

    print(
        f"{SECURITY_DOCUMENT_SET_NAME}: OK (id={existing['id']}, cc_pair={connector_status['cc_pair_id']})"
    )
    return 0


def ensure_document_set(base_url: str, cookie: str, dry_run: bool) -> int:
    existing = get_document_set_by_name(base_url, cookie, SECURITY_DOCUMENT_SET_NAME)
    connector_status = get_connector_status_by_name(
        base_url, cookie, SECURITY_CONNECTOR_NAME
    )
    markdown_files = collect_markdown_files()
    markdown_file_batches = chunk_markdown_files(markdown_files)

    if dry_run and existing is not None and connector_status is not None:
        current_cc_pair_ids = {
            summary["id"] for summary in existing.get("cc_pair_summaries", [])
        }
        if connector_status["cc_pair_id"] in current_cc_pair_ids:
            print(
                f"[DRY RUN] Document set already bound to {SECURITY_CONNECTOR_NAME}: "
                f"{SECURITY_DOCUMENT_SET_NAME} (id={existing['id']})"
            )
            return 0

    if dry_run:
        if existing is None:
            print(f"[DRY RUN] Would create document set: {SECURITY_DOCUMENT_SET_NAME}")
        if connector_status is None:
            print(
                f"[DRY RUN] Would create file connector: {SECURITY_CONNECTOR_NAME} "
                f"with {len(markdown_files)} markdown files in {len(markdown_file_batches)} batch(es)"
            )
        else:
            print(
                f"[DRY RUN] Would refresh file connector: {SECURITY_CONNECTOR_NAME} "
                f"with {len(markdown_files)} markdown files in {len(markdown_file_batches)} batch(es)"
            )
        if existing is not None:
            print(
                f"[DRY RUN] Would bind {SECURITY_DOCUMENT_SET_NAME} "
                f"to connector {SECURITY_CONNECTOR_NAME}"
            )
        return 0

    if existing is None:
        document_set_id = create_document_set(base_url, cookie)
        print(
            f"[OK] Created document set: {SECURITY_DOCUMENT_SET_NAME} (id={document_set_id})"
        )
        existing = get_document_set_by_name(base_url, cookie, SECURITY_DOCUMENT_SET_NAME)
        if existing is None:
            raise RuntimeError("Document set was created but could not be reloaded")

    if connector_status is None:
        upload_payload = upload_markdown_files(
            base_url, cookie, markdown_file_batches[0]
        )
        cc_pair_id = create_security_connector(base_url, cookie, upload_payload)
        connector_status = get_connector_status_by_name(
            base_url, cookie, SECURITY_CONNECTOR_NAME
        )
        if connector_status is None:
            raise RuntimeError("Security connector was created but could not be reloaded")
        connector_id = connector_status["connector"]["id"]
        for batch in markdown_file_batches[1:]:
            replace_connector_files(base_url, cookie, connector_id, batch, [])
        print(
            f"[OK] Created file connector: {SECURITY_CONNECTOR_NAME} "
            f"(cc_pair_id={cc_pair_id}, files={len(markdown_files)}, batches={len(markdown_file_batches)})"
        )
    else:
        connector_id = connector_status["connector"]["id"]
        existing_files = list_connector_files(base_url, cookie, connector_id)
        replace_connector_files(
            base_url,
            cookie,
            connector_id,
            markdown_file_batches[0],
            [file_info["file_id"] for file_info in existing_files],
        )
        for batch in markdown_file_batches[1:]:
            replace_connector_files(base_url, cookie, connector_id, batch, [])
        cc_pair_id = connector_status["cc_pair_id"]
        print(
            f"[OK] Refreshed file connector: {SECURITY_CONNECTOR_NAME} "
            f"(cc_pair_id={cc_pair_id}, files={len(markdown_files)}, batches={len(markdown_file_batches)})"
        )

    update_document_set_bindings(base_url, cookie, existing, cc_pair_id)
    print(
        f"[OK] Bound document set {SECURITY_DOCUMENT_SET_NAME} "
        f"to connector {SECURITY_CONNECTOR_NAME} (cc_pair_id={cc_pair_id})"
    )
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
