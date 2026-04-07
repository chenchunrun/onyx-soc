#!/usr/bin/env python3
"""Build and verify the governed threat-intel feed manifest.

This script treats Git-tracked threat-intel feed files as the formal content
package for the security platform. Local feed files that exist outside the
manifest are reported as unmanaged runtime assets.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
FEEDS_DIR = ROOT / "威胁情报" / "feeds"
DEFAULT_MANIFEST_PATH = ROOT / "threat-intelligence" / "feed_manifest.json"
CURATION_POLICY_PATH = ROOT / "threat-intelligence" / "curation_policy.yaml"
MANIFEST_VERSION = 1
SOURCE_PATTERN = re.compile(r"^\*Source:\s*(.+?)\*\s*$")
RETRIEVED_PATTERN = re.compile(r"^\*(Retrieved|Last Updated):\s*(.*?)\*\s*$")


def normalize_relative_path(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT)).replace("\\", "/")


def load_manifest_exclude_paths(path: Path = CURATION_POLICY_PATH) -> set[str]:
    if not path.exists():
        return set()

    policy = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(policy, dict):
        raise ValueError(f"Invalid curation policy: {path}")

    excluded_paths = policy.get("manifest_exclude_paths", [])
    if excluded_paths is None:
        return set()
    if not isinstance(excluded_paths, list):
        raise ValueError(f"Invalid manifest_exclude_paths in curation policy: {path}")

    normalized: set[str] = set()
    for raw_path in excluded_paths:
        value = str(raw_path).strip()
        if not value:
            continue
        normalized.add(value.replace("\\", "/"))
    return normalized


def git_tracked_feed_paths() -> list[Path]:
    command = [
        "git",
        "-c",
        "core.quotepath=false",
        "ls-files",
        "--",
        "knowledge-base/威胁情报/feeds/*.md",
    ]
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "git ls-files failed")

    excluded_paths = load_manifest_exclude_paths()
    paths = []
    for line in completed.stdout.splitlines():
        relative_path = line.strip().strip('"')
        if not relative_path:
            continue
        normalized = relative_path.replace("\\", "/")
        if normalized in excluded_paths:
            continue
        paths.append(REPO_ROOT / relative_path)
    return sorted(paths)


def discover_feed_files(tracked_only: bool = True) -> list[Path]:
    if tracked_only:
        return git_tracked_feed_paths()
    return sorted(FEEDS_DIR.glob("*.md"))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def extract_source(text: str) -> str:
    for line in text.splitlines():
        match = SOURCE_PATTERN.match(line.strip())
        if match:
            return match.group(1).strip()
    return "Unknown"


def extract_retrieved_at(text: str) -> str:
    for line in text.splitlines():
        match = RETRIEVED_PATTERN.match(line.strip())
        if match:
            return match.group(2).strip()
    return ""


def infer_cve_year(cve_id: str) -> str:
    if cve_id.startswith("CVE-") and len(cve_id) >= 13:
        return cve_id.split("-")[1]
    return "unknown"


def parse_feed_file(path: Path) -> dict[str, Any]:
    text = read_text(path)
    cve_id = path.stem.replace("_", "-")
    relative_path = normalize_relative_path(path)
    return {
        "path": relative_path,
        "cve_id": cve_id,
        "year": infer_cve_year(cve_id),
        "title": extract_title(text, cve_id),
        "source": extract_source(text),
        "retrieved_at": extract_retrieved_at(text),
        "sha256": sha256_text(text),
        "size_bytes": len(text.encode("utf-8")),
    }


def build_manifest(tracked_only: bool = True) -> dict[str, Any]:
    files = discover_feed_files(tracked_only=tracked_only)
    entries = [parse_feed_file(path) for path in files]

    source_counts = Counter(entry["source"] for entry in entries)
    year_counts = Counter(entry["year"] for entry in entries)
    retrieved_counts = Counter(entry["retrieved_at"] or "unknown" for entry in entries)

    return {
        "manifest_version": MANIFEST_VERSION,
        "managed_scope": "git_tracked" if tracked_only else "local_all",
        "feeds_dir": normalize_relative_path(FEEDS_DIR),
        "summary": {
            "total_feeds": len(entries),
            "total_size_bytes": sum(entry["size_bytes"] for entry in entries),
            "source_counts": dict(sorted(source_counts.items())),
            "year_counts": dict(sorted(year_counts.items())),
            "retrieved_counts": dict(sorted(retrieved_counts.items())),
        },
        "entries": sorted(entries, key=lambda entry: entry["path"]),
    }


def load_manifest(path: Path = DEFAULT_MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_manifest(manifest: dict[str, Any], path: Path = DEFAULT_MANIFEST_PATH) -> None:
    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def compare_manifests(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    mismatches: list[str] = []

    for key in ["manifest_version", "managed_scope", "feeds_dir"]:
        if expected.get(key) != actual.get(key):
            mismatches.append(
                f"Manifest field mismatch for {key}: expected={expected.get(key)!r} actual={actual.get(key)!r}"
            )

    if expected.get("summary") != actual.get("summary"):
        mismatches.append("Manifest summary does not match current governed feed corpus")

    expected_entries = {entry["path"]: entry for entry in expected.get("entries", [])}
    actual_entries = {entry["path"]: entry for entry in actual.get("entries", [])}

    missing_paths = sorted(set(expected_entries) - set(actual_entries))
    extra_paths = sorted(set(actual_entries) - set(expected_entries))
    if missing_paths:
        mismatches.append(
            "Manifest references missing governed feeds: " + ", ".join(missing_paths[:5])
        )
    if extra_paths:
        mismatches.append(
            "Governed feed corpus contains new files not present in manifest: "
            + ", ".join(extra_paths[:5])
        )

    for path, expected_entry in expected_entries.items():
        actual_entry = actual_entries.get(path)
        if actual_entry is None:
            continue
        for field in ["sha256", "size_bytes", "source", "retrieved_at", "title"]:
            if expected_entry.get(field) != actual_entry.get(field):
                mismatches.append(
                    f"Manifest entry mismatch for {path} field {field}: "
                    f"expected={expected_entry.get(field)!r} actual={actual_entry.get(field)!r}"
                )
                break

    return mismatches


def unmanaged_local_feed_paths(manifest: dict[str, Any]) -> list[str]:
    governed_paths = {entry["path"] for entry in manifest.get("entries", [])}
    local_paths = {normalize_relative_path(path) for path in discover_feed_files(tracked_only=False)}
    return sorted(local_paths - governed_paths)


def manifest_summary_lines(manifest: dict[str, Any]) -> list[str]:
    summary = manifest["summary"]
    source_counts = ", ".join(
        f"{source}={count}" for source, count in summary["source_counts"].items()
    )
    return [
        f"Managed scope: {manifest['managed_scope']}",
        f"Governed feeds: {summary['total_feeds']}",
        f"Total size: {summary['total_size_bytes']} bytes",
        f"Sources: {source_counts}",
    ]


def cmd_write(args: argparse.Namespace) -> int:
    manifest = build_manifest(tracked_only=not args.all_local)
    write_manifest(manifest, args.manifest_path)
    print(f"[OK] Wrote threat-intel manifest: {args.manifest_path}")
    for line in manifest_summary_lines(manifest):
        print(f"  {line}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    expected = load_manifest(args.manifest_path)
    actual = build_manifest(tracked_only=not args.all_local)
    mismatches = compare_manifests(expected, actual)
    if mismatches:
        print(f"[ERROR] Threat-intel manifest drift detected: {args.manifest_path}")
        for mismatch in mismatches[:10]:
            print(f"  - {mismatch}")
        return 1

    print(f"[OK] Threat-intel manifest is up to date: {args.manifest_path}")
    for line in manifest_summary_lines(expected):
        print(f"  {line}")
    unmanaged_paths = unmanaged_local_feed_paths(expected)
    print(f"  Unmanaged local feeds: {len(unmanaged_paths)}")
    if unmanaged_paths and args.strict_local:
        preview = ", ".join(unmanaged_paths[:5])
        suffix = " ..." if len(unmanaged_paths) > 5 else ""
        print(f"[ERROR] Unmanaged local threat-intel feeds detected: {preview}{suffix}")
        return 1
    return 0


def cmd_show_summary(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest_path)
    print(f"Threat-intel manifest: {args.manifest_path}")
    for line in manifest_summary_lines(manifest):
        print(f"  {line}")
    unmanaged_paths = unmanaged_local_feed_paths(manifest)
    print(f"  Unmanaged local feeds: {len(unmanaged_paths)}")
    if unmanaged_paths:
        preview = ", ".join(unmanaged_paths[:5])
        suffix = " ..." if len(unmanaged_paths) > 5 else ""
        print(f"  Preview: {preview}{suffix}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and verify threat-intel feed manifest")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--show-summary", action="store_true")
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="Path to feed_manifest.json",
    )
    parser.add_argument(
        "--all-local",
        action="store_true",
        help="Build or compare using all local feed files instead of Git-tracked files only",
    )
    parser.add_argument(
        "--strict-local",
        action="store_true",
        help="Fail verification if unmanaged local feed files are present",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.write:
        return cmd_write(args)
    if args.verify:
        return cmd_verify(args)
    return cmd_show_summary(args)


if __name__ == "__main__":
    raise SystemExit(main())
