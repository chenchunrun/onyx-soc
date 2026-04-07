#!/usr/bin/env python3
"""Threat intelligence setup for the Onyx security platform.

This script turns the checked-in threat-intel feed corpus into a managed bootstrap
stage for the security platform. It can optionally refresh the local feed corpus
from upstream sources before uploading to Onyx.

Examples:
    python setup_security_threat_intel.py --dry-run
    python setup_security_threat_intel.py --apply --limit 20
    python setup_security_threat_intel.py --apply --refresh --feed cisa_kev
    python setup_security_threat_intel.py --verify
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any

import requests
import yaml

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from build_threat_intel_manifest import DEFAULT_MANIFEST_PATH
from build_threat_intel_manifest import compare_manifests
from build_threat_intel_manifest import load_manifest
from build_threat_intel_manifest import manifest_summary_lines
from build_threat_intel_manifest import unmanaged_local_feed_paths
from build_threat_intel_manifest import write_manifest
from build_threat_intel_manifest import build_manifest as build_feed_manifest
from assess_threat_intel_lifecycle import build_lifecycle_report
from curate_threat_intel_corpus import build_unmanaged_report

ROOT = MODULE_DIR
THREAT_INTEL_DIR = ROOT / "威胁情报" / "feeds"
AGGREGATOR_PATH = ROOT / "threat-intelligence" / "threat_intel_aggregator.py"
SYNC_PLAN_PATH = ROOT / "threat-intelligence" / "sync_plan.yaml"
SYNC_STATE_PATH = ROOT / "threat-intelligence" / "sync_state.json"
SOURCE_PROFILES_PATH = ROOT / "threat-intelligence" / "source_profiles.yaml"
MANIFEST_PATH = DEFAULT_MANIFEST_PATH
VENV_PYTHON = ROOT.parent / ".venv" / "bin" / "python"
THREAT_INTEL_SOURCE = "threat-intelligence"

DEFAULT_FEEDS = [
    "cisa_kev",
    "nvd_security_advisories",
    "nvd_ics_advisories",
    "nvd_medical_advisories",
]


def get_python_executable() -> str:
    if VENV_PYTHON.exists():
        return str(VENV_PYTHON)
    return sys.executable


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def load_source_profiles() -> dict[str, Any]:
    with open(SOURCE_PROFILES_PATH, "r", encoding="utf-8") as handle:
        profiles = yaml.safe_load(handle)
    if not isinstance(profiles, dict):
        raise ValueError(f"Invalid source profiles: {SOURCE_PROFILES_PATH}")
    defined_profiles = profiles.get("profiles")
    if not isinstance(defined_profiles, dict) or not defined_profiles:
        raise ValueError(f"Source profiles {SOURCE_PROFILES_PATH} must define profiles")
    return profiles


def get_source_profile(profile_name: str) -> dict[str, Any]:
    profiles = load_source_profiles()["profiles"]
    if profile_name not in profiles:
        supported = ", ".join(sorted(profiles))
        raise ValueError(f"Unsupported source profile: {profile_name}. Supported: {supported}")
    profile = profiles[profile_name]
    if not isinstance(profile, dict):
        raise ValueError(f"Invalid source profile config for {profile_name}")
    if "allow_upstream_refresh" not in profile:
        raise ValueError(f"Source profile {profile_name} missing allow_upstream_refresh")
    return profile


def load_sync_plan() -> dict[str, Any]:
    with open(SYNC_PLAN_PATH, "r", encoding="utf-8") as handle:
        plan = yaml.safe_load(handle)
    if not isinstance(plan, dict):
        raise ValueError(f"Invalid sync plan: {SYNC_PLAN_PATH}")
    feeds = plan.get("feeds")
    if not isinstance(feeds, list) or not feeds:
        raise ValueError(f"Sync plan {SYNC_PLAN_PATH} must define feeds")
    for feed_config in feeds:
        if not isinstance(feed_config, dict):
            raise ValueError(f"Invalid feed config in {SYNC_PLAN_PATH}")
        feed_name = str(feed_config.get("name", ""))
        if feed_name not in DEFAULT_FEEDS:
            raise ValueError(f"Unsupported feed in sync plan: {feed_name}")
        interval_hours = feed_config.get("min_refresh_interval_hours")
        if not isinstance(interval_hours, int) or interval_hours <= 0:
            raise ValueError(
                f"Feed {feed_name} must define positive min_refresh_interval_hours"
            )
    return plan


def load_sync_state() -> dict[str, Any]:
    if not SYNC_STATE_PATH.exists():
        return {"feeds": {}}
    with open(SYNC_STATE_PATH, "r", encoding="utf-8") as handle:
        state = json.load(handle)
    if not isinstance(state, dict):
        raise ValueError(f"Invalid sync state: {SYNC_STATE_PATH}")
    feeds = state.get("feeds")
    if not isinstance(feeds, dict):
        state["feeds"] = {}
    return state


def write_sync_state(state: dict[str, Any]) -> None:
    with open(SYNC_STATE_PATH, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")


def feed_is_due(
    feed_config: dict[str, Any],
    feed_state: dict[str, Any] | None,
    now: datetime,
) -> bool:
    if not feed_state:
        return True
    last_success_at = str(feed_state.get("last_success_at", "")).strip()
    if not last_success_at:
        return True
    try:
        last_success = datetime.fromisoformat(last_success_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    interval = timedelta(hours=int(feed_config["min_refresh_interval_hours"]))
    return now - last_success >= interval


def due_feeds(
    plan: dict[str, Any], state: dict[str, Any], now: datetime
) -> list[dict[str, Any]]:
    feed_state_map = state.get("feeds", {})
    due: list[dict[str, Any]] = []
    for feed_config in plan["feeds"]:
        feed_name = str(feed_config["name"])
        if feed_is_due(feed_config, feed_state_map.get(feed_name), now):
            due.append(feed_config)
    return due


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
        print(f"[WARN] Login failed: {exc}")
    return None


def list_ingestion_documents(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/onyx-api/ingestion",
        cookies={"fastapiusersauth": cookie},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def discover_feed_files(limit: int | None = None) -> list[Path]:
    files = sorted(THREAT_INTEL_DIR.glob("*.md"))
    if limit is not None:
        return files[:limit]
    return files


def verify_governed_feed_manifest(strict_local: bool = False) -> tuple[list[str], list[str]]:
    expected = load_manifest(MANIFEST_PATH)
    actual = build_feed_manifest(tracked_only=True)
    mismatches = compare_manifests(expected, actual)
    unmanaged_paths = unmanaged_local_feed_paths(expected)
    if strict_local and unmanaged_paths:
        preview = ", ".join(unmanaged_paths[:5])
        suffix = " ..." if len(unmanaged_paths) > 5 else ""
        mismatches.append(f"Unmanaged local threat-intel feeds detected: {preview}{suffix}")
    return mismatches, unmanaged_paths


def print_manifest_summary(strict_local: bool = False) -> tuple[list[str], list[str]]:
    manifest = load_manifest(MANIFEST_PATH)
    print(f"Threat-intel manifest: {MANIFEST_PATH}")
    for line in manifest_summary_lines(manifest):
        print(f"  {line}")
    mismatches, unmanaged_paths = verify_governed_feed_manifest(strict_local=strict_local)
    print(f"  Unmanaged local feeds: {len(unmanaged_paths)}")
    return mismatches, unmanaged_paths


def print_curation_summary(strict_promotion_candidates: bool = False) -> list[str]:
    report = build_unmanaged_report(MANIFEST_PATH)
    summary = report["summary"]
    print(
        "  Unmanaged feed curation: "
        f"promotion_candidates={summary['promotion_candidate_total']}, "
        f"manual_review={summary['manual_review_total']}, "
        f"keep_runtime_only={summary['keep_runtime_only_total']}"
    )
    mismatches: list[str] = []
    if strict_promotion_candidates and report["promotion_candidates"]:
        preview = ", ".join(item["cve_id"] for item in report["promotion_candidates"][:5])
        suffix = " ..." if len(report["promotion_candidates"]) > 5 else ""
        mismatches.append(f"Unpromoted threat-intel candidates remain: {preview}{suffix}")
    return mismatches


def print_lifecycle_summary(strict_archive_candidates: bool = False) -> list[str]:
    report = build_lifecycle_report(MANIFEST_PATH)
    summary = report["summary"]
    quality_counts = summary.get("quality_counts", {}) or {}
    quality_line = ", ".join(
        f"{name}={count}" for name, count in sorted(quality_counts.items())
    )
    print(
        "  Governed feed lifecycle: "
        f"active={summary['active_total']}, "
        f"archive_candidates={summary['archive_candidate_total']}, "
        f"retained_historical={summary['retained_historical_total']}, "
        f"quality=[{quality_line}]"
    )
    mismatches: list[str] = []
    if strict_archive_candidates and report["archive_candidates"]:
        preview = ", ".join(item["cve_id"] for item in report["archive_candidates"][:5])
        suffix = " ..." if len(report["archive_candidates"]) > 5 else ""
        mismatches.append(f"Threat-intel archive candidates remain: {preview}{suffix}")
    return mismatches



def semantic_identifier_for_feed_file(file_path: Path) -> str:
    stem = file_path.stem.replace("_", "-")
    if stem.endswith("-threat-intel"):
        return stem
    return f"{stem}_threat_intel"



def title_for_feed_file(file_path: Path) -> str:
    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception:
        return file_path.stem.replace("_", "-")

    for line in content.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return file_path.stem.replace("_", "-")



def build_ingestion_payload(file_path: Path) -> dict[str, Any]:
    content = file_path.read_text(encoding="utf-8")
    semantic_identifier = semantic_identifier_for_feed_file(file_path)
    title = title_for_feed_file(file_path)
    cve_id = file_path.stem.replace("_", "-") if file_path.stem.startswith("CVE_") else ""
    return {
        "document": {
            "sections": [{"text": content, "link": ""}],
            "semantic_identifier": semantic_identifier,
            "metadata": {
                "category": "threat-intel-feed",
                "source": THREAT_INTEL_SOURCE,
                "file_path": str(file_path.relative_to(ROOT)),
                "cve_id": cve_id,
            },
            "doc_updated_at": "2026-01-01T00:00:00Z",
            "primary_owners": [],
            "secondary_owners": [],
            "title": title,
        }
    }



def upload_feed_file(base_url: str, cookie: str, file_path: Path, dry_run: bool) -> dict[str, Any]:
    semantic_identifier = semantic_identifier_for_feed_file(file_path)
    if dry_run:
        print(f"  [DRY RUN] {semantic_identifier}")
        return {"status": "dry_run", "semantic_identifier": semantic_identifier}

    response = requests.post(
        f"{base_url}/onyx-api/ingestion",
        json=build_ingestion_payload(file_path),
        cookies={"fastapiusersauth": cookie},
        timeout=60,
    )
    response.raise_for_status()
    result = response.json()
    return {
        "status": "ok",
        "semantic_identifier": semantic_identifier,
        "already_existed": bool(result.get("already_existed")),
    }



def build_aggregator_command(args: argparse.Namespace) -> list[str]:
    command = [get_python_executable(), str(AGGREGATOR_PATH), "--skip-onyx"]
    for feed in selected_feeds(args):
        command.extend(["--fetch", "--feed", feed])
    return command



def selected_feeds(args: argparse.Namespace) -> list[str]:
    return args.feed if args.feed else DEFAULT_FEEDS


def selected_profile_name(args: argparse.Namespace) -> str:
    return str(
        getattr(args, "source_profile", None)
        or os.environ.get("THREAT_INTEL_SOURCE_PROFILE", "live")
    )


def selected_profile(args: argparse.Namespace) -> dict[str, Any]:
    return get_source_profile(selected_profile_name(args))


def refresh_local_feed_files(args: argparse.Namespace) -> int:
    profile_name = selected_profile_name(args)
    profile = selected_profile(args)
    if not profile["allow_upstream_refresh"]:
        print(
            f"[SKIP] Source profile '{profile_name}' disables upstream refresh. "
            "Using local feed corpus only."
        )
        return 0
    feeds = selected_feeds(args)
    print(f"Refreshing threat-intel feeds: {', '.join(feeds)}")
    for feed in feeds:
        command = [
            get_python_executable(),
            str(AGGREGATOR_PATH),
            "--fetch",
            "--feed",
            feed,
            "--skip-onyx",
        ]
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode != 0:
            return completed.returncode
    return 0


def refresh_due_feeds(
    args: argparse.Namespace, due_feed_configs: list[dict[str, Any]]
) -> tuple[int, list[str]]:
    refreshed: list[str] = []
    for feed_config in due_feed_configs:
        feed = str(feed_config["name"])
        command = [
            get_python_executable(),
            str(AGGREGATOR_PATH),
            "--fetch",
            "--feed",
            feed,
            "--skip-onyx",
        ]
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode != 0:
            return completed.returncode, refreshed
        refreshed.append(feed)
    return 0, refreshed


def update_sync_state_for_success(
    state: dict[str, Any], refreshed_feeds: list[str], now: datetime
) -> dict[str, Any]:
    feeds_state = state.setdefault("feeds", {})
    timestamp = now.isoformat().replace("+00:00", "Z")
    for feed in refreshed_feeds:
        feeds_state[feed] = {
            "last_success_at": timestamp,
        }
    state["last_sync_run_at"] = timestamp
    state["last_refreshed_feeds"] = refreshed_feeds
    return state


def show_sync_plan() -> int:
    plan = load_sync_plan()
    state = load_sync_state()
    now = utc_now()
    due = {config["name"] for config in due_feeds(plan, state, now)}
    profiles = load_source_profiles()["profiles"]
    print(f"Sync plan: {SYNC_PLAN_PATH}")
    print(f"Source profiles: {', '.join(sorted(profiles))}")
    for feed_config in plan["feeds"]:
        feed_name = str(feed_config["name"])
        interval = int(feed_config["min_refresh_interval_hours"])
        feed_state = state.get("feeds", {}).get(feed_name, {})
        last_success = feed_state.get("last_success_at", "never")
        status = "DUE" if feed_name in due else "WAIT"
        print(
            f"  - {feed_name}: every {interval}h, last_success_at={last_success}, status={status}"
        )
    return 0


def run_scheduled_sync(args: argparse.Namespace) -> int:
    plan = load_sync_plan()
    state = load_sync_state()
    now = utc_now()
    due_feed_configs = due_feeds(plan, state, now)
    due_feed_names = [str(config["name"]) for config in due_feed_configs]
    profile_name = selected_profile_name(args)
    profile = selected_profile(args)

    print(f"Sync plan: {SYNC_PLAN_PATH}")
    print(f"Sync state: {SYNC_STATE_PATH}")
    print(f"Source profile: {profile_name}")
    if not due_feed_names:
        print("[OK] No due threat-intel feeds")
        return 0

    print(f"Due feeds: {', '.join(due_feed_names)}")
    if profile["allow_upstream_refresh"]:
        result, refreshed_feeds = refresh_due_feeds(args, due_feed_configs)
        if result != 0:
            return result
    else:
        print("[SKIP] Upstream refresh disabled; scheduled sync will use local feed corpus.")
        refreshed_feeds = due_feed_names

    apply_result = apply_threat_intel(
        argparse.Namespace(
            refresh=False,
            feed=None,
            limit=args.limit,
            url=args.url,
            email=args.email,
            password=args.password,
            source_profile=profile_name,
        )
    )
    if apply_result != 0:
        return apply_result

    write_sync_state(update_sync_state_for_success(state, refreshed_feeds, now))
    print(f"[OK] Scheduled threat-intel sync complete: {', '.join(refreshed_feeds)}")
    return 0



def dry_run(args: argparse.Namespace) -> int:
    profile_name = selected_profile_name(args)
    profile = selected_profile(args)
    files = discover_feed_files(limit=args.limit)
    print(f"Threat-intel files discovered: {len(files)}")
    print(f"Directory: {THREAT_INTEL_DIR}")
    print(f"Feeds profile: {', '.join(selected_feeds(args))}")
    print(f"Source profile: {profile_name}")
    try:
        mismatches, _ = print_manifest_summary(
            strict_local=bool(getattr(args, "strict_local_corpus", False))
        )
    except FileNotFoundError:
        print(f"[WARN] Threat-intel manifest not found: {MANIFEST_PATH}")
        mismatches = []
    curation_mismatches = print_curation_summary(
        strict_promotion_candidates=bool(getattr(args, "strict_promotion_candidates", False))
    )
    lifecycle_mismatches = print_lifecycle_summary(
        strict_archive_candidates=bool(getattr(args, "strict_archive_candidates", False))
    )
    if mismatches:
        print("[WARN] Governed threat-intel manifest drift detected during dry-run.")
    if curation_mismatches:
        print("[WARN] Threat-intel curation gate would fail in current state.")
    if lifecycle_mismatches:
        print("[WARN] Threat-intel lifecycle gate would fail in current state.")
    if args.refresh:
        if profile["allow_upstream_refresh"]:
            print("Would refresh local threat-intel feeds before upload.")
            print("Aggregator commands:")
            for feed in selected_feeds(args):
                print(
                    "  " + " ".join(
                        [
                            get_python_executable(),
                            str(AGGREGATOR_PATH),
                            "--fetch",
                            "--feed",
                            feed,
                            "--skip-onyx",
                        ]
                    )
                )
        else:
            print("Upstream refresh is disabled by source profile; would use local feed corpus only.")
    if files:
        print("Sample uploads:")
        for file_path in files[:5]:
            print(f"  - {semantic_identifier_for_feed_file(file_path)}")
    return 0



def apply_threat_intel(args: argparse.Namespace) -> int:
    if args.refresh:
        refresh_result = refresh_local_feed_files(args)
        if refresh_result != 0:
            return refresh_result

    files = discover_feed_files(limit=args.limit)
    if not files:
        print(f"[ERROR] No threat-intel feed files found in {THREAT_INTEL_DIR}")
        return 1

    cookie = get_cookie(args.url, args.email, args.password)
    if not cookie:
        print("[ERROR] Login failed. Check credentials.")
        return 1

    print(f"Uploading {len(files)} threat-intel files to {args.url} ...")
    uploaded = 0
    updated = 0
    for file_path in files:
        try:
            result = upload_feed_file(args.url, cookie, file_path, dry_run=False)
        except Exception as exc:
            print(f"  [ERROR] {file_path.name}: {exc}")
            return 1
        if result["already_existed"]:
            updated += 1
        else:
            uploaded += 1

    print(f"[OK] Threat-intel sync complete: {uploaded} new, {updated} updated")
    return 0



def verify_threat_intel(args: argparse.Namespace) -> int:
    files = discover_feed_files(limit=args.limit)
    if not files:
        print(f"[ERROR] No threat-intel feed files found in {THREAT_INTEL_DIR}")
        return 1

    print(f"Local threat-intel feed files: {len(files)}")
    try:
        mismatches, _ = print_manifest_summary(
            strict_local=bool(getattr(args, "strict_local_corpus", False))
        )
    except FileNotFoundError:
        print(f"[ERROR] Threat-intel manifest not found: {MANIFEST_PATH}")
        return 1
    curation_mismatches = print_curation_summary(
        strict_promotion_candidates=bool(getattr(args, "strict_promotion_candidates", False))
    )
    lifecycle_mismatches = print_lifecycle_summary(
        strict_archive_candidates=bool(getattr(args, "strict_archive_candidates", False))
    )
    if mismatches:
        for mismatch in mismatches[:10]:
            print(f"[ERROR] {mismatch}")
        return 1
    if curation_mismatches:
        for mismatch in curation_mismatches[:10]:
            print(f"[ERROR] {mismatch}")
        return 1
    if lifecycle_mismatches:
        for mismatch in lifecycle_mismatches[:10]:
            print(f"[ERROR] {mismatch}")
        return 1

    if args.local_only:
        print("[OK] Local verification only")
        return 0

    cookie = get_cookie(args.url, args.email, args.password)
    if not cookie:
        print("[ERROR] Login failed. Check credentials.")
        return 1

    try:
        docs = list_ingestion_documents(args.url, cookie)
    except Exception as exc:
        print(f"[ERROR] Failed to list ingestion documents: {exc}")
        return 1

    expected_ids = {semantic_identifier_for_feed_file(path) for path in files}
    actual_ids = {
        str(doc.get("semantic_id") or doc.get("semantic_identifier") or "")
        for doc in docs
    }
    missing = sorted(expected_ids - actual_ids)
    print(f"Threat-intel ingestion docs found: {len(expected_ids) - len(missing)}/{len(expected_ids)}")
    if missing:
        preview = ", ".join(missing[:5])
        suffix = " ..." if len(missing) > 5 else ""
        print(f"[ERROR] Missing threat-intel docs: {preview}{suffix}")
        return 1

    print("[OK] Threat-intel verification passed")
    return 0



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Setup threat-intelligence content for the Onyx security platform"
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--dry-run", action="store_true")
    mode_group.add_argument("--apply", action="store_true")
    mode_group.add_argument("--verify", action="store_true")
    mode_group.add_argument("--run-scheduled-sync", action="store_true")
    mode_group.add_argument("--show-sync-plan", action="store_true")
    parser.add_argument("--refresh", action="store_true", help="Refresh local feed files before apply")
    parser.add_argument("--feed", action="append", choices=DEFAULT_FEEDS, help="Feed to refresh; can be repeated")
    parser.add_argument(
        "--source-profile",
        choices=["live", "mock"],
        default=os.environ.get("THREAT_INTEL_SOURCE_PROFILE", "live"),
        help="Threat-intel source profile. 'live' refreshes upstream sources, 'mock' uses local curated feed files only.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Limit number of local files to process or verify")
    parser.add_argument("--local-only", action="store_true", help="Verify only local feed files without Onyx checks")
    parser.add_argument(
        "--strict-local-corpus",
        action="store_true",
        help="Fail verification if local threat-intel feed files exist outside the governed manifest.",
    )
    parser.add_argument(
        "--strict-promotion-candidates",
        action="store_true",
        help="Fail verification if unmanaged feeds contain promotion candidates that should be curated into the governed package.",
    )
    parser.add_argument(
        "--strict-archive-candidates",
        action="store_true",
        help="Fail verification if governed feeds contain archive candidates that should be reviewed for archive/retirement.",
    )
    parser.add_argument(
        "--write-manifest",
        action="store_true",
        help="Refresh the governed feed manifest before executing the selected mode.",
    )
    parser.add_argument("--url", default=os.environ.get("ONYX_URL", "http://localhost:8080"))
    parser.add_argument("--email", default=os.environ.get("ONYX_EMAIL", "security-admin@onyx.local"))
    parser.add_argument("--password", default=os.environ.get("ONYX_PASSWORD", "admin123"))
    return parser.parse_args()



def main() -> int:
    args = parse_args()
    if args.write_manifest:
        write_manifest(build_feed_manifest(tracked_only=True), MANIFEST_PATH)
        print(f"[OK] Refreshed threat-intel manifest: {MANIFEST_PATH}")
    if args.show_sync_plan:
        return show_sync_plan()
    if args.run_scheduled_sync:
        return run_scheduled_sync(args)
    if args.dry_run:
        return dry_run(args)
    if args.verify:
        return verify_threat_intel(args)
    return apply_threat_intel(args)


if __name__ == "__main__":
    raise SystemExit(main())
