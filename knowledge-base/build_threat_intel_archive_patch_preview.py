#!/usr/bin/env python3
"""Build a no-op patch preview for threat-intel archive worklists."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from build_threat_intel_archive_worklist import default_worklist_path
from build_threat_intel_archive_worklist import load_json
from build_threat_intel_archive_worklist import load_policy
from assess_threat_intel_lifecycle import CURATION_POLICY_PATH

ROOT = MODULE_DIR
MANIFEST_PATH = ROOT / "threat-intelligence" / "feed_manifest.json"


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def default_report_path(batch_id: str, policy: dict[str, Any]) -> Path:
    configured_dir = (policy.get("output", {}) or {}).get("archive_patch_preview_dir")
    if configured_dir:
        base_dir = ROOT.parent / configured_dir
    else:
        base_dir = ROOT / "threat-intelligence" / "archive_patch_previews"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / f"{batch_id}.json"


def build_patch_preview(worklist: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    items = worklist.get("items", [])
    removal_paths = {str(item.get("path")) for item in items if item.get("path")}
    remaining_entries = [
        entry
        for entry in manifest.get("entries", [])
        if str(entry.get("path")) not in removal_paths
    ]

    removed_source_counts = Counter(str(item.get("source", "Unknown")) for item in items)
    removed_year_counts = Counter(str(item.get("year", "unknown")) for item in items)
    removed_size_bytes = sum(int(item.get("size_bytes", 0) or 0) for item in items)

    remaining_source_counts = Counter(
        str(entry.get("source", "Unknown")) for entry in remaining_entries
    )
    remaining_year_counts = Counter(
        str(entry.get("year", "unknown")) for entry in remaining_entries
    )

    commands = [
        f"python knowledge-base/build_threat_intel_archive_worklist.py --batch-id {worklist['batch_id']} --write-report",
        "git rm " + " ".join(sorted(removal_paths)[:20]) + (" ..." if len(removal_paths) > 20 else ""),
        "python knowledge-base/build_threat_intel_manifest.py --write",
        "python knowledge-base/setup_security_threat_intel.py --verify --local-only",
    ]

    return {
        "batch_id": worklist["batch_id"],
        "summary": {
            "removal_candidate_count": len(items),
            "removal_size_bytes": removed_size_bytes,
            "projected_governed_total": len(remaining_entries),
            "removed_source_counts": dict(sorted(removed_source_counts.items())),
            "removed_year_counts": dict(sorted(removed_year_counts.items())),
            "projected_source_counts": dict(sorted(remaining_source_counts.items())),
            "projected_year_counts": dict(sorted(remaining_year_counts.items())),
        },
        "paths_to_remove": sorted(removal_paths),
        "commands": commands,
    }


def write_report(report: dict[str, Any], path: Path) -> None:
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def print_summary(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(f"Batch: {report['batch_id']}")
    print(f"Removal candidates: {summary['removal_candidate_count']}")
    print(f"Projected governed total: {summary['projected_governed_total']}")
    print(
        "Removed sources: "
        + ", ".join(f"{name}={count}" for name, count in summary["removed_source_counts"].items())
    )
    print(
        "Projected sources: "
        + ", ".join(f"{name}={count}" for name, count in summary["projected_source_counts"].items())
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a no-op patch preview for archive worklists"
    )
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--show-summary", action="store_true")
    parser.add_argument("--report-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(CURATION_POLICY_PATH)
    worklist_path = default_worklist_path(args.batch_id, policy)
    worklist = load_json(worklist_path)
    manifest = load_manifest()
    report = build_patch_preview(worklist, manifest)
    if args.write_report:
        report_path = args.report_path or default_report_path(args.batch_id, policy)
        write_report(report, report_path)
        print(f"[OK] Wrote threat-intel archive patch preview: {report_path}")
    print_summary(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
