#!/usr/bin/env python3
"""Export file-based security platform metadata into a backend-readable snapshot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
BACKEND_SNAPSHOT_PATH = (
    REPO_ROOT
    / "backend"
    / "onyx"
    / "server"
    / "manage"
    / "security_platform"
    / "static_snapshot.json"
)

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from build_threat_intel_manifest import DEFAULT_MANIFEST_PATH
from build_threat_intel_manifest import load_manifest
from curate_threat_intel_corpus import build_unmanaged_report
from verify_security_platform_acceptance import load_threat_intel_sync_summary
from verify_security_platform_acceptance import load_playbook_definitions_summary


def build_snapshot() -> dict[str, Any]:
    manifest = load_manifest(DEFAULT_MANIFEST_PATH)
    unmanaged_report = build_unmanaged_report(DEFAULT_MANIFEST_PATH)
    manifest_summary = manifest.get("summary", {}) if isinstance(manifest, dict) else {}
    unmanaged_summary = (
        unmanaged_report.get("summary", {})
        if isinstance(unmanaged_report, dict)
        else {}
    )
    playbooks_summary = load_playbook_definitions_summary()
    threat_intel_sync = load_threat_intel_sync_summary()

    return {
        "version": 1,
        "threat_intel_sync": {
            "source_profile": threat_intel_sync.get("source_profile"),
            "last_sync_run_at": threat_intel_sync.get("last_sync_run_at"),
            "due_status": threat_intel_sync.get("due_status"),
            "due_feeds": threat_intel_sync.get("due_feeds", []),
        },
        "threat_intel_corpus": {
            "governed": int(manifest_summary.get("total_feeds", 0) or 0),
            "unmanaged": int(unmanaged_summary.get("unmanaged_total", 0) or 0),
            "promotion_candidates": int(
                unmanaged_summary.get("promotion_candidate_total", 0) or 0
            ),
            "manual_review": int(
                unmanaged_summary.get("manual_review_total", 0) or 0
            ),
            "keep_runtime_only": int(
                unmanaged_summary.get("keep_runtime_only_total", 0) or 0
            ),
        },
        "playbooks": {
            "count": int(playbooks_summary.get("count", 0) or 0),
            "with_examples": len(playbooks_summary.get("playbooks_with_examples", [])),
            "items": [
                {
                    "name": item["name"],
                    "display_name": item.get("display_name", item["name"]),
                    "has_example_inputs": item["name"]
                    in set(playbooks_summary.get("playbooks_with_examples", [])),
                    "step_count": int(item.get("step_count", 0) or 0),
                }
                for item in _playbook_catalog()
            ],
        },
    }


def _playbook_catalog() -> list[dict[str, Any]]:
    playbooks_dir = REPO_ROOT / "docs" / "security-platform" / "playbooks"
    items: list[dict[str, Any]] = []
    for path in sorted(playbooks_dir.glob("*.yaml")):
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue
        items.append(
            {
                "name": str(data.get("name", path.stem)),
                "display_name": str(data.get("display_name", path.stem)),
                "step_count": len(data.get("steps", []) or []),
            }
        )
    return items


def write_snapshot(snapshot: dict[str, Any], path: Path) -> None:
    path.write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export security platform snapshot")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--path", type=Path, default=BACKEND_SNAPSHOT_PATH)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    snapshot = build_snapshot()
    if args.verify:
        existing = json.loads(args.path.read_text(encoding="utf-8"))
        if existing != snapshot:
            print(f"[ERROR] Security platform snapshot drift detected: {args.path}")
            return 1
        print(f"[OK] Security platform snapshot verified: {args.path}")
        return 0

    if args.write:
        write_snapshot(snapshot, args.path)
        print(f"[OK] Wrote security platform snapshot: {args.path}")
        return 0

    print(json.dumps(snapshot, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
