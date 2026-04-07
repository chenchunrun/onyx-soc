#!/usr/bin/env python3
"""Build a post-execution result summary for a threat-intel archive batch."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from assess_threat_intel_lifecycle import CURATION_POLICY_PATH
from assess_threat_intel_lifecycle import load_policy
from build_threat_intel_archive_patch_preview import default_report_path as default_patch_preview_path
from build_threat_intel_archive_patch_preview import load_json
from build_threat_intel_archive_worklist import default_worklist_path

ROOT = MODULE_DIR
MANIFEST_PATH = ROOT / "threat-intelligence" / "feed_manifest.json"
LIFECYCLE_REPORT_PATH = ROOT / "threat-intelligence" / "lifecycle_report.json"


def default_result_path(batch_id: str, policy: dict[str, Any]) -> Path:
    configured_dir = (policy.get("output", {}) or {}).get("archive_execution_result_dir")
    if configured_dir:
        base_dir = ROOT.parent / configured_dir
    else:
        base_dir = ROOT / "threat-intelligence" / "archive_execution_results"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / f"{batch_id}.json"


def build_execution_result(
    *,
    batch_id: str,
    mode: str,
    worklist: dict[str, Any],
    preview: dict[str, Any],
    manifest: dict[str, Any],
    lifecycle_report: dict[str, Any],
) -> dict[str, Any]:
    remaining_count = int(worklist.get("summary", {}).get("candidate_count", 0))
    projected_total = int(preview.get("summary", {}).get("projected_governed_total", 0))
    actual_total = int(manifest.get("summary", {}).get("total_feeds", 0))
    lifecycle_summary = lifecycle_report.get("summary", {})
    completed = remaining_count == 0 and actual_total == projected_total

    return {
        "batch_id": batch_id,
        "mode": mode,
        "completed": completed,
        "summary": {
            "remaining_candidate_count": remaining_count,
            "projected_governed_total": projected_total,
            "actual_governed_total": actual_total,
            "archive_candidates_total": int(
                lifecycle_summary.get("archive_candidate_total", 0)
            ),
            "retained_historical_total": int(
                lifecycle_summary.get("retained_historical_total", 0)
            ),
        },
    }


def write_result(result: dict[str, Any], path: Path) -> None:
    path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a post-execution result summary for a threat-intel archive batch"
    )
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--mode", default="apply", choices=["preview", "apply"])
    parser.add_argument("--write-result", action="store_true")
    parser.add_argument("--show-summary", action="store_true")
    parser.add_argument("--result-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(CURATION_POLICY_PATH)
    worklist = load_json(default_worklist_path(args.batch_id, policy))
    preview = load_json(default_patch_preview_path(args.batch_id, policy))
    manifest = load_json(MANIFEST_PATH)
    lifecycle_report = load_json(LIFECYCLE_REPORT_PATH)
    result = build_execution_result(
        batch_id=args.batch_id,
        mode=args.mode,
        worklist=worklist,
        preview=preview,
        manifest=manifest,
        lifecycle_report=lifecycle_report,
    )
    if args.write_result:
        result_path = args.result_path or default_result_path(args.batch_id, policy)
        write_result(result, result_path)
        print(f"[OK] Wrote threat-intel archive execution result: {result_path}")
    if args.show_summary:
        summary = result["summary"]
        print(f"Batch: {result['batch_id']}")
        print(f"Mode: {result['mode']}")
        print(f"Completed: {result['completed']}")
        print(f"Remaining candidates: {summary['remaining_candidate_count']}")
        print(f"Projected governed total: {summary['projected_governed_total']}")
        print(f"Actual governed total: {summary['actual_governed_total']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
