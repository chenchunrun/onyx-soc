#!/usr/bin/env python3
"""Build a per-batch archive worklist for threat-intel review."""

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

ROOT = MODULE_DIR
ARCHIVE_BATCHES_PATH = ROOT / "threat-intelligence" / "archive_batches.json"
LIFECYCLE_REPORT_PATH = ROOT / "threat-intelligence" / "lifecycle_report.json"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_batch(batch_id: str, path: Path = ARCHIVE_BATCHES_PATH) -> dict[str, Any]:
    doc = load_json(path)
    for batch in doc.get("batches", []):
        if str(batch.get("batch_id")) == batch_id:
            return batch
    supported = ", ".join(
        str(batch.get("batch_id")) for batch in doc.get("batches", []) if batch.get("batch_id")
    )
    raise ValueError(f"Unknown batch_id: {batch_id}. Supported: {supported}")


def default_worklist_path(batch_id: str, policy: dict[str, Any]) -> Path:
    configured_dir = (policy.get("output", {}) or {}).get("archive_worklist_dir")
    if configured_dir:
        base_dir = ROOT.parent / configured_dir
    else:
        base_dir = ROOT / "threat-intelligence" / "archive_worklists"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / f"{batch_id}.json"


def build_worklist(batch: dict[str, Any], lifecycle_report: dict[str, Any]) -> dict[str, Any]:
    source = str(batch["source"])
    quality_tier = str(batch["quality_tier"])
    years = set(str(year) for year in batch.get("years", []))

    items = [
        item
        for item in lifecycle_report.get("archive_candidates", [])
        if str(item.get("source")) == source
        and str(item.get("quality_tier")) == quality_tier
        and str(item.get("year")) in years
    ]
    items = sorted(items, key=lambda item: (str(item.get("year")), str(item.get("cve_id"))))

    return {
        "batch_id": batch["batch_id"],
        "description": batch.get("description", ""),
        "recommended_action": batch.get("recommended_action", ""),
        "summary": {
            "candidate_count": len(items),
            "source": source,
            "quality_tier": quality_tier,
            "years": sorted(years),
        },
        "items": items,
    }


def write_worklist(report: dict[str, Any], path: Path) -> None:
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def print_summary(report: dict[str, Any]) -> None:
    print(f"Batch: {report['batch_id']}")
    print(f"Candidates: {report['summary']['candidate_count']}")
    print(f"Source: {report['summary']['source']}")
    print(f"Quality: {report['summary']['quality_tier']}")
    print("Years: " + ", ".join(report["summary"]["years"]))
    if report["items"]:
        preview = ", ".join(item["cve_id"] for item in report["items"][:10])
        suffix = " ..." if len(report["items"]) > 10 else ""
        print(f"Preview: {preview}{suffix}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a per-batch archive review worklist"
    )
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--show-summary", action="store_true")
    parser.add_argument("--report-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(CURATION_POLICY_PATH)
    batch = load_batch(args.batch_id)
    lifecycle_report = load_json(LIFECYCLE_REPORT_PATH)
    report = build_worklist(batch, lifecycle_report)
    if args.write_report:
        report_path = args.report_path or default_worklist_path(args.batch_id, policy)
        write_worklist(report, report_path)
        print(f"[OK] Wrote threat-intel archive worklist: {report_path}")
    print_summary(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
