#!/usr/bin/env python3
"""Build executable archive-review batches from threat-intel lifecycle outputs."""

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
from plan_threat_intel_archive import build_archive_plan

ROOT = MODULE_DIR
LIFECYCLE_REPORT_PATH = ROOT / "threat-intelligence" / "lifecycle_report.json"


def load_lifecycle_report(path: Path = LIFECYCLE_REPORT_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def default_report_path(policy: dict[str, Any]) -> Path:
    configured = (policy.get("output", {}) or {}).get("archive_batches_path")
    if configured:
        return ROOT.parent / configured
    return ROOT / "threat-intelligence" / "archive_batches.json"


def build_archive_batches(
    lifecycle_report: dict[str, Any],
    archive_plan: dict[str, Any],
) -> dict[str, Any]:
    candidates = lifecycle_report.get("archive_candidates", [])

    phase1_items = [
        item
        for item in candidates
        if item.get("source") == "CISA Known Exploited Vulnerabilities Catalog"
        and item.get("quality_tier") == "limited"
    ]
    phase1_years = sorted({str(item.get("year", "unknown")) for item in phase1_items})

    phase2_items = [
        item
        for item in candidates
        if item.get("source") == "NIST National Vulnerability Database (NVD)"
        and item.get("quality_tier") == "authoritative"
    ]
    phase2_years = sorted({str(item.get("year", "unknown")) for item in phase2_items})

    return {
        "summary": {
            "total_archive_candidates": archive_plan["summary"]["archive_candidate_total"],
            "batch_count": 2,
        },
        "batches": [
            {
                "batch_id": "phase-1-cisa-limited-historical",
                "description": "First archive review batch for low-value historical CISA placeholder feeds.",
                "source": "CISA Known Exploited Vulnerabilities Catalog",
                "quality_tier": "limited",
                "years": phase1_years,
                "candidate_count": len(phase1_items),
                "preview_cve_ids": [item["cve_id"] for item in phase1_items[:20]],
                "recommended_action": "Archive or remove placeholder-heavy historical CISA feeds from the governed package after review.",
            },
            {
                "batch_id": "phase-2-nvd-authoritative-historical",
                "description": "Second archive review batch for historical authoritative NVD feeds.",
                "source": "NIST National Vulnerability Database (NVD)",
                "quality_tier": "authoritative",
                "years": phase2_years,
                "candidate_count": len(phase2_items),
                "preview_cve_ids": [item["cve_id"] for item in phase2_items[:20]],
                "recommended_action": "Review whether historical authoritative NVD feeds should be archived into a separate historical package.",
            },
        ],
    }


def write_report(report: dict[str, Any], path: Path) -> None:
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def print_summary(report: dict[str, Any]) -> None:
    print(f"Archive batches: {report['summary']['batch_count']}")
    for batch in report["batches"]:
        print(
            f"- {batch['batch_id']}: {batch['candidate_count']} candidates "
            f"({batch['source']}, {batch['quality_tier']})"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build executable archive-review batches for threat-intel feeds"
    )
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--show-summary", action="store_true")
    parser.add_argument("--report-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(CURATION_POLICY_PATH)
    lifecycle_report = load_lifecycle_report()
    archive_plan = build_archive_plan()
    report = build_archive_batches(lifecycle_report, archive_plan)
    if args.write_report:
        report_path = args.report_path or default_report_path(policy)
        write_report(report, report_path)
        print(f"[OK] Wrote threat-intel archive batches: {report_path}")
    print_summary(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
