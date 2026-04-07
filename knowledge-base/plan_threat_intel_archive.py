#!/usr/bin/env python3
"""Build an actionable archive plan for governed threat-intel feeds."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from assess_threat_intel_lifecycle import CURATION_POLICY_PATH
from assess_threat_intel_lifecycle import DEFAULT_MANIFEST_PATH
from assess_threat_intel_lifecycle import build_lifecycle_report
from assess_threat_intel_lifecycle import load_policy

ROOT = MODULE_DIR


def default_report_path(policy: dict[str, Any]) -> Path:
    configured = (policy.get("output", {}) or {}).get("archive_plan_path")
    if configured:
        return ROOT.parent / configured
    return ROOT / "threat-intelligence" / "archive_plan.json"


def build_archive_plan(
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    policy_path: Path = CURATION_POLICY_PATH,
) -> dict[str, Any]:
    lifecycle_report = build_lifecycle_report(manifest_path, policy_path)
    candidates = lifecycle_report.get("archive_candidates", [])

    by_source = Counter(str(item.get("source", "Unknown")) for item in candidates)
    by_year = Counter(str(item.get("year", "unknown")) for item in candidates)
    by_quality = Counter(str(item.get("quality_tier", "unknown")) for item in candidates)

    source_buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in candidates:
        source_buckets[str(item.get("source", "Unknown"))].append(item)

    action_groups: list[dict[str, Any]] = []
    for source, items in sorted(source_buckets.items()):
        years = sorted({str(item.get("year", "unknown")) for item in items})
        quality_counts = Counter(str(item.get("quality_tier", "unknown")) for item in items)
        preview = [item["cve_id"] for item in sorted(items, key=lambda x: x["cve_id"])[:10]]
        action_groups.append(
            {
                "source": source,
                "candidate_count": len(items),
                "years": years,
                "quality_counts": dict(sorted(quality_counts.items())),
                "preview_cve_ids": preview,
                "recommended_action": (
                    "Prioritize archive review for placeholder-heavy historical feeds"
                    if "limited" in quality_counts
                    else "Review historical governed feeds for archive packaging"
                ),
            }
        )

    return {
        "summary": {
            "archive_candidate_total": len(candidates),
            "by_source": dict(sorted(by_source.items())),
            "by_year": dict(sorted(by_year.items())),
            "by_quality": dict(sorted(by_quality.items())),
        },
        "action_groups": action_groups,
    }


def write_report(report: dict[str, Any], path: Path) -> None:
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def print_summary(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(f"Archive candidates: {summary['archive_candidate_total']}")
    print(
        "By source: "
        + ", ".join(f"{name}={count}" for name, count in summary["by_source"].items())
    )
    print(
        "By year: "
        + ", ".join(f"{name}={count}" for name, count in summary["by_year"].items())
    )
    print(
        "By quality: "
        + ", ".join(f"{name}={count}" for name, count in summary["by_quality"].items())
    )
    for group in report["action_groups"][:5]:
        print(
            f"- {group['source']}: {group['candidate_count']} candidates "
            f"(years={','.join(group['years'][:5])}{'...' if len(group['years']) > 5 else ''})"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an actionable archive plan for governed threat-intel feeds"
    )
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--show-summary", action="store_true")
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--policy-path", type=Path, default=CURATION_POLICY_PATH)
    parser.add_argument("--report-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(args.policy_path)
    report = build_archive_plan(args.manifest_path, args.policy_path)
    if args.write_report:
        report_path = args.report_path or default_report_path(policy)
        write_report(report, report_path)
        print(f"[OK] Wrote threat-intel archive plan: {report_path}")
    print_summary(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
