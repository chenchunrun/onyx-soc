#!/usr/bin/env python3
"""Assess lifecycle and quality state for governed threat-intel feeds."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from typing import Any

import yaml

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from build_threat_intel_manifest import DEFAULT_MANIFEST_PATH
from build_threat_intel_manifest import load_manifest

ROOT = MODULE_DIR
CURATION_POLICY_PATH = ROOT / "threat-intelligence" / "curation_policy.yaml"


def load_policy(path: Path = CURATION_POLICY_PATH) -> dict[str, Any]:
    policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(policy, dict):
        raise ValueError(f"Invalid curation policy: {path}")
    return policy


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def classify_governed_feed(
    entry: dict[str, Any], text: str, policy: dict[str, Any]
) -> dict[str, Any]:
    quality_rules = policy.get("quality_rules", {}) or {}
    lifecycle_rules = policy.get("lifecycle_rules", {}) or {}

    quality_reasons: list[str] = []
    source = str(entry.get("source", "")).strip()
    cve_id = str(entry.get("cve_id", "")).strip()
    year = int(str(entry.get("year", "0") or 0))

    for field in quality_rules.get("required_fields", []):
        value = str(entry.get(field, "")).strip()
        if not value:
            quality_reasons.append(f"missing_{field}")

    for marker in quality_rules.get("limited_quality_markers", []):
        if marker in text:
            quality_reasons.append(f"limited_marker:{marker}")

    if quality_reasons:
        quality_tier = "limited"
    elif source in set(quality_rules.get("authoritative_sources", [])):
        quality_tier = "authoritative"
    else:
        quality_tier = "standard"

    lifecycle_reasons: list[str] = []
    active_year_threshold = int(lifecycle_rules.get("active_year_threshold", 2023))
    archive_candidate_year_threshold = int(
        lifecycle_rules.get("archive_candidate_year_threshold", 2015)
    )
    archive_candidate_quality_tiers = set(
        lifecycle_rules.get(
            "archive_candidate_quality_tiers",
            ["authoritative", "standard", "limited"],
        )
    )
    archive_exempt_sources = set(lifecycle_rules.get("archive_exempt_sources", []))
    archive_exempt_cve_ids = set(lifecycle_rules.get("archive_exempt_cve_ids", []))

    if cve_id in archive_exempt_cve_ids:
        lifecycle_state = "retained_historical"
        lifecycle_reasons.append("archive_exempt_cve")
    elif source in archive_exempt_sources:
        lifecycle_state = "retained_historical"
        lifecycle_reasons.append("archive_exempt_source")
    elif year >= active_year_threshold:
        lifecycle_state = "active"
        lifecycle_reasons.append(f"recent_year:{year}")
    elif year < archive_candidate_year_threshold and quality_tier in archive_candidate_quality_tiers:
        lifecycle_state = "archive_candidate"
        lifecycle_reasons.append(f"older_than_threshold:{archive_candidate_year_threshold}")
    else:
        lifecycle_state = "retained_historical"
        lifecycle_reasons.append("historical_but_retained")

    return {
        **entry,
        "quality_tier": quality_tier,
        "quality_reasons": quality_reasons,
        "lifecycle_state": lifecycle_state,
        "lifecycle_reasons": lifecycle_reasons,
    }


def build_lifecycle_report(
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    policy_path: Path = CURATION_POLICY_PATH,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    policy = load_policy(policy_path)

    items: list[dict[str, Any]] = []
    for entry in manifest.get("entries", []):
        if not isinstance(entry, dict):
            continue
        path = ROOT.parent / str(entry["path"])
        text = read_text(path)
        items.append(classify_governed_feed(entry, text, policy))

    lifecycle_counts = Counter(item["lifecycle_state"] for item in items)
    quality_counts = Counter(item["quality_tier"] for item in items)
    archive_candidates = [
        item for item in items if item["lifecycle_state"] == "archive_candidate"
    ]

    return {
        "policy_version": policy.get("version", 1),
        "manifest_path": str(manifest_path),
        "summary": {
            "governed_total": len(items),
            "active_total": lifecycle_counts.get("active", 0),
            "archive_candidate_total": lifecycle_counts.get("archive_candidate", 0),
            "retained_historical_total": lifecycle_counts.get("retained_historical", 0),
            "quality_counts": dict(sorted(quality_counts.items())),
        },
        "archive_candidates": archive_candidates,
    }


def default_report_path(policy: dict[str, Any]) -> Path:
    configured = (policy.get("output", {}) or {}).get("lifecycle_report_path")
    if configured:
        return ROOT.parent / configured
    return ROOT / "threat-intelligence" / "lifecycle_report.json"


def write_report(report: dict[str, Any], path: Path) -> None:
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def print_summary(report: dict[str, Any]) -> None:
    summary = report["summary"]
    quality_counts = summary.get("quality_counts", {})
    quality_line = ", ".join(
        f"{name}={count}" for name, count in sorted(quality_counts.items())
    )
    print(f"Governed feeds: {summary['governed_total']}")
    print(f"Active feeds: {summary['active_total']}")
    print(f"Archive candidates: {summary['archive_candidate_total']}")
    print(f"Retained historical: {summary['retained_historical_total']}")
    print(f"Quality tiers: {quality_line}")
    if report["archive_candidates"]:
        preview = ", ".join(item["cve_id"] for item in report["archive_candidates"][:5])
        suffix = " ..." if len(report["archive_candidates"]) > 5 else ""
        print(f"Archive preview: {preview}{suffix}")


def has_archive_candidates(report: dict[str, Any]) -> bool:
    return bool(report["archive_candidates"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assess lifecycle state for governed threat-intel feeds"
    )
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--show-summary", action="store_true")
    parser.add_argument(
        "--strict-archive-candidates",
        action="store_true",
        help="Fail if governed feeds include archive candidates that should be reviewed for archive/retirement.",
    )
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--policy-path", type=Path, default=CURATION_POLICY_PATH)
    parser.add_argument("--report-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(args.policy_path)
    report = build_lifecycle_report(args.manifest_path, args.policy_path)
    if args.write_report:
        report_path = args.report_path or default_report_path(policy)
        write_report(report, report_path)
        print(f"[OK] Wrote threat-intel lifecycle report: {report_path}")
    print_summary(report)
    if args.strict_archive_candidates and has_archive_candidates(report):
        preview = ", ".join(item["cve_id"] for item in report["archive_candidates"][:5])
        suffix = " ..." if len(report["archive_candidates"]) > 5 else ""
        print(f"[ERROR] Threat-intel archive candidates remain: {preview}{suffix}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
