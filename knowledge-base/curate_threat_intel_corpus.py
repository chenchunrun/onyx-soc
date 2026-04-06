#!/usr/bin/env python3
"""Classify unmanaged threat-intel feed files for promotion or review."""

from __future__ import annotations

import argparse
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
from build_threat_intel_manifest import parse_feed_file
from build_threat_intel_manifest import unmanaged_local_feed_paths

ROOT = MODULE_DIR
CURATION_POLICY_PATH = ROOT / "threat-intelligence" / "curation_policy.yaml"


def load_policy(path: Path = CURATION_POLICY_PATH) -> dict[str, Any]:
    policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(policy, dict):
        raise ValueError(f"Invalid curation policy: {path}")
    return policy


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def classify_unmanaged_feed(entry: dict[str, Any], text: str, policy: dict[str, Any]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    promotion_rules = policy.get("promotion_rules", {})
    review_rules = policy.get("review_rules", {})

    allow_sources = set(promotion_rules.get("allow_sources", []))
    if entry.get("source") not in allow_sources:
        reasons.append(f"source_not_promotable:{entry.get('source', 'unknown')}")

    for field in promotion_rules.get("require_fields", []):
        value = str(entry.get(field, "")).strip()
        if not value:
            reasons.append(f"missing_{field}")

    for marker in promotion_rules.get("reject_if_text_contains", []):
        if marker in text:
            reasons.append(f"contains_rejected_marker:{marker}")

    low_quality_sources = set(review_rules.get("low_quality_sources", []))
    low_quality_markers = review_rules.get("low_quality_markers", [])
    if entry.get("source") in low_quality_sources:
        reasons.append(f"review_source:{entry['source']}")
    for marker in low_quality_markers:
        if marker in text:
            reasons.append(f"review_marker:{marker}")

    if not reasons:
        return "promotion_candidate", []

    review_only = all(reason.startswith("review_") for reason in reasons)
    if review_only:
        return "manual_review", reasons
    return "keep_runtime_only", reasons


def build_unmanaged_report(
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    policy_path: Path = CURATION_POLICY_PATH,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    policy = load_policy(policy_path)
    unmanaged_paths = unmanaged_local_feed_paths(manifest)

    promotion_candidates: list[dict[str, Any]] = []
    manual_review: list[dict[str, Any]] = []
    keep_runtime_only: list[dict[str, Any]] = []

    for relative_path in unmanaged_paths:
        path = ROOT.parent / relative_path
        entry = parse_feed_file(path)
        text = read_text(path)
        decision, reasons = classify_unmanaged_feed(entry, text, policy)
        entry_with_decision = {
            **entry,
            "decision": decision,
            "reasons": reasons,
        }
        if decision == "promotion_candidate":
            promotion_candidates.append(entry_with_decision)
        elif decision == "manual_review":
            manual_review.append(entry_with_decision)
        else:
            keep_runtime_only.append(entry_with_decision)

    return {
        "policy_version": policy.get("version", 1),
        "manifest_path": str(manifest_path),
        "summary": {
            "unmanaged_total": len(unmanaged_paths),
            "promotion_candidate_total": len(promotion_candidates),
            "manual_review_total": len(manual_review),
            "keep_runtime_only_total": len(keep_runtime_only),
        },
        "promotion_candidates": promotion_candidates,
        "manual_review": manual_review,
        "keep_runtime_only": keep_runtime_only,
    }


def default_report_path(policy: dict[str, Any]) -> Path:
    configured = policy.get("output", {}).get("report_path")
    if configured:
        return ROOT.parent / configured
    return ROOT / "threat-intelligence" / "unmanaged_feed_report.json"


def write_report(report: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def print_summary(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(f"Unmanaged feeds: {summary['unmanaged_total']}")
    print(f"Promotion candidates: {summary['promotion_candidate_total']}")
    print(f"Manual review: {summary['manual_review_total']}")
    print(f"Keep runtime only: {summary['keep_runtime_only_total']}")
    if report["promotion_candidates"]:
        preview = ", ".join(item["cve_id"] for item in report["promotion_candidates"][:5])
        suffix = " ..." if len(report["promotion_candidates"]) > 5 else ""
        print(f"Promotion preview: {preview}{suffix}")
    if report["manual_review"]:
        preview = ", ".join(item["cve_id"] for item in report["manual_review"][:5])
        suffix = " ..." if len(report["manual_review"]) > 5 else ""
        print(f"Manual review preview: {preview}{suffix}")


def has_unpromoted_candidates(report: dict[str, Any]) -> bool:
    return bool(report["promotion_candidates"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Classify unmanaged threat-intel feed files")
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--show-summary", action="store_true")
    parser.add_argument(
        "--strict-promotion-candidates",
        action="store_true",
        help="Fail if unmanaged feeds include promotion candidates that are not yet part of the governed package.",
    )
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--policy-path", type=Path, default=CURATION_POLICY_PATH)
    parser.add_argument("--report-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(args.policy_path)
    report = build_unmanaged_report(args.manifest_path, args.policy_path)
    if args.write_report:
        report_path = args.report_path or default_report_path(policy)
        write_report(report, report_path)
        print(f"[OK] Wrote unmanaged threat-intel report: {report_path}")
    print_summary(report)
    if args.strict_promotion_candidates and has_unpromoted_candidates(report):
        preview = ", ".join(item["cve_id"] for item in report["promotion_candidates"][:5])
        suffix = " ..." if len(report["promotion_candidates"]) > 5 else ""
        print(f"[ERROR] Unpromoted threat-intel candidates remain: {preview}{suffix}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
