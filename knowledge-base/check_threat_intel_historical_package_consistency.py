#!/usr/bin/env python3
"""Validate historical package catalog consistency against package manifests and README files."""

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
from build_threat_intel_historical_package_index import default_index_path
from build_threat_intel_historical_package_index import historical_package_root

ROOT = MODULE_DIR


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _to_repo_path(value: str) -> Path:
    return ROOT.parent / value


def evaluate_catalog_consistency() -> dict[str, Any]:
    policy = load_policy(CURATION_POLICY_PATH)
    package_root = historical_package_root(policy)
    index_path = default_index_path(policy)
    issues: list[str] = []
    package_checks: list[dict[str, Any]] = []

    if not index_path.exists():
        return {
            "ok": False,
            "summary": {
                "package_count": 0,
                "consistent_package_count": 0,
                "issue_count": 1,
            },
            "issues": [f"Missing historical package index: {index_path}"],
            "package_checks": [],
        }

    index_doc = load_json(index_path)
    packages = index_doc.get("packages", [])
    if not isinstance(packages, list):
        packages = []
        issues.append("Historical package index packages field is not a list")

    package_dirs = {
        path.name
        for path in package_root.iterdir()
        if path.is_dir()
    } if package_root.exists() else set()
    indexed_ids = {
        str(package.get("batch_id", "")).strip()
        for package in packages
        if isinstance(package, dict) and str(package.get("batch_id", "")).strip()
    }

    missing_from_index = sorted(package_dirs - indexed_ids)
    extra_in_index = sorted(indexed_ids - package_dirs)
    if missing_from_index:
        issues.append(
            "Historical package directories missing from index: "
            + ", ".join(missing_from_index)
        )
    if extra_in_index:
        issues.append(
            "Historical package index references missing directories: "
            + ", ".join(extra_in_index)
        )

    for package in packages:
        if not isinstance(package, dict):
            continue
        batch_id = str(package.get("batch_id", "")).strip()
        if not batch_id:
            continue

        manifest_repo_path = str(package.get("manifest_path", "")).strip()
        readme_repo_path = str(package.get("readme_path", "")).strip()
        package_issues: list[str] = []

        manifest_path = _to_repo_path(manifest_repo_path) if manifest_repo_path else None
        readme_path = _to_repo_path(readme_repo_path) if readme_repo_path else None

        manifest_doc: dict[str, Any] = {}
        if manifest_path is None or not manifest_path.exists():
            package_issues.append(f"Missing manifest: {manifest_repo_path or batch_id}")
        else:
            manifest_doc = load_json(manifest_path)
            manifest_summary = manifest_doc.get("summary", {}) if isinstance(manifest_doc, dict) else {}
            if str(manifest_doc.get("batch_id", "")).strip() != batch_id:
                package_issues.append(
                    f"Manifest batch_id mismatch: {manifest_doc.get('batch_id')} != {batch_id}"
                )
            if int(package.get("item_count", 0) or 0) != int(
                manifest_summary.get("item_count", 0) or 0
            ):
                package_issues.append("Index item_count does not match manifest summary")
            if int(package.get("total_size_bytes", 0) or 0) != int(
                manifest_summary.get("total_size_bytes", 0) or 0
            ):
                package_issues.append("Index total_size_bytes does not match manifest summary")
            if (package.get("source_counts", {}) or {}) != (manifest_summary.get("source_counts", {}) or {}):
                package_issues.append("Index source_counts does not match manifest summary")
            if (package.get("quality_counts", {}) or {}) != (manifest_summary.get("quality_counts", {}) or {}):
                package_issues.append("Index quality_counts does not match manifest summary")
            if (package.get("year_counts", {}) or {}) != (manifest_summary.get("year_counts", {}) or {}):
                package_issues.append("Index year_counts does not match manifest summary")

        if readme_path is None or not readme_path.exists():
            package_issues.append(f"Missing README: {readme_repo_path or batch_id}")
        else:
            readme_text = read_text(readme_path)
            if batch_id not in readme_text:
                package_issues.append("README does not mention batch_id")
            if manifest_repo_path and manifest_repo_path not in index_doc.get("packages", [{}])[0].get("manifest_path", manifest_repo_path):
                pass
            if str(package.get("item_count", "")).strip() and str(package.get("item_count")) not in readme_text:
                package_issues.append("README does not mention item_count")

        package_checks.append(
            {
                "batch_id": batch_id,
                "ok": not package_issues,
                "issue_count": len(package_issues),
                "issues": package_issues,
            }
        )
        issues.extend(f"{batch_id}: {issue}" for issue in package_issues)

    consistent_package_count = sum(1 for item in package_checks if item["ok"])
    return {
        "ok": not issues,
        "summary": {
            "package_count": len(package_checks),
            "consistent_package_count": consistent_package_count,
            "issue_count": len(issues),
        },
        "issues": issues,
        "package_checks": package_checks,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check historical package catalog consistency"
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = evaluate_catalog_consistency()
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        summary = result["summary"]
        print(
            "Historical package consistency: "
            f"packages={summary['package_count']}, "
            f"consistent={summary['consistent_package_count']}, "
            f"issues={summary['issue_count']}"
        )
        for issue in result["issues"]:
            print(f"- {issue}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
