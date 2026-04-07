#!/usr/bin/env python3
"""Build a catalog index for generated threat-intel historical packages."""

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


def historical_package_root(policy: dict[str, Any]) -> Path:
    configured_dir = (policy.get("output", {}) or {}).get("historical_package_dir")
    if configured_dir:
        return ROOT.parent / configured_dir
    return ROOT / "threat-intelligence" / "historical_packages"


def default_index_path(policy: dict[str, Any]) -> Path:
    configured = (policy.get("output", {}) or {}).get("historical_package_index_path")
    if configured:
        return ROOT.parent / configured
    return historical_package_root(policy) / "index.json"


def discover_historical_packages(policy: dict[str, Any]) -> list[dict[str, Any]]:
    package_root = historical_package_root(policy)
    packages: list[dict[str, Any]] = []
    if not package_root.exists():
        return packages

    for package_dir in sorted(path for path in package_root.iterdir() if path.is_dir()):
        manifest_path = package_dir / "manifest.json"
        readme_path = package_dir / "README.md"
        if not manifest_path.exists():
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        summary = manifest.get("summary", {})
        packages.append(
            {
                "batch_id": manifest.get("batch_id", package_dir.name),
                "description": manifest.get("description", ""),
                "recommended_action": manifest.get("recommended_action", ""),
                "manifest_path": str(manifest_path.relative_to(ROOT.parent)).replace("\\", "/"),
                "readme_path": str(readme_path.relative_to(ROOT.parent)).replace("\\", "/")
                if readme_path.exists()
                else "",
                "item_count": int(summary.get("item_count", 0)),
                "total_size_bytes": int(summary.get("total_size_bytes", 0)),
                "source_counts": summary.get("source_counts", {}),
                "year_counts": summary.get("year_counts", {}),
                "quality_counts": summary.get("quality_counts", {}),
            }
        )
    return packages


def build_index(packages: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "catalog_version": 1,
        "summary": {
            "package_count": len(packages),
            "total_item_count": sum(int(pkg["item_count"]) for pkg in packages),
            "total_size_bytes": sum(int(pkg["total_size_bytes"]) for pkg in packages),
        },
        "packages": packages,
    }


def build_catalog_readme(index_doc: dict[str, Any]) -> str:
    summary = index_doc["summary"]
    lines = [
        "# Threat-Intel Historical Package Catalog",
        "",
        "## Summary",
        "",
        f"- `package_count`: `{summary['package_count']}`",
        f"- `total_item_count`: `{summary['total_item_count']}`",
        f"- `total_size_bytes`: `{summary['total_size_bytes']}`",
        "",
        "## Packages",
        "",
    ]
    for package in index_doc["packages"]:
        lines.extend(
            [
                f"### `{package['batch_id']}`",
                "",
                f"- `description`: {package['description']}",
                f"- `item_count`: `{package['item_count']}`",
                f"- `manifest`: `{package['manifest_path']}`",
                f"- `readme`: `{package['readme_path']}`",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def write_index(path: Path, index_doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(index_doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_catalog_readme(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a catalog index for threat-intel historical packages"
    )
    parser.add_argument("--write-index", action="store_true")
    parser.add_argument("--show-summary", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(CURATION_POLICY_PATH)
    packages = discover_historical_packages(policy)
    index_doc = build_index(packages)
    if args.write_index:
        index_path = default_index_path(policy)
        write_index(index_path, index_doc)
        readme_path = historical_package_root(policy) / "README.md"
        write_catalog_readme(readme_path, build_catalog_readme(index_doc))
        print(f"[OK] Wrote historical package index: {index_path}")
        print(f"[OK] Wrote historical package catalog README: {readme_path}")
    if args.show_summary:
        summary = index_doc["summary"]
        print(f"Packages: {summary['package_count']}")
        print(f"Items: {summary['total_item_count']}")
        print(f"Size: {summary['total_size_bytes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
