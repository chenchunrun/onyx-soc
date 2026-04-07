#!/usr/bin/env python3
"""Build a historical package manifest and README from an archive batch worklist."""

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

from assess_threat_intel_lifecycle import CURATION_POLICY_PATH
from assess_threat_intel_lifecycle import load_policy
from build_threat_intel_archive_worklist import default_worklist_path, load_json

ROOT = MODULE_DIR


def package_dir_for_batch(batch_id: str, policy: dict[str, Any]) -> Path:
    configured_dir = (policy.get("output", {}) or {}).get("historical_package_dir")
    if configured_dir:
        base_dir = ROOT.parent / configured_dir
    else:
        base_dir = ROOT / "threat-intelligence" / "historical_packages"
    return base_dir / batch_id


def build_package_manifest(worklist: dict[str, Any]) -> dict[str, Any]:
    items = worklist.get("items", [])
    source_counts = Counter(str(item.get("source", "Unknown")) for item in items)
    year_counts = Counter(str(item.get("year", "unknown")) for item in items)
    quality_counts = Counter(str(item.get("quality_tier", "unknown")) for item in items)

    return {
        "package_version": 1,
        "batch_id": worklist["batch_id"],
        "description": worklist.get("description", ""),
        "recommended_action": worklist.get("recommended_action", ""),
        "summary": {
            "item_count": len(items),
            "total_size_bytes": sum(int(item.get("size_bytes", 0) or 0) for item in items),
            "source_counts": dict(sorted(source_counts.items())),
            "year_counts": dict(sorted(year_counts.items())),
            "quality_counts": dict(sorted(quality_counts.items())),
        },
        "entries": items,
    }


def build_package_readme(manifest: dict[str, Any]) -> str:
    summary = manifest["summary"]
    source_counts = ", ".join(
        f"{name}={count}" for name, count in summary["source_counts"].items()
    )
    year_counts = ", ".join(
        f"{year}={count}" for year, count in summary["year_counts"].items()
    )
    quality_counts = ", ".join(
        f"{name}={count}" for name, count in summary["quality_counts"].items()
    )
    sample = "\n".join(
        f"- `{entry['cve_id']}`: {entry['title']}" for entry in manifest["entries"][:10]
    )
    if not sample:
        sample = "- none"

    return f"""# Threat-Intel Historical Package

## Batch

- `batch_id`: `{manifest['batch_id']}`
- `description`: {manifest.get('description', '')}
- `recommended_action`: {manifest.get('recommended_action', '')}

## Summary

- `item_count`: `{summary['item_count']}`
- `total_size_bytes`: `{summary['total_size_bytes']}`
- `sources`: `{source_counts}`
- `years`: `{year_counts}`
- `quality`: `{quality_counts}`

## Purpose

This package preserves archive-batch content outside the governed threat-intel corpus.
It is intended as a historical reference package for older feeds that have been reviewed
for removal from the active governed set.

## Sample Entries

{sample}
"""


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_readme(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def generate_historical_package(batch_id: str) -> dict[str, Path]:
    policy = load_policy(CURATION_POLICY_PATH)
    worklist = load_json(default_worklist_path(batch_id, policy))
    package_dir = package_dir_for_batch(batch_id, policy)
    package_dir.mkdir(parents=True, exist_ok=True)

    manifest = build_package_manifest(worklist)
    readme = build_package_readme(manifest)

    manifest_path = package_dir / "manifest.json"
    readme_path = package_dir / "README.md"
    write_manifest(manifest_path, manifest)
    write_readme(readme_path, readme)

    return {"manifest": manifest_path, "readme": readme_path}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a historical package manifest and README for an archive batch"
    )
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--show-paths", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = generate_historical_package(args.batch_id)
    print(f"[OK] Generated historical package for batch: {args.batch_id}")
    if args.show_paths:
        for label, path in paths.items():
            print(f"{label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
