#!/usr/bin/env python3
"""Build a reviewable execution plan for a threat-intel archive batch."""

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
from build_threat_intel_archive_action_script import default_script_path
from build_threat_intel_archive_patch_preview import default_report_path as default_patch_preview_path
from build_threat_intel_archive_patch_preview import load_json
from build_threat_intel_archive_worklist import default_worklist_path

ROOT = MODULE_DIR


def default_plan_path(batch_id: str, policy: dict[str, Any]) -> Path:
    configured_dir = (policy.get("output", {}) or {}).get("archive_execution_plan_dir")
    if configured_dir:
        base_dir = ROOT.parent / configured_dir
    else:
        base_dir = ROOT / "threat-intelligence" / "archive_execution_plans"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / f"{batch_id}.md"


def build_execution_plan(
    *,
    batch_id: str,
    worklist: dict[str, Any],
    preview: dict[str, Any],
    action_script_path: Path,
) -> str:
    summary = preview["summary"]
    worklist_summary = worklist["summary"]
    years = ", ".join(str(year) for year in worklist_summary.get("years", []))
    removed_sources = summary.get("removed_source_counts", {})
    projected_sources = summary.get("projected_source_counts", {})
    removed_sources_text = ", ".join(
        f"{name}={count}" for name, count in removed_sources.items()
    ) or "none"
    projected_sources_text = ", ".join(
        f"{name}={count}" for name, count in projected_sources.items()
    ) or "none"
    sample_paths = [str(path) for path in preview.get("paths_to_remove", [])[:10]]
    sample_paths_text = "\n".join(f"- `{path}`" for path in sample_paths) or "- none"

    commands = [
        "python knowledge-base/build_threat_intel_manifest.py --verify",
        "python knowledge-base/assess_threat_intel_lifecycle.py --write-report --show-summary",
        f"python knowledge-base/build_threat_intel_archive_worklist.py --batch-id {batch_id} --write-report --show-summary",
        f"python knowledge-base/build_threat_intel_archive_patch_preview.py --batch-id {batch_id} --write-report --show-summary",
        f"bash {action_script_path.as_posix()}",
    ]
    command_text = "\n".join(f"1. `{command}`" if idx == 0 else f"{idx + 1}. `{command}`" for idx, command in enumerate(commands))

    rollback_commands = [
        "git reset --hard HEAD",
        "git clean -fd knowledge-base/threat-intelligence/archive_worklists knowledge-base/threat-intelligence/archive_patch_previews knowledge-base/threat-intelligence/archive_action_scripts knowledge-base/threat-intelligence/archive_execution_plans",
        "python knowledge-base/build_threat_intel_manifest.py --verify",
    ]
    rollback_text = "\n".join(f"1. `{command}`" if idx == 0 else f"{idx + 1}. `{command}`" for idx, command in enumerate(rollback_commands))

    return f"""# Threat-Intel Archive Execution Plan

## Batch

- `batch_id`: `{batch_id}`
- `description`: {worklist.get('description', '')}
- `recommended_action`: {worklist.get('recommended_action', '')}

## Scope

- `candidate_count`: `{worklist_summary['candidate_count']}`
- `source`: `{worklist_summary['source']}`
- `quality_tier`: `{worklist_summary['quality_tier']}`
- `years`: `{years}`

## Projected Impact

- `projected_governed_total`: `{summary['projected_governed_total']}`
- `removal_size_bytes`: `{summary['removal_size_bytes']}`
- `removed_sources`: `{removed_sources_text}`
- `projected_sources`: `{projected_sources_text}`

## Sample Paths

{sample_paths_text}

## Preconditions

- Run in a clean git worktree or disposable branch.
- Ensure the repo-level Python environment is available.
- Confirm no unrelated `knowledge-base/威胁情报/feeds` edits are pending.
- Rebuild the worklist and patch preview before execution.

## Execution Steps

{command_text}

## Validation Targets

- `git rm` removes the expected `{worklist_summary['candidate_count']}` files.
- `feed_manifest.json` rebuilds successfully.
- `lifecycle_report.json` rebuilds successfully.
- `archive_worklists/{batch_id}.json` becomes `candidate_count=0`.
- `archive_patch_previews/{batch_id}.json` becomes `removal_candidate_count=0`.
- `python knowledge-base/setup_security_threat_intel.py --verify --local-only` returns success.

## Rollback

{rollback_text}

## Notes

- Action script path: `{action_script_path.as_posix()}`
- This plan is generated from the current worklist and patch preview and should be regenerated if the corpus changes.
"""


def write_plan(text: str, path: Path) -> None:
    path.write_text(text, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a reviewable execution plan for a threat-intel archive batch"
    )
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--write-plan", action="store_true")
    parser.add_argument("--show-path", action="store_true")
    parser.add_argument("--plan-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(CURATION_POLICY_PATH)
    worklist_path = default_worklist_path(args.batch_id, policy)
    preview_path = default_patch_preview_path(args.batch_id, policy)
    action_script_path = default_script_path(args.batch_id, policy)
    worklist = load_json(worklist_path)
    preview = load_json(preview_path)
    plan = build_execution_plan(
        batch_id=args.batch_id,
        worklist=worklist,
        preview=preview,
        action_script_path=action_script_path,
    )
    plan_path = args.plan_path or default_plan_path(args.batch_id, policy)
    if args.write_plan:
        write_plan(plan, plan_path)
        print(f"[OK] Wrote threat-intel archive execution plan: {plan_path}")
    if args.show_path:
        print(plan_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
