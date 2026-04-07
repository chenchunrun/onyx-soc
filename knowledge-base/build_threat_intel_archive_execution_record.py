#!/usr/bin/env python3
"""Build a reviewable execution record template for a threat-intel archive batch."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from assess_threat_intel_lifecycle import CURATION_POLICY_PATH
from assess_threat_intel_lifecycle import load_policy
from build_threat_intel_archive_execution_plan import default_plan_path
from build_threat_intel_archive_patch_preview import default_report_path as default_patch_preview_path
from build_threat_intel_archive_patch_preview import load_json
from build_threat_intel_archive_worklist import default_worklist_path

ROOT = MODULE_DIR


def default_record_path(batch_id: str, policy: dict[str, Any]) -> Path:
    configured_dir = (policy.get("output", {}) or {}).get("archive_execution_record_dir")
    if configured_dir:
        base_dir = ROOT.parent / configured_dir
    else:
        base_dir = ROOT / "threat-intelligence" / "archive_execution_records"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / f"{batch_id}.md"


def build_execution_record(
    *,
    batch_id: str,
    worklist: dict[str, Any],
    preview: dict[str, Any],
    execution_plan_path: Path,
) -> str:
    worklist_summary = worklist["summary"]
    preview_summary = preview["summary"]
    years = ", ".join(str(year) for year in worklist_summary.get("years", []))
    validation_targets = [
        f"`git rm` removed the expected `{worklist_summary['candidate_count']}` files",
        "`feed_manifest.json` rebuilt successfully",
        "`lifecycle_report.json` rebuilt successfully",
        f"`archive_worklists/{batch_id}.json` reached `candidate_count=0`",
        f"`archive_patch_previews/{batch_id}.json` reached `removal_candidate_count=0`",
        "`setup_security_threat_intel.py --verify --local-only` returned success",
    ]
    validation_text = "\n".join(f"- [ ] {item}" for item in validation_targets)
    sample_paths = [str(path) for path in preview.get("paths_to_remove", [])[:10]]
    sample_paths_text = "\n".join(f"- `{path}`" for path in sample_paths) or "- none"

    return f"""# Threat-Intel Archive Execution Record

## Batch

- `batch_id`: `{batch_id}`
- `description`: {worklist.get('description', '')}
- `recommended_action`: {worklist.get('recommended_action', '')}

## Approval

- `requested_by`:
- `approved_by`:
- `approval_date`:
- `change_ticket`:

## Execution Context

- `operator`:
- `execution_date`:
- `branch_or_worktree`:
- `execution_mode`: `preview` / `apply`
- `result`: `pending`

## Scope Snapshot

- `candidate_count`: `{worklist_summary['candidate_count']}`
- `source`: `{worklist_summary['source']}`
- `quality_tier`: `{worklist_summary['quality_tier']}`
- `years`: `{years}`
- `projected_governed_total_after_apply`: `{preview_summary['projected_governed_total']}`
- `removal_size_bytes`: `{preview_summary['removal_size_bytes']}`

## Sample Paths

{sample_paths_text}

## Reference Artifacts

- `execution_plan`: `{execution_plan_path.as_posix()}`
- `worklist`: `knowledge-base/threat-intelligence/archive_worklists/{batch_id}.json`
- `patch_preview`: `knowledge-base/threat-intelligence/archive_patch_previews/{batch_id}.json`

## Execution Checklist

- [ ] Manifest verification completed before execution
- [ ] Lifecycle report refreshed before execution
- [ ] Archive worklist refreshed before execution
- [ ] Patch preview refreshed before execution
- [ ] Archive action script executed in clean worktree or disposable branch

## Validation Results

{validation_text}

## Observed Outputs

- `git diff summary`:
- `post-apply governed_total`:
- `post-apply unmanaged_local_feeds`:
- `post-apply archive_candidates`:

## Rollback

- `rollback_triggered`: `no`
- `rollback_reason`:
- `rollback_commands_executed`:

## Notes

- This record is a template. Fill it during the real archive execution.
- Regenerate it if the corresponding execution plan, worklist, or patch preview changes.
"""


def write_record(text: str, path: Path) -> None:
    path.write_text(text, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a reviewable execution record template for a threat-intel archive batch"
    )
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--write-record", action="store_true")
    parser.add_argument("--show-path", action="store_true")
    parser.add_argument("--record-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(CURATION_POLICY_PATH)
    worklist_path = default_worklist_path(args.batch_id, policy)
    preview_path = default_patch_preview_path(args.batch_id, policy)
    execution_plan_path = default_plan_path(args.batch_id, policy)
    worklist = load_json(worklist_path)
    preview = load_json(preview_path)
    record = build_execution_record(
        batch_id=args.batch_id,
        worklist=worklist,
        preview=preview,
        execution_plan_path=execution_plan_path,
    )
    record_path = args.record_path or default_record_path(args.batch_id, policy)
    if args.write_record:
        write_record(record, record_path)
        print(f"[OK] Wrote threat-intel archive execution record: {record_path}")
    if args.show_path:
        print(record_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
