#!/usr/bin/env python3
"""Generate the full archive artifact chain for a threat-intel batch."""

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
from build_threat_intel_archive_action_script import (
    build_action_script,
    default_script_path,
    write_script,
)
from build_threat_intel_archive_execution_plan import (
    build_execution_plan,
    default_plan_path,
    write_plan,
)
from build_threat_intel_archive_execution_record import (
    build_execution_record,
    default_record_path,
    write_record,
)
from build_threat_intel_archive_patch_preview import (
    build_patch_preview,
    default_report_path as default_patch_preview_path,
    load_manifest,
    write_report,
)
from build_threat_intel_archive_worklist import (
    build_worklist,
    default_worklist_path,
    load_batch,
    load_json,
    write_worklist,
)

ROOT = MODULE_DIR
LIFECYCLE_REPORT_PATH = ROOT / "threat-intelligence" / "lifecycle_report.json"


def generate_batch_artifacts(batch_id: str) -> dict[str, Path]:
    policy = load_policy(CURATION_POLICY_PATH)
    batch = load_batch(batch_id)
    lifecycle_report = load_json(LIFECYCLE_REPORT_PATH)
    manifest = load_manifest()

    worklist = build_worklist(batch, lifecycle_report)
    worklist_path = default_worklist_path(batch_id, policy)
    write_worklist(worklist, worklist_path)

    preview = build_patch_preview(worklist, manifest)
    preview_path = default_patch_preview_path(batch_id, policy)
    write_report(preview, preview_path)

    action_script = build_action_script(preview)
    action_script_path = default_script_path(batch_id, policy)
    write_script(action_script, action_script_path)

    execution_plan = build_execution_plan(
        batch_id=batch_id,
        worklist=worklist,
        preview=preview,
        action_script_path=action_script_path,
    )
    execution_plan_path = default_plan_path(batch_id, policy)
    write_plan(execution_plan, execution_plan_path)

    execution_record = build_execution_record(
        batch_id=batch_id,
        worklist=worklist,
        preview=preview,
        execution_plan_path=execution_plan_path,
        execution_result_path=ROOT
        / "threat-intelligence"
        / "archive_execution_results"
        / f"{batch_id}.json",
    )
    execution_record_path = default_record_path(batch_id, policy)
    write_record(execution_record, execution_record_path)

    return {
        "worklist": worklist_path,
        "patch_preview": preview_path,
        "action_script": action_script_path,
        "execution_plan": execution_plan_path,
        "execution_record": execution_record_path,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the full archive artifact chain for a threat-intel batch"
    )
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--show-paths", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = generate_batch_artifacts(args.batch_id)
    print(f"[OK] Generated archive artifacts for batch: {args.batch_id}")
    if args.show_paths:
        for label, path in paths.items():
            print(f"{label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
