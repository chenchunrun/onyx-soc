#!/usr/bin/env python3
"""Generate a runnable archive-action shell script from a patch preview."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from assess_threat_intel_lifecycle import CURATION_POLICY_PATH
from assess_threat_intel_lifecycle import load_policy
from build_threat_intel_archive_patch_preview import default_report_path
from build_threat_intel_archive_patch_preview import load_json

ROOT = MODULE_DIR


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def default_script_path(batch_id: str, policy: dict) -> Path:
    configured_dir = (policy.get("output", {}) or {}).get("archive_action_script_dir")
    if configured_dir:
        base_dir = ROOT.parent / configured_dir
    else:
        base_dir = ROOT / "threat-intelligence" / "archive_action_scripts"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / f"{batch_id}.sh"


def build_action_script(preview: dict) -> str:
    batch_id = str(preview["batch_id"])
    paths = [str(path) for path in preview.get("paths_to_remove", [])]
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        f"# Generated archive action script for {batch_id}",
        f"echo '[INFO] Applying archive batch: {batch_id}'",
        "",
    ]
    if paths:
        joined = " \\\n+  ".join(shell_quote(path) for path in paths)
        lines.extend(
            [
                "git rm \\",
                f"  {joined}",
                "",
            ]
        )
    lines.extend(
        [
            "python knowledge-base/build_threat_intel_manifest.py --write",
            "python knowledge-base/assess_threat_intel_lifecycle.py --write-report",
            f"python knowledge-base/build_threat_intel_archive_worklist.py --batch-id {batch_id} --write-report",
            f"python knowledge-base/build_threat_intel_archive_patch_preview.py --batch-id {batch_id} --write-report",
            "python knowledge-base/setup_security_threat_intel.py --verify --local-only",
            "",
            "echo '[OK] Archive batch script completed'",
            "",
        ]
    )
    return "\n".join(lines)


def write_script(script: str, path: Path) -> None:
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a runnable archive-action shell script from a patch preview"
    )
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--write-script", action="store_true")
    parser.add_argument("--show-path", action="store_true")
    parser.add_argument("--script-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(CURATION_POLICY_PATH)
    preview_path = default_report_path(args.batch_id, policy)
    preview = load_json(preview_path)
    script = build_action_script(preview)
    script_path = args.script_path or default_script_path(args.batch_id, policy)
    if args.write_script:
        write_script(script, script_path)
        print(f"[OK] Wrote threat-intel archive action script: {script_path}")
    if args.show_path:
        print(script_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
