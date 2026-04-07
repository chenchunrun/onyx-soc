from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "build_threat_intel_archive_action_script.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_archive_action_script", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_action_script_contains_git_rm_and_followup_steps() -> None:
    module = _load_module()
    preview = {
        "batch_id": "phase-1-cisa-limited-historical",
        "paths_to_remove": [
            "knowledge-base/威胁情报/feeds/CVE_2010_0001.md",
            "knowledge-base/威胁情报/feeds/CVE_2011_0002.md",
        ],
    }

    script = module.build_action_script(preview)

    assert "git rm" in script
    assert 'ACTION_MODE="${ACTION_MODE:-preview}"' in script
    assert 'if [ "$ACTION_MODE" = "preview" ]; then' in script
    assert '$PYTHON_BIN knowledge-base/build_threat_intel_manifest.py --write' in script
    assert '$PYTHON_BIN knowledge-base/assess_threat_intel_lifecycle.py --write-report' in script
    assert '$PYTHON_BIN knowledge-base/build_threat_intel_archive_execution_result.py --batch-id phase-1-cisa-limited-historical --mode "$ACTION_MODE" --write-result --show-summary' in script
    assert '$PYTHON_BIN knowledge-base/setup_security_threat_intel.py --verify --local-only' in script
    assert "\n+  " not in script
    assert 'PYTHON_BIN="${PYTHON_BIN:-}"' in script


def test_default_script_path_uses_policy_output() -> None:
    module = _load_module()

    path = module.default_script_path(
        "phase-1-cisa-limited-historical",
        {"output": {"archive_action_script_dir": "knowledge-base/threat-intelligence/archive_action_scripts"}},
    )

    assert path.name == "phase-1-cisa-limited-historical.sh"
