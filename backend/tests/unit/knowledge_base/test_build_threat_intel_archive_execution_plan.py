from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = (
    REPO_ROOT / "knowledge-base" / "build_threat_intel_archive_execution_plan.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_archive_execution_plan", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_execution_plan_contains_execution_and_rollback_steps() -> None:
    module = _load_module()
    worklist = {
        "batch_id": "phase-1-cisa-limited-historical",
        "description": "Archive old limited CISA entries",
        "recommended_action": "Review and remove from governed corpus",
        "summary": {
            "candidate_count": 147,
            "source": "CISA Known Exploited Vulnerabilities Catalog",
            "quality_tier": "limited",
            "years": ["2002", "2004"],
        },
    }
    preview = {
        "summary": {
            "projected_governed_total": 1755,
            "removal_size_bytes": 2048,
            "removed_source_counts": {
                "CISA Known Exploited Vulnerabilities Catalog": 147
            },
            "projected_source_counts": {
                "CISA Known Exploited Vulnerabilities Catalog": 1406,
                "NIST National Vulnerability Database (NVD)": 349,
            },
        },
        "paths_to_remove": [
            "knowledge-base/威胁情报/feeds/CVE_2002_0367.md",
            "knowledge-base/威胁情报/feeds/CVE_2004_0210.md",
        ],
    }

    text = module.build_execution_plan(
        batch_id="phase-1-cisa-limited-historical",
        worklist=worklist,
        preview=preview,
        action_script_path=Path(
            "knowledge-base/threat-intelligence/archive_action_scripts/phase-1-cisa-limited-historical.sh"
        ),
    )

    assert "# Threat-Intel Archive Execution Plan" in text
    assert "## Preconditions" in text
    assert "## Execution Steps" in text
    assert "## Rollback" in text
    assert "git reset --hard HEAD" in text
    assert "build_threat_intel_manifest.py --verify" in text
    assert "phase-1-cisa-limited-historical.sh" in text


def test_default_plan_path_uses_policy_output() -> None:
    module = _load_module()

    path = module.default_plan_path(
        "phase-1-cisa-limited-historical",
        {
            "output": {
                "archive_execution_plan_dir": "knowledge-base/threat-intelligence/archive_execution_plans"
            }
        },
    )

    assert path.name == "phase-1-cisa-limited-historical.md"
