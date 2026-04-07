from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = (
    REPO_ROOT / "knowledge-base" / "build_threat_intel_archive_execution_record.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_archive_execution_record", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_execution_record_contains_audit_sections() -> None:
    module = _load_module()
    worklist = {
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
        },
        "paths_to_remove": [
            "knowledge-base/威胁情报/feeds/CVE_2002_0367.md",
            "knowledge-base/威胁情报/feeds/CVE_2004_0210.md",
        ],
    }

    text = module.build_execution_record(
        batch_id="phase-1-cisa-limited-historical",
        worklist=worklist,
        preview=preview,
        execution_plan_path=Path(
            "knowledge-base/threat-intelligence/archive_execution_plans/phase-1-cisa-limited-historical.md"
        ),
        execution_result_path=Path(
            "knowledge-base/threat-intelligence/archive_execution_results/phase-1-cisa-limited-historical.json"
        ),
    )

    assert "# Threat-Intel Archive Execution Record" in text
    assert "## Approval" in text
    assert "## Execution Checklist" in text
    assert "## Validation Results" in text
    assert "## Rollback" in text
    assert "rollback_triggered" in text
    assert "execution_result" in text


def test_default_record_path_uses_policy_output() -> None:
    module = _load_module()

    path = module.default_record_path(
        "phase-1-cisa-limited-historical",
        {
            "output": {
                "archive_execution_record_dir": "knowledge-base/threat-intelligence/archive_execution_records"
            }
        },
    )

    assert path.name == "phase-1-cisa-limited-historical.md"
