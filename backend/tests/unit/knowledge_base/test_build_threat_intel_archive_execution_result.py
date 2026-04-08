from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = (
    REPO_ROOT / "knowledge-base" / "build_threat_intel_archive_execution_result.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_archive_execution_result", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_execution_result_marks_completed_when_counts_match() -> None:
    module = _load_module()
    result = module.build_execution_result(
        batch_id="phase-1-cisa-limited-historical",
        mode="apply",
        worklist={
            "summary": {"candidate_count": 0},
            "items": [
                {"cve_id": "CVE-2010-0001"},
                {"cve_id": "CVE-2011-0002"},
            ],
        },
        preview={"summary": {"projected_governed_total": 1755}},
        manifest={"summary": {"total_feeds": 1755}},
        lifecycle_report={
            "summary": {
                "archive_candidate_total": 56,
                "retained_historical_total": 1061,
            },
            "archive_candidates": [
                {"cve_id": "CVE-2012-9999"},
            ],
        },
    )

    assert result["completed"] is True
    assert result["mode"] == "apply"
    assert result["summary"]["remaining_candidate_count"] == 0
    assert result["summary"]["remaining_batch_candidate_count"] == 0
    assert result["summary"]["actual_governed_total"] == 1755
    assert result["consistency_issues"] == []


def test_build_execution_result_reports_unresolved_batch_targets_and_inconsistency() -> None:
    module = _load_module()
    result = module.build_execution_result(
        batch_id="phase-1-cisa-limited-historical",
        mode="apply",
        worklist={
            "summary": {"candidate_count": 0},
            "items": [
                {"cve_id": "CVE-2010-0001"},
                {"cve_id": "CVE-2011-0002"},
            ],
        },
        preview={"summary": {"projected_governed_total": 1755}},
        manifest={"summary": {"total_feeds": 1755}},
        lifecycle_report={
            "summary": {
                "archive_candidate_total": 57,
                "retained_historical_total": 1061,
            },
            "archive_candidates": [
                {"cve_id": "CVE-2011-0002"},
                {"cve_id": "CVE-2012-9999"},
            ],
        },
    )

    assert result["completed"] is False
    assert result["summary"]["targeted_candidate_count"] == 2
    assert result["summary"]["remaining_batch_candidate_count"] == 1
    assert result["summary"]["unresolved_batch_targets_preview"] == ["CVE-2011-0002"]
    assert result["summary"]["consistency_issue_count"] == 1
    assert "worklist candidate_count does not match unresolved lifecycle candidates" in result[
        "consistency_issues"
    ][0]


def test_default_result_path_uses_policy_output() -> None:
    module = _load_module()

    path = module.default_result_path(
        "phase-1-cisa-limited-historical",
        {
            "output": {
                "archive_execution_result_dir": "knowledge-base/threat-intelligence/archive_execution_results"
            }
        },
    )

    assert path.name == "phase-1-cisa-limited-historical.json"
