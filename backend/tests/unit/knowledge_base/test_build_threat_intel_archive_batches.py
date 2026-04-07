from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "build_threat_intel_archive_batches.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_archive_batches", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_archive_batches_creates_phase_batches() -> None:
    module = _load_module()
    lifecycle_report = {
        "archive_candidates": [
            {
                "cve_id": "CVE-2010-0001",
                "source": "CISA Known Exploited Vulnerabilities Catalog",
                "quality_tier": "limited",
                "year": "2010",
            },
            {
                "cve_id": "CVE-2011-0002",
                "source": "CISA Known Exploited Vulnerabilities Catalog",
                "quality_tier": "limited",
                "year": "2011",
            },
            {
                "cve_id": "CVE-2012-0003",
                "source": "NIST National Vulnerability Database (NVD)",
                "quality_tier": "authoritative",
                "year": "2012",
            },
        ]
    }
    archive_plan = {"summary": {"archive_candidate_total": 3}}

    result = module.build_archive_batches(lifecycle_report, archive_plan)

    assert result["summary"]["batch_count"] == 2
    assert result["batches"][0]["batch_id"] == "phase-1-cisa-limited-historical"
    assert result["batches"][0]["candidate_count"] == 2
    assert result["batches"][1]["batch_id"] == "phase-2-nvd-authoritative-historical"
    assert result["batches"][1]["candidate_count"] == 1


def test_default_report_path_reads_policy_output() -> None:
    module = _load_module()

    path = module.default_report_path(
        {"output": {"archive_batches_path": "knowledge-base/threat-intelligence/archive_batches.json"}}
    )

    assert path.name == "archive_batches.json"
