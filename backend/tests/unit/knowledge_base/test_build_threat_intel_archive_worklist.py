from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "build_threat_intel_archive_worklist.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_archive_worklist", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_worklist_filters_items_by_batch_source_quality_and_year() -> None:
    module = _load_module()
    batch = {
        "batch_id": "phase-1-cisa-limited-historical",
        "source": "CISA Known Exploited Vulnerabilities Catalog",
        "quality_tier": "limited",
        "years": ["2010", "2011"],
        "description": "test",
        "recommended_action": "review",
    }
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
                "cve_id": "CVE-2011-0003",
                "source": "NIST National Vulnerability Database (NVD)",
                "quality_tier": "authoritative",
                "year": "2011",
            },
        ]
    }

    report = module.build_worklist(batch, lifecycle_report)

    assert report["summary"]["candidate_count"] == 2
    assert [item["cve_id"] for item in report["items"]] == [
        "CVE-2010-0001",
        "CVE-2011-0002",
    ]


def test_default_worklist_path_uses_policy_output(tmp_path: Path) -> None:
    module = _load_module()

    path = module.default_worklist_path(
        "phase-1-cisa-limited-historical",
        {"output": {"archive_worklist_dir": "knowledge-base/threat-intelligence/archive_worklists"}},
    )

    assert path.name == "phase-1-cisa-limited-historical.json"
