from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "plan_threat_intel_archive.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "plan_threat_intel_archive", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_archive_plan_groups_candidates_by_source_year_and_quality(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "build_lifecycle_report",
        lambda manifest_path, policy_path: {
            "archive_candidates": [
                {
                    "cve_id": "CVE-2010-0001",
                    "source": "CISA Known Exploited Vulnerabilities Catalog",
                    "year": "2010",
                    "quality_tier": "limited",
                },
                {
                    "cve_id": "CVE-2011-0002",
                    "source": "CISA Known Exploited Vulnerabilities Catalog",
                    "year": "2011",
                    "quality_tier": "limited",
                },
                {
                    "cve_id": "CVE-2012-0003",
                    "source": "NIST National Vulnerability Database (NVD)",
                    "year": "2012",
                    "quality_tier": "authoritative",
                },
            ]
        },
    )

    report = module.build_archive_plan()

    assert report["summary"]["archive_candidate_total"] == 3
    assert report["summary"]["by_source"] == {
        "CISA Known Exploited Vulnerabilities Catalog": 2,
        "NIST National Vulnerability Database (NVD)": 1,
    }
    assert report["summary"]["by_year"] == {"2010": 1, "2011": 1, "2012": 1}
    assert report["summary"]["by_quality"] == {"authoritative": 1, "limited": 2}
    assert report["action_groups"][0]["source"] == "CISA Known Exploited Vulnerabilities Catalog"
    assert report["action_groups"][0]["recommended_action"] == "Prioritize archive review for placeholder-heavy historical feeds"


def test_default_report_path_uses_policy_output(tmp_path: Path) -> None:
    module = _load_module()

    path = module.default_report_path(
        {"output": {"archive_plan_path": "knowledge-base/threat-intelligence/archive_plan.json"}}
    )

    assert path.name == "archive_plan.json"
