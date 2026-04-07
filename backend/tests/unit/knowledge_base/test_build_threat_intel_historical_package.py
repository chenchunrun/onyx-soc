from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = (
    REPO_ROOT / "knowledge-base" / "build_threat_intel_historical_package.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_historical_package", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_package_manifest_summarizes_items() -> None:
    module = _load_module()
    worklist = {
        "batch_id": "phase-2-nvd-authoritative-historical",
        "description": "desc",
        "recommended_action": "archive",
        "items": [
            {
                "cve_id": "CVE-2011-1565",
                "title": "Example",
                "source": "NIST National Vulnerability Database (NVD)",
                "year": "2011",
                "quality_tier": "authoritative",
                "size_bytes": 123,
            },
            {
                "cve_id": "CVE-2011-1566",
                "title": "Example 2",
                "source": "NIST National Vulnerability Database (NVD)",
                "year": "2011",
                "quality_tier": "authoritative",
                "size_bytes": 100,
            },
        ],
    }

    manifest = module.build_package_manifest(worklist)

    assert manifest["summary"]["item_count"] == 2
    assert manifest["summary"]["total_size_bytes"] == 223
    assert manifest["summary"]["source_counts"] == {
        "NIST National Vulnerability Database (NVD)": 2
    }


def test_build_package_readme_contains_summary() -> None:
    module = _load_module()
    text = module.build_package_readme(
        {
            "batch_id": "phase-2-nvd-authoritative-historical",
            "description": "desc",
            "recommended_action": "archive",
            "summary": {
                "item_count": 2,
                "total_size_bytes": 223,
                "source_counts": {"NVD": 2},
                "year_counts": {"2011": 2},
                "quality_counts": {"authoritative": 2},
            },
            "entries": [
                {"cve_id": "CVE-2011-1565", "title": "Example"},
            ],
        }
    )

    assert "# Threat-Intel Historical Package" in text
    assert "`item_count`: `2`" in text
    assert "CVE-2011-1565" in text
