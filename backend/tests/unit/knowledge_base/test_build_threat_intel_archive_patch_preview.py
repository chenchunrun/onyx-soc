from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "build_threat_intel_archive_patch_preview.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_archive_patch_preview", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_patch_preview_projects_manifest_after_removal() -> None:
    module = _load_module()
    worklist = {
        "batch_id": "phase-1-cisa-limited-historical",
        "items": [
            {
                "path": "knowledge-base/威胁情报/feeds/CVE_2010_0001.md",
                "source": "CISA Known Exploited Vulnerabilities Catalog",
                "year": "2010",
                "size_bytes": 100,
            },
            {
                "path": "knowledge-base/威胁情报/feeds/CVE_2011_0002.md",
                "source": "CISA Known Exploited Vulnerabilities Catalog",
                "year": "2011",
                "size_bytes": 120,
            },
        ],
    }
    manifest = {
        "entries": [
            {
                "path": "knowledge-base/威胁情报/feeds/CVE_2010_0001.md",
                "source": "CISA Known Exploited Vulnerabilities Catalog",
                "year": "2010",
            },
            {
                "path": "knowledge-base/威胁情报/feeds/CVE_2011_0002.md",
                "source": "CISA Known Exploited Vulnerabilities Catalog",
                "year": "2011",
            },
            {
                "path": "knowledge-base/威胁情报/feeds/CVE_2012_0003.md",
                "source": "NIST National Vulnerability Database (NVD)",
                "year": "2012",
            },
        ]
    }

    report = module.build_patch_preview(worklist, manifest)

    assert report["summary"]["removal_candidate_count"] == 2
    assert report["summary"]["removal_size_bytes"] == 220
    assert report["summary"]["projected_governed_total"] == 1
    assert report["summary"]["removed_source_counts"] == {
        "CISA Known Exploited Vulnerabilities Catalog": 2
    }
    assert report["summary"]["projected_source_counts"] == {
        "NIST National Vulnerability Database (NVD)": 1
    }


def test_default_report_path_uses_policy_output() -> None:
    module = _load_module()

    path = module.default_report_path(
        "phase-1-cisa-limited-historical",
        {"output": {"archive_patch_preview_dir": "knowledge-base/threat-intelligence/archive_patch_previews"}},
    )

    assert path.name == "phase-1-cisa-limited-historical.json"
