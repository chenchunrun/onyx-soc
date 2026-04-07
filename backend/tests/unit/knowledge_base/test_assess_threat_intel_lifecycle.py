from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "assess_threat_intel_lifecycle.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "assess_threat_intel_lifecycle", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_classify_governed_feed_marks_recent_authoritative_feed_active() -> None:
    module = _load_module()
    policy = {
        "quality_rules": {
            "authoritative_sources": ["NIST National Vulnerability Database (NVD)"],
            "required_fields": ["source", "retrieved_at", "title"],
            "limited_quality_markers": ["No description available."],
        },
        "lifecycle_rules": {
            "active_year_threshold": 2023,
            "archive_candidate_year_threshold": 2015,
            "archive_candidate_quality_tiers": ["authoritative", "standard", "limited"],
            "archive_exempt_sources": [],
            "archive_exempt_cve_ids": [],
        },
    }
    entry = {
        "cve_id": "CVE-2025-0001",
        "year": "2025",
        "source": "NIST National Vulnerability Database (NVD)",
        "retrieved_at": "2026-04-07",
        "title": "Example",
    }

    result = module.classify_governed_feed(entry, "Useful content", policy)

    assert result["quality_tier"] == "authoritative"
    assert result["lifecycle_state"] == "active"


def test_classify_governed_feed_marks_old_feed_as_archive_candidate() -> None:
    module = _load_module()
    policy = {
        "quality_rules": {
            "authoritative_sources": ["NIST National Vulnerability Database (NVD)"],
            "required_fields": ["source", "retrieved_at", "title"],
            "limited_quality_markers": ["No description available."],
        },
        "lifecycle_rules": {
            "active_year_threshold": 2023,
            "archive_candidate_year_threshold": 2015,
            "archive_candidate_quality_tiers": ["authoritative", "standard", "limited"],
            "archive_exempt_sources": [],
            "archive_exempt_cve_ids": [],
        },
    }
    entry = {
        "cve_id": "CVE-2010-0001",
        "year": "2010",
        "source": "NIST National Vulnerability Database (NVD)",
        "retrieved_at": "2026-04-07",
        "title": "Example",
    }

    result = module.classify_governed_feed(entry, "Useful content", policy)

    assert result["lifecycle_state"] == "archive_candidate"
    assert "older_than_threshold:2015" in result["lifecycle_reasons"]


def test_build_lifecycle_report_summarizes_quality_and_archive_counts(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    manifest_path = tmp_path / "feed_manifest.json"
    feed_dir = tmp_path / "knowledge-base" / "威胁情报" / "feeds"
    feed_dir.mkdir(parents=True)
    old_feed = feed_dir / "CVE_2010_0001.md"
    new_feed = feed_dir / "CVE_2025_0001.md"
    old_feed.write_text("# Old\n*Source: NIST National Vulnerability Database (NVD)*\n*Retrieved: 2026-04-07*\n", encoding="utf-8")
    new_feed.write_text("# New\n*Source: NIST National Vulnerability Database (NVD)*\n*Retrieved: 2026-04-07*\n", encoding="utf-8")
    manifest_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "path": str(old_feed.relative_to(tmp_path)).replace("\\", "/"),
                        "cve_id": "CVE-2010-0001",
                        "year": "2010",
                        "source": "NIST National Vulnerability Database (NVD)",
                        "retrieved_at": "2026-04-07",
                        "title": "Old",
                    },
                    {
                        "path": str(new_feed.relative_to(tmp_path)).replace("\\", "/"),
                        "cve_id": "CVE-2025-0001",
                        "year": "2025",
                        "source": "NIST National Vulnerability Database (NVD)",
                        "retrieved_at": "2026-04-07",
                        "title": "New",
                    },
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "curation_policy.yaml"
    policy_path.write_text(
        (
            "version: 1\n"
            "quality_rules:\n"
            "  authoritative_sources:\n"
            "    - NIST National Vulnerability Database (NVD)\n"
            "  required_fields:\n"
            "    - source\n"
            "    - retrieved_at\n"
            "    - title\n"
            "  limited_quality_markers:\n"
            "    - No description available.\n"
            "lifecycle_rules:\n"
            "  active_year_threshold: 2023\n"
            "  archive_candidate_year_threshold: 2015\n"
            "  archive_candidate_quality_tiers:\n"
            "    - authoritative\n"
            "    - standard\n"
            "    - limited\n"
            "  archive_exempt_sources: []\n"
            "  archive_exempt_cve_ids: []\n"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "ROOT", tmp_path / "knowledge-base")
    monkeypatch.setattr(module, "load_manifest", lambda path=manifest_path: json.loads(manifest_path.read_text(encoding="utf-8")))

    report = module.build_lifecycle_report(manifest_path, policy_path)

    assert report["summary"]["governed_total"] == 2
    assert report["summary"]["active_total"] == 1
    assert report["summary"]["archive_candidate_total"] == 1
    assert report["summary"]["quality_counts"] == {"authoritative": 2}

