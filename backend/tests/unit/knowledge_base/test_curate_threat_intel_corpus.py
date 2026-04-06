from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "curate_threat_intel_corpus.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "curate_threat_intel_corpus", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_classify_unmanaged_feed_as_promotion_candidate() -> None:
    module = _load_module()
    policy = {
        "promotion_rules": {
            "allow_sources": ["NIST National Vulnerability Database (NVD)"],
            "require_fields": ["source", "retrieved_at", "title"],
            "reject_if_text_contains": ["No description available."],
        },
        "review_rules": {
            "low_quality_sources": ["CISA Known Exploited Vulnerabilities Catalog"],
            "low_quality_markers": ["No description available."],
        },
    }
    entry = {
        "source": "NIST National Vulnerability Database (NVD)",
        "retrieved_at": "2026-04-06",
        "title": "CVE-2024-1111: Example",
    }

    decision, reasons = module.classify_unmanaged_feed(entry, "Useful description", policy)

    assert decision == "promotion_candidate"
    assert reasons == []


def test_classify_unmanaged_feed_as_runtime_only_for_low_quality_placeholder() -> None:
    module = _load_module()
    policy = {
        "promotion_rules": {
            "allow_sources": ["NIST National Vulnerability Database (NVD)"],
            "require_fields": ["source", "retrieved_at", "title"],
            "reject_if_text_contains": ["No description available."],
        },
        "review_rules": {
            "low_quality_sources": ["CISA Known Exploited Vulnerabilities Catalog"],
            "low_quality_markers": ["No description available.", "*Last Updated: *"],
        },
    }
    entry = {
        "source": "CISA Known Exploited Vulnerabilities Catalog",
        "retrieved_at": "",
        "title": "CVE-2026-35616: N/A",
    }

    decision, reasons = module.classify_unmanaged_feed(entry, "No description available.\n*Last Updated: *", policy)

    assert decision == "keep_runtime_only"
    assert any(reason.startswith("source_not_promotable") for reason in reasons)


def test_has_unpromoted_candidates_true_when_report_contains_candidates() -> None:
    module = _load_module()

    result = module.has_unpromoted_candidates({"promotion_candidates": [{"cve_id": "CVE-2024-1111"}]})

    assert result is True
