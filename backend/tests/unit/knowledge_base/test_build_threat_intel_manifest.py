from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "build_threat_intel_manifest.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_manifest", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_manifest_summarizes_governed_feed_files(monkeypatch, tmp_path) -> None:
    module = _load_module()
    feed_a = tmp_path / "CVE_2024_1111.md"
    feed_a.write_text(
        "# CVE-2024-1111: Example\n\n*Source: CISA Known Exploited Vulnerabilities Catalog*\n*Last Updated: 2026-04-06*\n",
        encoding="utf-8",
    )
    feed_b = tmp_path / "CVE_2023_2222.md"
    feed_b.write_text(
        "# CVE-2023-2222: Example\n\n*Source: NIST National Vulnerability Database (NVD)*\n*Retrieved: 2026-04-05*\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(module, "discover_feed_files", lambda tracked_only=True: [feed_a, feed_b])
    monkeypatch.setattr(module, "normalize_relative_path", lambda path: path.name)

    manifest = module.build_manifest(tracked_only=True)

    assert manifest["managed_scope"] == "git_tracked"
    assert manifest["summary"]["total_feeds"] == 2
    assert manifest["summary"]["source_counts"] == {
        "CISA Known Exploited Vulnerabilities Catalog": 1,
        "NIST National Vulnerability Database (NVD)": 1,
    }
    assert manifest["summary"]["year_counts"] == {"2023": 1, "2024": 1}


def test_compare_manifests_detects_entry_drift() -> None:
    module = _load_module()
    expected = {
        "manifest_version": 1,
        "managed_scope": "git_tracked",
        "feeds_dir": "knowledge-base/威胁情报/feeds",
        "summary": {"total_feeds": 1},
        "entries": [
            {
                "path": "knowledge-base/威胁情报/feeds/CVE_2024_1111.md",
                "sha256": "old",
                "size_bytes": 100,
                "source": "CISA",
                "retrieved_at": "2026-04-06",
                "title": "A",
            }
        ],
    }
    actual = {
        "manifest_version": 1,
        "managed_scope": "git_tracked",
        "feeds_dir": "knowledge-base/威胁情报/feeds",
        "summary": {"total_feeds": 1},
        "entries": [
            {
                "path": "knowledge-base/威胁情报/feeds/CVE_2024_1111.md",
                "sha256": "new",
                "size_bytes": 100,
                "source": "CISA",
                "retrieved_at": "2026-04-06",
                "title": "A",
            }
        ],
    }

    mismatches = module.compare_manifests(expected, actual)

    assert len(mismatches) == 1
    assert "field sha256" in mismatches[0]


def test_unmanaged_local_feed_paths_reports_extra_local_assets(monkeypatch) -> None:
    module = _load_module()
    manifest = {
        "entries": [
            {"path": "knowledge-base/威胁情报/feeds/CVE_2024_1111.md"},
        ]
    }
    monkeypatch.setattr(
        module,
        "discover_feed_files",
        lambda tracked_only=False: [
            Path("knowledge-base/威胁情报/feeds/CVE_2024_1111.md"),
            Path("knowledge-base/威胁情报/feeds/CVE_2024_2222.md"),
        ],
    )
    monkeypatch.setattr(module, "normalize_relative_path", lambda path: str(path))

    unmanaged = module.unmanaged_local_feed_paths(manifest)

    assert unmanaged == ["knowledge-base/威胁情报/feeds/CVE_2024_2222.md"]


def test_git_tracked_feed_paths_excludes_manifest_runtime_only_paths(monkeypatch) -> None:
    module = _load_module()
    tracked_output = "\n".join(
        [
            "knowledge-base/威胁情报/feeds/CVE_2024_1111.md",
            "knowledge-base/威胁情报/feeds/CVE_2026_35616.md",
        ]
    )

    class Completed:
        returncode = 0
        stdout = tracked_output
        stderr = ""

    monkeypatch.setattr(module, "load_manifest_exclude_paths", lambda path=module.CURATION_POLICY_PATH: {"knowledge-base/威胁情报/feeds/CVE_2026_35616.md"})
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: Completed())

    paths = module.git_tracked_feed_paths()

    assert [module.normalize_relative_path(path) for path in paths] == [
        "knowledge-base/威胁情报/feeds/CVE_2024_1111.md"
    ]
