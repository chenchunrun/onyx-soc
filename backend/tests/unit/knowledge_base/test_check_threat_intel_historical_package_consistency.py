from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = (
    REPO_ROOT
    / "knowledge-base"
    / "check_threat_intel_historical_package_consistency.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "check_threat_intel_historical_package_consistency", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_evaluate_catalog_consistency_ok(tmp_path, monkeypatch) -> None:
    module = _load_module()
    package_root = tmp_path / "historical_packages"
    package_root.mkdir()
    package_dir = package_root / "phase-1"
    package_dir.mkdir()
    (package_dir / "manifest.json").write_text(
        (
            "{"
            '"batch_id":"phase-1",'
            '"summary":{"item_count":2,"total_size_bytes":10,"source_counts":{"CISA":2},"year_counts":{"2014":2},"quality_counts":{"limited":2}}'
            "}"
        ),
        encoding="utf-8",
    )
    (package_dir / "README.md").write_text(
        "# Threat-Intel Historical Package\n\nphase-1\n2\n", encoding="utf-8"
    )
    index_path = package_root / "index.json"
    repo_manifest = "knowledge-base/threat-intelligence/historical_packages/phase-1/manifest.json"
    repo_readme = "knowledge-base/threat-intelligence/historical_packages/phase-1/README.md"
    index_path.write_text(
        (
            "{"
            f'"packages":[{{"batch_id":"phase-1","item_count":2,"total_size_bytes":10,"manifest_path":"{repo_manifest}","readme_path":"{repo_readme}","source_counts":{{"CISA":2}},"year_counts":{{"2014":2}},"quality_counts":{{"limited":2}}}}],'
            '"summary":{"package_count":1,"total_item_count":2,"total_size_bytes":10}'
            "}"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "load_policy", lambda path: {})
    monkeypatch.setattr(module, "historical_package_root", lambda policy: package_root)
    monkeypatch.setattr(module, "default_index_path", lambda policy: index_path)
    monkeypatch.setattr(module, "_to_repo_path", lambda value: package_root / "phase-1" / Path(value).name)

    result = module.evaluate_catalog_consistency()

    assert result["ok"] is True
    assert result["summary"]["consistent_package_count"] == 1
    assert result["issues"] == []


def test_evaluate_catalog_consistency_detects_drift(tmp_path, monkeypatch) -> None:
    module = _load_module()
    package_root = tmp_path / "historical_packages"
    package_root.mkdir()
    package_dir = package_root / "phase-1"
    package_dir.mkdir()
    (package_dir / "manifest.json").write_text(
        '{"batch_id":"phase-x","summary":{"item_count":1,"total_size_bytes":10,"source_counts":{},"year_counts":{},"quality_counts":{}}}',
        encoding="utf-8",
    )
    (package_dir / "README.md").write_text("# no useful data\n", encoding="utf-8")
    index_path = package_root / "index.json"
    repo_manifest = "knowledge-base/threat-intelligence/historical_packages/phase-1/manifest.json"
    repo_readme = "knowledge-base/threat-intelligence/historical_packages/phase-1/README.md"
    index_path.write_text(
        (
            "{"
            f'"packages":[{{"batch_id":"phase-1","item_count":2,"total_size_bytes":10,"manifest_path":"{repo_manifest}","readme_path":"{repo_readme}","source_counts":{{}},"year_counts":{{}},"quality_counts":{{}}}}],'
            '"summary":{"package_count":1,"total_item_count":2,"total_size_bytes":10}'
            "}"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "load_policy", lambda path: {})
    monkeypatch.setattr(module, "historical_package_root", lambda policy: package_root)
    monkeypatch.setattr(module, "default_index_path", lambda policy: index_path)
    monkeypatch.setattr(module, "_to_repo_path", lambda value: package_root / "phase-1" / Path(value).name)

    result = module.evaluate_catalog_consistency()

    assert result["ok"] is False
    assert any("Manifest batch_id mismatch" in issue for issue in result["issues"])
    assert any("README does not mention batch_id" in issue for issue in result["issues"])
