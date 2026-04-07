from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = (
    REPO_ROOT / "knowledge-base" / "build_threat_intel_historical_package_index.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_historical_package_index", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_index_summarizes_packages() -> None:
    module = _load_module()
    index_doc = module.build_index(
        [
            {
                "batch_id": "phase-1",
                "item_count": 147,
                "total_size_bytes": 100,
            },
            {
                "batch_id": "phase-2",
                "item_count": 56,
                "total_size_bytes": 50,
            },
        ]
    )

    assert index_doc["summary"]["package_count"] == 2
    assert index_doc["summary"]["total_item_count"] == 203
    assert index_doc["summary"]["total_size_bytes"] == 150


def test_build_catalog_readme_lists_packages() -> None:
    module = _load_module()
    text = module.build_catalog_readme(
        {
            "summary": {
                "package_count": 2,
                "total_item_count": 203,
                "total_size_bytes": 150,
            },
            "packages": [
                {
                    "batch_id": "phase-1",
                    "description": "desc",
                    "item_count": 147,
                    "manifest_path": "a/manifest.json",
                    "readme_path": "a/README.md",
                }
            ],
        }
    )

    assert "# Threat-Intel Historical Package Catalog" in text
    assert "`package_count`: `2`" in text
    assert "### `phase-1`" in text
