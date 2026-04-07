from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / 'knowledge-base' / 'export_security_platform_snapshot.py'


def _load_module():
    spec = importlib.util.spec_from_file_location(
        'export_security_platform_snapshot', MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_snapshot_contains_expected_sections(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        'load_manifest',
        lambda path: {'summary': {'total_feeds': 1902}},
    )
    monkeypatch.setattr(
        module,
        'build_unmanaged_report',
        lambda path: {
            'summary': {
                'unmanaged_total': 1,
                'promotion_candidate_total': 0,
                'manual_review_total': 0,
                'keep_runtime_only_total': 1,
            }
        },
    )
    monkeypatch.setattr(
        module,
        'load_playbook_definitions_summary',
        lambda: {
            'count': 2,
            'playbooks_with_examples': ['a', 'b'],
        },
    )
    monkeypatch.setattr(
        module,
        '_playbook_catalog',
        lambda: [
            {'name': 'a', 'display_name': 'A', 'step_count': 4},
            {'name': 'b', 'display_name': 'B', 'step_count': 6},
        ],
    )
    monkeypatch.setattr(
        module,
        'load_threat_intel_sync_summary',
        lambda: {
            'source_profile': 'mock',
            'last_sync_run_at': '2026-04-07T00:00:00Z',
            'due_status': 'WAIT',
            'due_feeds': [],
        },
    )
    monkeypatch.setattr(
        module,
        'load_historical_package_summary',
        lambda: {
            'package_count': 2,
            'total_item_count': 203,
            'total_size_bytes': 242152,
            'package_ids': [
                'phase-1-cisa-limited-historical',
                'phase-2-nvd-authoritative-historical',
            ],
        },
    )

    snapshot = module.build_snapshot()

    assert snapshot['threat_intel_sync']['source_profile'] == 'mock'
    assert snapshot['threat_intel_corpus']['governed'] == 1902
    assert snapshot['historical_packages']['package_count'] == 2
    assert snapshot['historical_packages']['total_item_count'] == 203
    assert snapshot['historical_packages']['package_ids'] == [
        'phase-1-cisa-limited-historical',
        'phase-2-nvd-authoritative-historical',
    ]
    assert snapshot['playbooks']['count'] == 2
    assert snapshot['playbooks']['with_examples'] == 2
    assert snapshot['playbooks']['items'][0]['name'] == 'a'
