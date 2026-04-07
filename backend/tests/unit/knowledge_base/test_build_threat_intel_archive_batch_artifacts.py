from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = (
    REPO_ROOT / "knowledge-base" / "build_threat_intel_archive_batch_artifacts.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "build_threat_intel_archive_batch_artifacts", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_generate_batch_artifacts_returns_expected_labels(monkeypatch) -> None:
    module = _load_module()
    calls: list[str] = []

    monkeypatch.setattr(module, "load_policy", lambda _path: {})
    monkeypatch.setattr(
        module,
        "load_batch",
        lambda batch_id: {
            "batch_id": batch_id,
            "description": "desc",
            "recommended_action": "act",
            "source": "src",
            "quality_tier": "limited",
            "years": ["2010"],
        },
    )
    monkeypatch.setattr(module, "load_json", lambda _path: {"summary": {}, "archive_candidates": []})
    monkeypatch.setattr(module, "load_manifest", lambda: {"entries": [], "summary": {}})
    monkeypatch.setattr(
        module,
        "build_worklist",
        lambda batch, lifecycle: {"batch_id": batch["batch_id"], "summary": {"candidate_count": 0, "source": "src", "quality_tier": "limited", "years": ["2010"]}},
    )
    monkeypatch.setattr(module, "build_patch_preview", lambda worklist, manifest: {"batch_id": worklist["batch_id"], "summary": {"projected_governed_total": 0, "removal_size_bytes": 0}, "paths_to_remove": []})
    monkeypatch.setattr(module, "build_action_script", lambda preview: "#!/usr/bin/env bash\n")
    monkeypatch.setattr(module, "build_execution_plan", lambda **kwargs: "plan")
    monkeypatch.setattr(module, "build_execution_record", lambda **kwargs: "record")

    def _writer(name):
        def inner(*args, **kwargs):
            calls.append(name)
        return inner

    monkeypatch.setattr(module, "write_worklist", _writer("worklist"))
    monkeypatch.setattr(module, "write_report", _writer("patch_preview"))
    monkeypatch.setattr(module, "write_script", _writer("action_script"))
    monkeypatch.setattr(module, "write_plan", _writer("execution_plan"))
    monkeypatch.setattr(module, "write_record", _writer("execution_record"))

    monkeypatch.setattr(module, "default_worklist_path", lambda batch_id, policy: Path(f"/tmp/{batch_id}.worklist.json"))
    monkeypatch.setattr(module, "default_patch_preview_path", lambda batch_id, policy: Path(f"/tmp/{batch_id}.preview.json"))
    monkeypatch.setattr(module, "default_script_path", lambda batch_id, policy: Path(f"/tmp/{batch_id}.sh"))
    monkeypatch.setattr(module, "default_plan_path", lambda batch_id, policy: Path(f"/tmp/{batch_id}.plan.md"))
    monkeypatch.setattr(module, "default_record_path", lambda batch_id, policy: Path(f"/tmp/{batch_id}.record.md"))

    paths = module.generate_batch_artifacts("phase-2-nvd-authoritative-historical")

    assert set(paths.keys()) == {
        "worklist",
        "patch_preview",
        "action_script",
        "execution_plan",
        "execution_record",
    }
    assert calls == [
        "worklist",
        "patch_preview",
        "action_script",
        "execution_plan",
        "execution_record",
    ]
