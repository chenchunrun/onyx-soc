from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "setup_security_document_set.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "setup_security_document_set", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_verify_document_set_returns_zero_when_present(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "get_document_set_by_name",
        lambda base_url, cookie, name: {
            "id": 5,
            "name": name,
            "cc_pair_summaries": [{"id": 9, "name": "安全知识文件源"}],
        },
    )
    monkeypatch.setattr(
        module,
        "get_connector_status_by_name",
        lambda base_url, cookie, name: {"cc_pair_id": 9},
    )

    result = module.verify_document_set("http://example.com", "cookie")
    output = capsys.readouterr().out

    assert result == 0
    assert "安全知识库: OK (id=5, cc_pair=9)" in output


def test_verify_document_set_returns_one_when_missing(capsys, monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "get_document_set_by_name",
        lambda base_url, cookie, name: None,
    )

    result = module.verify_document_set("http://example.com", "cookie")
    output = capsys.readouterr().out

    assert result == 1
    assert "安全知识库: MISSING" in output


def test_verify_document_set_returns_one_for_default_cc_pair(
    monkeypatch, capsys
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "get_document_set_by_name",
        lambda base_url, cookie, name: {
            "id": 5,
            "name": name,
            "cc_pair_summaries": [{"id": 1, "name": "DefaultCCPair"}],
        },
    )

    result = module.verify_document_set("http://example.com", "cookie")
    output = capsys.readouterr().out

    assert result == 1
    assert "INVALID (bound to DefaultCCPair)" in output


def test_ensure_document_set_dry_run_reports_create(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "get_document_set_by_name",
        lambda base_url, cookie, name: None,
    )
    monkeypatch.setattr(
        module,
        "get_connector_status_by_name",
        lambda base_url, cookie, name: None,
    )
    monkeypatch.setattr(module, "collect_markdown_files", lambda: [Path("a.md")])

    result = module.ensure_document_set("http://example.com", "cookie", dry_run=True)
    output = capsys.readouterr().out

    assert result == 0
    assert "Would create document set: 安全知识库" in output
    assert (
        "Would create file connector: 安全知识文件源 with 1 markdown files in 1 batch(es)"
        in output
    )


def test_chunk_markdown_files_splits_large_batches() -> None:
    module = _load_module()

    batches = module.chunk_markdown_files(
        [Path(f"doc-{index}.md") for index in range(module.MAX_FILES_PER_UPLOAD + 1)]
    )

    assert len(batches) == 2
    assert len(batches[0]) == module.MAX_FILES_PER_UPLOAD
    assert len(batches[1]) == 1


def test_ensure_document_set_creates_and_binds_real_connector(
    monkeypatch, capsys
) -> None:
    module = _load_module()
    document_set = {
        "id": 11,
        "name": module.SECURITY_DOCUMENT_SET_NAME,
        "description": module.SECURITY_DOCUMENT_SET_DESCRIPTION,
        "cc_pair_summaries": [],
        "is_public": True,
        "users": [],
        "groups": [],
        "federated_connector_summaries": [],
    }
    get_document_set_calls = {"count": 0}
    get_connector_calls = {"count": 0}

    def _get_document_set(base_url, cookie, name):
        get_document_set_calls["count"] += 1
        if get_document_set_calls["count"] == 1:
            return None
        return document_set

    monkeypatch.setattr(module, "get_document_set_by_name", _get_document_set)
    def _get_connector_status(base_url, cookie, name):
        get_connector_calls["count"] += 1
        if get_connector_calls["count"] == 1:
            return None
        return {"cc_pair_id": 22, "connector": {"id": 44}}

    monkeypatch.setattr(module, "get_connector_status_by_name", _get_connector_status)
    monkeypatch.setattr(module, "collect_markdown_files", lambda: [Path("a.md")])
    monkeypatch.setattr(module, "create_document_set", lambda base_url, cookie: 11)
    monkeypatch.setattr(
        module,
        "upload_markdown_files",
        lambda base_url, cookie, markdown_files: {
            "file_paths": ["fid-1"],
            "file_names": ["a.md"],
            "zip_metadata_file_id": None,
        },
    )
    monkeypatch.setattr(
        module,
        "create_security_connector",
        lambda base_url, cookie, upload_payload: 22,
    )
    captured_update: dict[str, object] = {}

    def _capture_update(base_url, cookie, loaded_document_set, cc_pair_id):
        captured_update["document_set"] = loaded_document_set
        captured_update["cc_pair_id"] = cc_pair_id

    monkeypatch.setattr(module, "update_document_set_bindings", _capture_update)

    result = module.ensure_document_set("http://example.com", "cookie", dry_run=False)
    output = capsys.readouterr().out

    assert result == 0
    assert "Created document set: 安全知识库 (id=11)" in output
    assert (
        "Created file connector: 安全知识文件源 (cc_pair_id=22, files=1, batches=1)"
        in output
    )
    assert (
        "Bound document set 安全知识库 to connector 安全知识文件源 (cc_pair_id=22)"
        in output
    )
    assert captured_update["document_set"] == document_set
    assert captured_update["cc_pair_id"] == 22


def test_ensure_document_set_refreshes_existing_connector_and_rebinds(
    monkeypatch, capsys
) -> None:
    module = _load_module()
    document_set = {
        "id": 11,
        "name": module.SECURITY_DOCUMENT_SET_NAME,
        "description": module.SECURITY_DOCUMENT_SET_DESCRIPTION,
        "cc_pair_summaries": [{"id": 1, "name": "DefaultCCPair"}],
        "is_public": True,
        "users": [],
        "groups": [],
        "federated_connector_summaries": [],
    }
    connector_status = {
        "cc_pair_id": 33,
        "connector": {"id": 44},
    }

    monkeypatch.setattr(
        module,
        "get_document_set_by_name",
        lambda base_url, cookie, name: document_set,
    )
    monkeypatch.setattr(
        module,
        "get_connector_status_by_name",
        lambda base_url, cookie, name: connector_status,
    )
    monkeypatch.setattr(
        module, "collect_markdown_files", lambda: [Path("a.md"), Path("b.md")]
    )
    monkeypatch.setattr(
        module,
        "list_connector_files",
        lambda base_url, cookie, connector_id: [
            {"file_id": "old-1"},
            {"file_id": "old-2"},
        ],
    )
    captured_replace: dict[str, object] = {}
    monkeypatch.setattr(
        module,
        "replace_connector_files",
        lambda base_url, cookie, connector_id, markdown_files, file_ids_to_remove: (
            captured_replace.update(
                {
                    "connector_id": connector_id,
                    "markdown_files": markdown_files,
                    "file_ids_to_remove": file_ids_to_remove,
                }
            )
        ),
    )
    captured_update: dict[str, object] = {}
    monkeypatch.setattr(
        module,
        "update_document_set_bindings",
        lambda base_url, cookie, loaded_document_set, cc_pair_id: captured_update.update(
            {"document_set": loaded_document_set, "cc_pair_id": cc_pair_id}
        ),
    )

    result = module.ensure_document_set("http://example.com", "cookie", dry_run=False)
    output = capsys.readouterr().out

    assert result == 0
    assert (
        "Refreshed file connector: 安全知识文件源 (cc_pair_id=33, files=2, batches=1)"
        in output
    )
    assert captured_replace["connector_id"] == 44
    assert captured_replace["file_ids_to_remove"] == ["old-1", "old-2"]
    assert captured_update["document_set"] == document_set
    assert captured_update["cc_pair_id"] == 33
