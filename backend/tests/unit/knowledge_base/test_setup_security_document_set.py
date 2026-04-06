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
        lambda base_url, cookie, name: {"id": 5, "name": name},
    )

    result = module.verify_document_set("http://example.com", "cookie")
    output = capsys.readouterr().out

    assert result == 0
    assert "安全知识库: OK (id=5)" in output


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


def test_ensure_document_set_dry_run_reports_create(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "get_document_set_by_name",
        lambda base_url, cookie, name: None,
    )

    result = module.ensure_document_set("http://example.com", "cookie", dry_run=True)
    output = capsys.readouterr().out

    assert result == 0
    assert "Would create document set: 安全知识库" in output


def test_ensure_document_set_creates_when_missing(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "get_document_set_by_name",
        lambda base_url, cookie, name: None,
    )
    monkeypatch.setattr(module, "create_document_set", lambda base_url, cookie: 11)

    result = module.ensure_document_set("http://example.com", "cookie", dry_run=False)
    output = capsys.readouterr().out

    assert result == 0
    assert "Created document set: 安全知识库 (id=11)" in output
