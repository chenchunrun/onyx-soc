from __future__ import annotations

import importlib.util
from argparse import Namespace
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "setup_security_threat_intel.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "setup_security_threat_intel", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_selected_feeds_defaults_to_standard_profile() -> None:
    module = _load_module()

    result = module.selected_feeds(Namespace(feed=None))

    assert result == module.DEFAULT_FEEDS


def test_selected_profile_name_defaults_to_live() -> None:
    module = _load_module()

    result = module.selected_profile_name(Namespace())

    assert result == "live"


def test_semantic_identifier_for_feed_file_uses_threat_intel_suffix() -> None:
    module = _load_module()

    result = module.semantic_identifier_for_feed_file(Path("CVE_2024_1234.md"))

    assert result == "CVE-2024-1234_threat_intel"


def test_build_aggregator_command_uses_selected_feeds() -> None:
    module = _load_module()

    command = module.build_aggregator_command(
        Namespace(feed=["cisa_kev", "nvd_ics_advisories"])
    )

    assert command[1].endswith("threat_intel_aggregator.py")
    assert "--skip-onyx" in command
    assert command[-3:] == ["--fetch", "--feed", "nvd_ics_advisories"]


def test_dry_run_reports_discovered_files(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "discover_feed_files",
        lambda limit=None: [Path("one.md"), Path("two.md")],
    )
    monkeypatch.setattr(
        module,
        "semantic_identifier_for_feed_file",
        lambda path: f"id:{path.stem}",
    )

    result = module.dry_run(
        Namespace(limit=None, refresh=False, feed=None)
    )
    output = capsys.readouterr().out

    assert result == 0
    assert "Threat-intel files discovered: 2" in output
    assert "id:one" in output


def test_verify_threat_intel_local_only_passes_with_files(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "discover_feed_files",
        lambda limit=None: [Path("CVE_2024_1234.md")],
    )

    result = module.verify_threat_intel(
        Namespace(limit=None, local_only=True, url="http://example.com", email="a", password="b")
    )
    output = capsys.readouterr().out

    assert result == 0
    assert "Local verification only" in output


def test_verify_threat_intel_detects_missing_ingestion_docs(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "discover_feed_files",
        lambda limit=None: [Path("CVE_2024_1234.md")],
    )
    monkeypatch.setattr(module, "get_cookie", lambda *args, **kwargs: "cookie")
    monkeypatch.setattr(module, "list_ingestion_documents", lambda *args, **kwargs: [])

    result = module.verify_threat_intel(
        Namespace(limit=None, local_only=False, url="http://example.com", email="a", password="b")
    )
    output = capsys.readouterr().out

    assert result == 1
    assert "Missing threat-intel docs" in output


def test_due_feeds_marks_never_synced_feed_as_due() -> None:
    module = _load_module()

    result = module.due_feeds(
        {"feeds": [{"name": "cisa_kev", "min_refresh_interval_hours": 24}]},
        {"feeds": {}},
        datetime(2026, 4, 7, tzinfo=timezone.utc),
    )

    assert [feed["name"] for feed in result] == ["cisa_kev"]


def test_due_feeds_skips_recently_synced_feed() -> None:
    module = _load_module()

    result = module.due_feeds(
        {"feeds": [{"name": "cisa_kev", "min_refresh_interval_hours": 24}]},
        {"feeds": {"cisa_kev": {"last_success_at": "2026-04-06T20:00:00Z"}}},
        datetime(2026, 4, 7, 0, 0, tzinfo=timezone.utc),
    )

    assert result == []


def test_run_scheduled_sync_updates_state(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    state_path = tmp_path / "sync_state.json"
    state_path.write_text(json.dumps({"feeds": {}}), encoding="utf-8")
    monkeypatch.setattr(module, "SYNC_STATE_PATH", state_path)
    monkeypatch.setattr(
        module,
        "load_sync_plan",
        lambda: {"feeds": [{"name": "cisa_kev", "min_refresh_interval_hours": 24}]},
    )
    monkeypatch.setattr(
        module,
        "utc_now",
        lambda: datetime(2026, 4, 7, 0, 0, tzinfo=timezone.utc),
    )
    monkeypatch.setattr(
        module,
        "refresh_due_feeds",
        lambda args, due_feed_configs: (0, ["cisa_kev"]),
    )
    monkeypatch.setattr(module, "apply_threat_intel", lambda args: 0)
    monkeypatch.setattr(module, "selected_profile_name", lambda args: "live")
    monkeypatch.setattr(module, "selected_profile", lambda args: {"allow_upstream_refresh": True})

    result = module.run_scheduled_sync(
        Namespace(limit=None, url="http://example.com", email="a", password="b")
    )
    output = capsys.readouterr().out
    saved_state = json.loads(state_path.read_text(encoding="utf-8"))

    assert result == 0
    assert "Due feeds: cisa_kev" in output
    assert saved_state["feeds"]["cisa_kev"]["last_success_at"] == "2026-04-07T00:00:00Z"


def test_show_sync_plan_reports_due_status(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    state_path = tmp_path / "sync_state.json"
    state_path.write_text(
        json.dumps({"feeds": {"cisa_kev": {"last_success_at": "2026-04-05T00:00:00Z"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "SYNC_STATE_PATH", state_path)
    monkeypatch.setattr(
        module,
        "load_sync_plan",
        lambda: {"feeds": [{"name": "cisa_kev", "min_refresh_interval_hours": 24}]},
    )
    monkeypatch.setattr(
        module,
        "utc_now",
        lambda: datetime(2026, 4, 7, 0, 0, tzinfo=timezone.utc),
    )

    result = module.show_sync_plan()
    output = capsys.readouterr().out

    assert result == 0
    assert "Source profiles:" in output
    assert "status=DUE" in output


def test_refresh_local_feed_files_skips_upstream_in_mock_profile(
    monkeypatch, capsys
) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "selected_profile_name", lambda args: "mock")
    monkeypatch.setattr(module, "selected_profile", lambda args: {"allow_upstream_refresh": False})

    result = module.refresh_local_feed_files(Namespace(feed=None))
    output = capsys.readouterr().out

    assert result == 0
    assert "disables upstream refresh" in output


def test_run_scheduled_sync_skips_upstream_in_mock_profile(
    monkeypatch, tmp_path, capsys
) -> None:
    module = _load_module()
    state_path = tmp_path / "sync_state.json"
    state_path.write_text(json.dumps({"feeds": {}}), encoding="utf-8")
    monkeypatch.setattr(module, "SYNC_STATE_PATH", state_path)
    monkeypatch.setattr(
        module,
        "load_sync_plan",
        lambda: {"feeds": [{"name": "cisa_kev", "min_refresh_interval_hours": 24}]},
    )
    monkeypatch.setattr(
        module,
        "utc_now",
        lambda: datetime(2026, 4, 7, 0, 0, tzinfo=timezone.utc),
    )
    monkeypatch.setattr(module, "selected_profile_name", lambda args: "mock")
    monkeypatch.setattr(module, "selected_profile", lambda args: {"allow_upstream_refresh": False})
    monkeypatch.setattr(
        module,
        "refresh_due_feeds",
        lambda args, due_feed_configs: (_ for _ in ()).throw(
            AssertionError("refresh_due_feeds should not be called for mock profile")
        ),
    )
    monkeypatch.setattr(module, "apply_threat_intel", lambda args: 0)

    result = module.run_scheduled_sync(
        Namespace(limit=None, url="http://example.com", email="a", password="b")
    )
    output = capsys.readouterr().out

    assert result == 0
    assert "Source profile: mock" in output
    assert "Upstream refresh disabled" in output
