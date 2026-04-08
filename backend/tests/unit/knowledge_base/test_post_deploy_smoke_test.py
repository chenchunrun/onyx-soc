from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "post_deploy_smoke_test.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("post_deploy_smoke_test", MODULE_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_load_deployment_profile_summary_reports_missing_required_env(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module()
    deployment_profiles_path = tmp_path / "deployment-profiles.yaml"
    deployment_profiles_path.write_text(
        (
            "profiles:\n"
            "  demo:\n"
            "    required_env:\n"
            "      - SECURITY_TOOLS_MOCK_SERVER_URL\n"
            "      - SECURITY_TOOLS_MOCK_API_KEY\n"
            "    expectations:\n"
            "      security_tools_profile: mock\n"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "DEPLOYMENT_PROFILES_PATH", deployment_profiles_path)
    monkeypatch.setenv("SECURITY_PLATFORM_DEPLOYMENT_PROFILE", "demo")
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_SERVER_URL", "http://localhost:9999")
    monkeypatch.delenv("SECURITY_TOOLS_MOCK_API_KEY", raising=False)

    summary = module.load_deployment_profile_summary()

    assert summary == {
        "deployment_profile": "demo",
        "expected_security_tools_profile": "mock",
        "required_env": [
            "SECURITY_TOOLS_MOCK_SERVER_URL",
            "SECURITY_TOOLS_MOCK_API_KEY",
        ],
        "missing_required_env": ["SECURITY_TOOLS_MOCK_API_KEY"],
    }


def test_expected_threat_intel_tool_server_url_uses_mock_env(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_SERVER_URL", "http://localhost:9999")

    result = module.expected_threat_intel_tool_server_url(
        {"expected_security_tools_profile": "mock"}
    )

    assert result == "http://localhost:9999"


def test_threat_intel_tool_runtime_summary_extracts_server_and_headers() -> None:
    module = _load_module()

    result = module.threat_intel_tool_runtime_summary(
        {
            "definition": {"servers": [{"url": "http://localhost:9999"}]},
            "custom_headers": [{"key": "x-apikey", "value": "secret"}],
        }
    )

    assert result == {
        "server_url": "http://localhost:9999",
        "header_keys": ["x-apikey"],
    }


def test_tool_response_has_failure_markers_detects_connection_refused() -> None:
    module = _load_module()

    assert (
        module.tool_response_has_failure_markers(
            "工具调用失败（威胁情报服务连接被拒绝）"
        )
        is True
    )


def test_tool_response_has_failure_markers_allows_successful_mock_summary() -> None:
    module = _load_module()

    assert (
        module.tool_response_has_failure_markers(
            "8.8.8.8 是 Google 公共 DNS 服务器，风险等级低。"
        )
        is False
    )


def test_persona_live_response_looks_valid_accepts_non_empty_reply() -> None:
    module = _load_module()

    assert module.persona_live_response_looks_valid("这里是漏洞评估结论：风险中等。") is True


def test_persona_live_response_looks_valid_rejects_empty_reply() -> None:
    module = _load_module()

    assert module.persona_live_response_looks_valid("   ") is False


def test_list_mock_tool_requests_returns_list(monkeypatch) -> None:
    module = _load_module()

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self):
            return [{"method": "GET", "path": "/ip_addresses/8.8.8.8"}]

    monkeypatch.setattr(module.requests, "get", lambda *args, **kwargs: _Response())

    result = module.list_mock_tool_requests("http://localhost:9999")

    assert result == [{"method": "GET", "path": "/ip_addresses/8.8.8.8"}]


def test_resolve_mock_server_observer_url_maps_host_docker_internal(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.delenv("SECURITY_TOOLS_MOCK_SERVER_OBSERVER_URL", raising=False)

    result = module.resolve_mock_server_observer_url("http://host.docker.internal:9999")

    assert result == "http://127.0.0.1:9999"


def test_resolve_mock_server_observer_url_prefers_explicit_env(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setenv("SECURITY_TOOLS_MOCK_SERVER_OBSERVER_URL", "http://localhost:19999")

    result = module.resolve_mock_server_observer_url("http://host.docker.internal:9999")

    assert result == "http://localhost:19999"


def test_main_returns_one_when_login_fails(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            url="http://example.com",
            email="security-admin@example.com",
            password="secret",
            json=False,
        ),
    )
    monkeypatch.setattr(module, "get_cookie", lambda *_args, **_kwargs: None)

    result = module.main()

    assert result == 1
    assert "[ERROR] Login failed. Check credentials." in capsys.readouterr().out


def test_main_json_returns_zero_for_successful_smoke(monkeypatch, capsys) -> None:
    module = _load_module()
    expected_result = {"ok": True, "summary": {"tool": "threat_intel_lookup"}}
    monkeypatch.setattr(
        module.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            url="http://example.com",
            email="security-admin@example.com",
            password="secret",
            json=True,
        ),
    )
    monkeypatch.setattr(module, "get_cookie", lambda *_args, **_kwargs: "cookie")
    monkeypatch.setattr(module, "run_smoke_test", lambda *_args, **_kwargs: expected_result)

    result = module.main()

    assert result == 0
    assert json.loads(capsys.readouterr().out) == expected_result


def test_main_human_returns_one_for_failed_smoke(monkeypatch) -> None:
    module = _load_module()
    expected_result = {"ok": False, "summary": {}, "failures": ["tool failed"]}
    printed: list[dict] = []

    monkeypatch.setattr(
        module.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            url="http://example.com",
            email="security-admin@example.com",
            password="secret",
            json=False,
        ),
    )
    monkeypatch.setattr(module, "get_cookie", lambda *_args, **_kwargs: "cookie")
    monkeypatch.setattr(module, "run_smoke_test", lambda *_args, **_kwargs: expected_result)
    monkeypatch.setattr(module, "print_human_result", lambda result: printed.append(result))

    result = module.main()

    assert result == 1
    assert printed == [expected_result]
