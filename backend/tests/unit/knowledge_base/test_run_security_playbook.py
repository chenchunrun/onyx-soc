from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[4] / "knowledge-base" / "run_security_playbook.py"
)
spec = importlib.util.spec_from_file_location("run_security_playbook", MODULE_PATH)
assert spec and spec.loader
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@pytest.fixture()
def sample_playbook() -> dict[str, Any]:
    return {
        "name": "test-playbook",
        "inputs": [
            {"name": "incident_ip", "required": True},
            {"name": "asset_hostname", "required": True},
        ],
        "steps": [
            {
                "id": "lookup_intel",
                "persona": "安全事件分析师",
                "tool": "threat_intel_lookup",
                "prompt": "查询 {{inputs.incident_ip}}",
            },
            {
                "id": "summary",
                "persona": "应急响应指挥官",
                "prompt": "总结 {{steps.lookup_intel.full_message}}",
            },
        ],
    }


def test_parse_inputs_rejects_invalid_value() -> None:
    with pytest.raises(ValueError, match="Expected key=value"):
        runner.parse_inputs(["incident_ip"])


def test_render_template_supports_inputs_and_step_outputs() -> None:
    rendered = runner.render_template(
        "IP={{inputs.incident_ip}} msg={{steps.lookup.full_message}}",
        {
            "inputs": {"incident_ip": "8.8.8.8"},
            "steps": {"lookup": {"full_message": "intel-hit"}},
        },
    )

    assert rendered == "IP=8.8.8.8 msg=intel-hit"


def test_validate_playbook_detects_duplicate_step_ids() -> None:
    errors = runner.validate_playbook(
        {
            "name": "dup-playbook",
            "steps": [
                {"id": "same", "persona": "A", "prompt": "one"},
                {"id": "same", "persona": "B", "prompt": "two"},
            ],
        }
    )

    assert "Duplicate step id: same" in errors


def test_validate_playbook_rejects_invalid_mock_llm_response_json() -> None:
    errors = runner.validate_playbook(
        {
            "name": "bad-mock-playbook",
            "steps": [
                {
                    "id": "same",
                    "persona": "A",
                    "prompt": "one",
                    "mock_llm_response": "{bad-json",
                },
            ],
        }
    )

    assert "Step same has invalid mock_llm_response JSON" in errors


def test_validate_playbook_rejects_template_step_without_response_template() -> None:
    errors = runner.validate_playbook(
        {
            "name": "bad-template-playbook",
            "steps": [
                {
                    "id": "summary",
                    "persona": "应急响应指挥官",
                    "execution_mode": "template",
                },
            ],
        }
    )

    assert (
        "Step summary with execution_mode=template missing response_template"
        in errors
    )


def test_validate_playbook_rejects_unknown_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "load_declared_tool_bindings", lambda: {})

    errors = runner.validate_playbook(
        {
            "name": "bad-tool-playbook",
            "steps": [
                {
                    "id": "lookup",
                    "persona": "安全事件分析师",
                    "tool": "not_a_real_tool",
                    "execution_mode": "direct",
                    "tool_args": {"ioc": "8.8.8.8"},
                    "prompt": "查询",
                }
            ],
        }
    )

    assert "Step lookup references unknown tool not_a_real_tool" in errors


def test_validate_playbook_rejects_tool_not_bound_to_persona(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner,
        "load_declared_tool_bindings",
        lambda: {"send_security_alert": {"应急响应指挥官"}},
    )

    errors = runner.validate_playbook(
        {
            "name": "bad-binding-playbook",
            "steps": [
                {
                    "id": "alert",
                    "persona": "安全事件分析师",
                    "tool": "send_security_alert",
                    "execution_mode": "direct",
                    "tool_args": {"title": "test"},
                    "prompt": "发送告警",
                }
            ],
        }
    )

    assert (
        "Step alert uses tool send_security_alert not bound to persona 安全事件分析师"
        in errors
    )


def test_validate_playbook_rejects_future_step_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner,
        "load_declared_tool_bindings",
        lambda: {"threat_intel_lookup": {"安全事件分析师"}},
    )

    errors = runner.validate_playbook(
        {
            "name": "future-step-playbook",
            "inputs": [{"name": "incident_ip", "required": True}],
            "steps": [
                {
                    "id": "summary",
                    "persona": "安全事件分析师",
                    "prompt": "总结 {{steps.lookup.full_message}}",
                },
                {
                    "id": "lookup",
                    "persona": "安全事件分析师",
                    "tool": "threat_intel_lookup",
                    "execution_mode": "direct",
                    "tool_args": {"ip": "{{inputs.incident_ip}}"},
                    "prompt": "查询 {{inputs.incident_ip}}",
                },
            ],
        }
    )

    assert (
        "Step summary: Unknown or future step reference: steps.lookup.full_message"
        in errors
    )


def test_validate_playbook_requires_tool_args_for_direct_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner,
        "load_declared_tool_bindings",
        lambda: {"threat_intel_lookup": {"安全事件分析师"}},
    )

    errors = runner.validate_playbook(
        {
            "name": "missing-tool-args-playbook",
            "steps": [
                {
                    "id": "lookup",
                    "persona": "安全事件分析师",
                    "tool": "threat_intel_lookup",
                    "execution_mode": "direct",
                    "prompt": "查询 8.8.8.8",
                }
            ],
        }
    )

    assert (
        "Step lookup with execution_mode=direct missing tool_args"
        in errors
    )


def test_pick_openapi_operation_prefers_matching_required_parameters() -> None:
    method, path, _operation = runner._pick_openapi_operation(
        {
            "paths": {
                "/files/{hash}": {
                    "get": {
                        "parameters": [
                            {"name": "hash", "in": "path", "required": True}
                        ]
                    }
                },
                "/ip_addresses/{ip}": {
                    "get": {
                        "parameters": [
                            {"name": "ip", "in": "path", "required": True}
                        ]
                    }
                },
            }
        },
        {"ip": "8.8.8.8"},
    )

    assert method == "GET"
    assert path == "/ip_addresses/{ip}"


def test_required_inputs_returns_only_required_names(sample_playbook: dict[str, Any]) -> None:
    assert runner.required_inputs(sample_playbook) == ["incident_ip", "asset_hostname"]


def test_example_inputs_returns_mapping() -> None:
    playbook = {
        "example_inputs": {
            "incident_ip": "8.8.8.8",
            "asset_hostname": "finance-host-01",
        }
    }

    assert runner.example_inputs(playbook) == {
        "incident_ip": "8.8.8.8",
        "asset_hostname": "finance-host-01",
    }


def test_send_chat_message_with_timeout_returns_timeout_result(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_send_chat_message(*args: Any, **kwargs: Any) -> dict[str, Any]:
        import time
        time.sleep(0.05)
        return {"full_message": "late", "tool_call_debug": [], "error": None}

    monkeypatch.setattr(runner, "send_chat_message", fake_send_chat_message)

    result = runner.send_chat_message_with_timeout(
        "http://127.0.0.1:3000/api",
        "cookie",
        "chat-1",
        "hello",
        step_timeout_seconds=0,
    )

    assert result["error"] == "step_timeout_after_0s"


def test_send_chat_message_passes_mock_llm_response(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _Response:
        def raise_for_status(self) -> None:
            return None

    def fake_post(*_args: Any, **kwargs: Any) -> _Response:
        captured["json"] = kwargs["json"]
        return _Response()

    monkeypatch.setattr(runner.requests, "post", fake_post)
    monkeypatch.setattr(
        runner,
        "parse_stream_response",
        lambda _response: {"full_message": "ok", "tool_call_debug": [], "error": None},
    )

    result = runner.send_chat_message(
        "http://127.0.0.1:3000/api",
        "cookie",
        "chat-1",
        "hello",
        forced_tool_id=15,
        mock_llm_response='{"name":"threat_intel_lookup","arguments":{"ioc":"8.8.8.8"}}',
    )

    assert result["error"] is None
    assert captured["json"]["forced_tool_id"] == 15
    assert captured["json"]["mock_llm_response"] == '{"name":"threat_intel_lookup","arguments":{"ioc":"8.8.8.8"}}'


def test_resolve_host_accessible_url_rewrites_host_docker_internal() -> None:
    assert (
        runner.resolve_host_accessible_url("http://host.docker.internal:9999")
        == "http://127.0.0.1:9999"
    )


def test_execute_playbook_marks_missing_tool_observation_as_failure(
    monkeypatch: pytest.MonkeyPatch, sample_playbook: dict[str, Any]
) -> None:
    monkeypatch.setattr(
        runner,
        "resolve_runtime",
        lambda _base_url, _cookie: (
            {
                "安全事件分析师": {"id": 2, "name": "安全事件分析师"},
                "应急响应指挥官": {"id": 3, "name": "应急响应指挥官"},
            },
            {"threat_intel_lookup": {"id": 15, "name": "threat_intel_lookup"}},
        ),
    )
    monkeypatch.setattr(runner, "create_chat_session", lambda *_args, **_kwargs: "chat-1")

    def fake_send_chat_message_with_timeout(
        _base_url: str,
        _cookie: str,
        _chat_session_id: str,
        message: str,
        *,
        forced_tool_id: int | None = None,
        step_timeout_seconds: int = 90,
        mock_llm_response: str | None = None,
    ) -> dict[str, Any]:
        assert mock_llm_response is None
        if forced_tool_id is not None:
            return {
                "full_message": "intel result",
                "tool_call_debug": [],
                "error": None,
            }
        return {
            "full_message": f"summary for {message}",
            "tool_call_debug": [],
            "error": None,
        }

    monkeypatch.setattr(runner, "send_chat_message_with_timeout", fake_send_chat_message_with_timeout)

    result = runner.execute_playbook(
        sample_playbook,
        "http://127.0.0.1:3000/api",
        "cookie",
        {"incident_ip": "8.8.8.8", "asset_hostname": "finance-host-01"},
    )

    assert result["ok"] is False
    assert "Step lookup_intel: tool_not_observed:threat_intel_lookup" in result["failures"]
    assert len(result["steps"]) == 1
    assert result["steps"][0]["id"] == "lookup_intel"


def test_execute_playbook_stops_on_first_failure_by_default(
    monkeypatch: pytest.MonkeyPatch, sample_playbook: dict[str, Any]
) -> None:
    monkeypatch.setattr(
        runner,
        "resolve_runtime",
        lambda _base_url, _cookie: (
            {
                "安全事件分析师": {"id": 2, "name": "安全事件分析师"},
                "应急响应指挥官": {"id": 3, "name": "应急响应指挥官"},
            },
            {"threat_intel_lookup": {"id": 15, "name": "threat_intel_lookup"}},
        ),
    )
    monkeypatch.setattr(runner, "create_chat_session", lambda *_args, **_kwargs: "chat-1")
    monkeypatch.setattr(
        runner,
        "send_chat_message_with_timeout",
        lambda *_args, **_kwargs: {
            "full_message": "",
            "tool_call_debug": [],
            "error": "step_timeout_after_20s",
        },
    )

    result = runner.execute_playbook(
        sample_playbook,
        "http://127.0.0.1:3000/api",
        "cookie",
        {"incident_ip": "8.8.8.8", "asset_hostname": "finance-host-01"},
    )

    assert result["ok"] is False
    assert len(result["steps"]) == 1
    assert result["steps"][0]["id"] == "lookup_intel"


def test_execute_playbook_continues_after_chat_failure_when_requested(
    monkeypatch: pytest.MonkeyPatch, sample_playbook: dict[str, Any]
) -> None:
    monkeypatch.setattr(
        runner,
        "resolve_runtime",
        lambda _base_url, _cookie: (
            {
                "安全事件分析师": {"id": 2, "name": "安全事件分析师"},
                "应急响应指挥官": {"id": 3, "name": "应急响应指挥官"},
            },
            {"threat_intel_lookup": {"id": 15, "name": "threat_intel_lookup"}},
        ),
    )
    monkeypatch.setattr(runner, "create_chat_session", lambda *_args, **_kwargs: "chat-1")

    def fake_send_chat_message_with_timeout(
        _base_url: str,
        _cookie: str,
        _chat_session_id: str,
        message: str,
        *,
        forced_tool_id: int | None = None,
        step_timeout_seconds: int = 90,
        mock_llm_response: str | None = None,
    ) -> dict[str, Any]:
        if forced_tool_id is not None:
            return {
                "full_message": "",
                "tool_call_debug": [{"tool_name": "threat_intel_lookup", "tool_args": {"ip": "8.8.8.8"}}],
                "error": "step_timeout_after_20s",
            }
        return {
            "full_message": f"summary for {message}",
            "tool_call_debug": [],
            "error": None,
        }

    monkeypatch.setattr(runner, "send_chat_message_with_timeout", fake_send_chat_message_with_timeout)

    result = runner.execute_playbook(
        sample_playbook,
        "http://127.0.0.1:3000/api",
        "cookie",
        {"incident_ip": "8.8.8.8", "asset_hostname": "finance-host-01"},
        stop_on_failure=False,
    )

    assert result["ok"] is False
    assert len(result["steps"]) == 2
    assert result["steps"][0]["id"] == "lookup_intel"
    assert result["steps"][1]["id"] == "summary"
    assert "Step lookup_intel: step_timeout_after_20s" in result["failures"]


def test_execute_playbook_continues_after_direct_tool_failure_when_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    playbook = {
        "name": "direct-continue-playbook",
        "inputs": [{"name": "incident_ip", "required": True}],
        "steps": [
            {
                "id": "lookup_intel",
                "persona": "安全事件分析师",
                "tool": "threat_intel_lookup",
                "execution_mode": "direct",
                "tool_args": {"ip": "{{inputs.incident_ip}}"},
                "prompt": "查询 {{inputs.incident_ip}}",
            },
            {
                "id": "summary",
                "persona": "应急响应指挥官",
                "execution_mode": "template",
                "response_template": "结论：{{inputs.incident_ip}} 继续观察",
            },
        ],
    }
    monkeypatch.setattr(
        runner,
        "resolve_runtime",
        lambda _base_url, _cookie: (
            {"安全事件分析师": {"id": 2, "name": "安全事件分析师"}},
            {"threat_intel_lookup": {"id": 15, "name": "threat_intel_lookup"}},
        ),
    )
    monkeypatch.setattr(runner, "create_chat_session", lambda *_args, **_kwargs: "chat-1")
    monkeypatch.setattr(
        runner,
        "execute_direct_tool_step",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("mock tool down")),
    )

    result = runner.execute_playbook(
        playbook,
        "http://127.0.0.1:3000/api",
        "cookie",
        {"incident_ip": "8.8.8.8"},
        stop_on_failure=False,
    )

    assert result["ok"] is False
    assert len(result["steps"]) == 1
    assert result["steps"][0]["id"] == "summary"
    assert "Step lookup_intel: direct_tool_failed:mock tool down" in result["failures"]


def test_execute_playbook_fails_when_persona_missing(
    monkeypatch: pytest.MonkeyPatch, sample_playbook: dict[str, Any]
) -> None:
    monkeypatch.setattr(
        runner,
        "resolve_runtime",
        lambda _base_url, _cookie: ({}, {"threat_intel_lookup": {"id": 15, "name": "threat_intel_lookup"}}),
    )

    result = runner.execute_playbook(
        sample_playbook,
        "http://127.0.0.1:3000/api",
        "cookie",
        {"incident_ip": "8.8.8.8", "asset_hostname": "finance-host-01"},
    )

    assert result["ok"] is False
    assert "Step lookup_intel: missing persona 安全事件分析师" in result["failures"]


def test_execute_playbook_supports_template_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    playbook = {
        "name": "template-playbook",
        "steps": [
            {
                "id": "summary",
                "persona": "应急响应指挥官",
                "execution_mode": "template",
                "response_template": "结论：{{inputs.asset_hostname}} 继续观察",
            }
        ],
    }
    monkeypatch.setattr(runner, "resolve_runtime", lambda _base_url, _cookie: ({}, {}))

    result = runner.execute_playbook(
        playbook,
        "http://127.0.0.1:3000/api",
        "cookie",
        {"asset_hostname": "finance-host-01"},
    )

    assert result["ok"] is True
    assert result["steps"][0]["id"] == "summary"
    assert result["steps"][0]["full_message"] == "结论：finance-host-01 继续观察"


def test_main_verify_definitions_returns_zero_for_valid_playbooks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        runner.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            list_playbooks=False,
            show_playbook=None,
            verify_definitions=True,
            dry_run=False,
            execute=False,
            playbook=None,
            input=[],
            url="http://example.com",
            email="security-admin@example.com",
            password="secret",
            json=False,
            step_timeout_seconds=90,
            continue_on_failure=False,
        ),
    )
    monkeypatch.setattr(
        runner,
        "list_playbooks",
        lambda: [{"name": "incident-triage-readonly", "display_name": "事件研判只读流程"}],
    )
    monkeypatch.setattr(
        runner,
        "load_playbook_definition",
        lambda _name: {
            "name": "incident-triage-readonly",
            "inputs": [{"name": "incident_ip", "required": True}],
            "example_inputs": {"incident_ip": "8.8.8.8"},
            "steps": [{"id": "lookup", "persona": "安全事件分析师", "prompt": "查询 {{inputs.incident_ip}}"}],
        },
    )
    monkeypatch.setattr(runner, "validate_playbook", lambda _playbook: [])

    result = runner.main()

    assert result == 0
    assert "[OK] Verified 1 playbook definitions" in capsys.readouterr().out


def test_main_dry_run_json_returns_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        runner.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            list_playbooks=False,
            show_playbook=None,
            verify_definitions=False,
            dry_run=True,
            execute=False,
            playbook="incident-triage-readonly",
            input=["incident_ip=8.8.8.8"],
            url="http://example.com",
            email="security-admin@example.com",
            password="secret",
            json=True,
            step_timeout_seconds=90,
            continue_on_failure=False,
        ),
    )
    monkeypatch.setattr(
        runner,
        "load_playbook_definition",
        lambda _name: {
            "name": "incident-triage-readonly",
            "inputs": [{"name": "incident_ip", "required": True}],
            "steps": [
                {
                    "id": "lookup",
                    "persona": "安全事件分析师",
                    "tool": "threat_intel_lookup",
                    "prompt": "查询 {{inputs.incident_ip}}",
                }
            ],
        },
    )
    monkeypatch.setattr(runner, "validate_playbook", lambda _playbook: [])

    result = runner.main()

    assert result == 0
    assert json.loads(capsys.readouterr().out) == {
        "playbook": "incident-triage-readonly",
        "inputs": {"incident_ip": "8.8.8.8"},
        "steps": [
            {
                "id": "lookup",
                "persona": "安全事件分析师",
                "tool": "threat_intel_lookup",
                "prompt": "查询 8.8.8.8",
            }
        ],
    }


def test_main_execute_returns_one_when_login_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        runner.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            list_playbooks=False,
            show_playbook=None,
            verify_definitions=False,
            dry_run=False,
            execute=True,
            playbook="incident-triage-readonly",
            input=["incident_ip=8.8.8.8"],
            url="http://example.com",
            email="security-admin@example.com",
            password="secret",
            json=False,
            step_timeout_seconds=90,
            continue_on_failure=False,
        ),
    )
    monkeypatch.setattr(
        runner,
        "load_playbook_definition",
        lambda _name: {
            "name": "incident-triage-readonly",
            "inputs": [{"name": "incident_ip", "required": True}],
            "steps": [{"id": "lookup", "persona": "安全事件分析师", "prompt": "查询 {{inputs.incident_ip}}"}],
        },
    )
    monkeypatch.setattr(runner, "validate_playbook", lambda _playbook: [])
    monkeypatch.setattr(runner, "get_cookie", lambda *_args, **_kwargs: None)

    result = runner.main()

    assert result == 1
    assert "[ERROR] Login failed. Check credentials." in capsys.readouterr().out


def test_main_execute_passes_continue_on_failure_to_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, Any] = {}

    monkeypatch.setattr(
        runner.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            list_playbooks=False,
            show_playbook=None,
            verify_definitions=False,
            dry_run=False,
            execute=True,
            playbook="incident-triage-readonly",
            input=["incident_ip=8.8.8.8"],
            url="http://example.com",
            email="security-admin@example.com",
            password="secret",
            json=True,
            step_timeout_seconds=45,
            continue_on_failure=True,
        ),
    )
    monkeypatch.setattr(
        runner,
        "load_playbook_definition",
        lambda _name: {
            "name": "incident-triage-readonly",
            "inputs": [{"name": "incident_ip", "required": True}],
            "steps": [{"id": "lookup", "persona": "安全事件分析师", "prompt": "查询 {{inputs.incident_ip}}"}],
        },
    )
    monkeypatch.setattr(runner, "validate_playbook", lambda _playbook: [])
    monkeypatch.setattr(runner, "get_cookie", lambda *_args, **_kwargs: "cookie")

    def fake_execute_playbook(
        playbook: dict[str, Any],
        base_url: str,
        cookie: str,
        inputs: dict[str, str],
        *,
        step_timeout_seconds: int = 90,
        show_progress: bool = False,
        stop_on_failure: bool = True,
    ) -> dict[str, Any]:
        captured["playbook"] = playbook["name"]
        captured["base_url"] = base_url
        captured["cookie"] = cookie
        captured["inputs"] = inputs
        captured["step_timeout_seconds"] = step_timeout_seconds
        captured["show_progress"] = show_progress
        captured["stop_on_failure"] = stop_on_failure
        return {"ok": True, "playbook": playbook["name"], "inputs": inputs, "steps": [], "failures": []}

    monkeypatch.setattr(runner, "execute_playbook", fake_execute_playbook)

    result = runner.main()

    assert result == 0
    assert captured == {
        "playbook": "incident-triage-readonly",
        "base_url": "http://example.com",
        "cookie": "cookie",
        "inputs": {"incident_ip": "8.8.8.8"},
        "step_timeout_seconds": 45,
        "show_progress": False,
        "stop_on_failure": False,
    }
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "playbook": "incident-triage-readonly",
        "inputs": {"incident_ip": "8.8.8.8"},
        "steps": [],
        "failures": [],
    }
