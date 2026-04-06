#!/usr/bin/env python3
"""
Post-deployment smoke test for the Onyx security platform customization.

This script verifies:
1. A security persona can create a chat session and answer a prompt.
2. The read-only threat_intel_lookup tool can be invoked through chat.

Examples:
    python post_deploy_smoke_test.py
    python post_deploy_smoke_test.py --json
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlparse, urlunparse
import uuid
from typing import Any

import requests
import yaml


PERSONA_SMOKE_SCENARIOS = [
    {
        "persona_name": "安全事件分析师",
        "token": "SMOKE_OK_ANALYST",
        "prompt": "你是安全事件分析师。请直接回复字符串 SMOKE_OK_ANALYST，不要添加任何其他内容。",
    },
    {
        "persona_name": "应急响应指挥官",
        "token": "SMOKE_OK_COMMANDER",
        "prompt": "你是应急响应指挥官。请直接回复字符串 SMOKE_OK_COMMANDER，不要添加任何其他内容。",
    },
    {
        "persona_name": "漏洞评估专家",
        "token": "SMOKE_OK_VULN",
        "prompt": "你是漏洞评估专家。请直接回复字符串 SMOKE_OK_VULN，不要添加任何其他内容。",
    },
    {
        "persona_name": "合规审计员",
        "token": "SMOKE_OK_COMPLIANCE",
        "prompt": "你是合规审计员。请直接回复字符串 SMOKE_OK_COMPLIANCE，不要添加任何其他内容。",
    },
]

ANALYST_PERSONA_NAME = "安全事件分析师"
THREAT_INTEL_TOOL_NAME = "threat_intel_lookup"
SMOKE_PROBE_TOKEN = "SMOKE_OK_ANALYST"
ROOT = Path(__file__).resolve().parent
DEPLOYMENT_PROFILES_PATH = ROOT.parent / "docs" / "security-platform" / "deployment-profiles.yaml"


def get_cookie(base_url: str, email: str, password: str) -> str | None:
    try:
        response = requests.post(
            f"{base_url}/auth/login",
            data={"username": email, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        if response.status_code == 204:
            cookie = response.headers.get("set-cookie", "")
            for part in cookie.split(","):
                part = part.strip()
                if "fastapiusersauth=" in part:
                    return part.split(";")[0].split("=")[1]
    except Exception as exc:
        print(f"  [WARN] Login failed: {exc}")
    return None


def session_headers(cookie: str) -> dict[str, str]:
    return {"Content-Type": "application/json", "Cookie": f"fastapiusersauth={cookie}; "}


def list_personas(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/persona",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def list_openapi_tools(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/tool/openapi",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def clear_mock_tool_requests(mock_server_url: str) -> None:
    response = requests.delete(f"{mock_server_url.rstrip('/')}/__requests__", timeout=10)
    response.raise_for_status()


def list_mock_tool_requests(mock_server_url: str) -> list[dict[str, Any]]:
    response = requests.get(f"{mock_server_url.rstrip('/')}/__requests__", timeout=10)
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, list):
        return payload
    return []


def resolve_mock_server_observer_url(mock_server_url: str) -> str:
    explicit_observer_url = os.environ.get("SECURITY_TOOLS_MOCK_SERVER_OBSERVER_URL", "").strip()
    if explicit_observer_url:
        return explicit_observer_url.rstrip("/")

    parsed = urlparse(mock_server_url)
    if parsed.hostname == "host.docker.internal":
        host = "127.0.0.1"
        netloc = f"{host}:{parsed.port}" if parsed.port else host
        return urlunparse(
            (
                parsed.scheme,
                netloc,
                "",
                "",
                "",
                "",
            )
        ).rstrip("/")
    return mock_server_url.rstrip("/")


def get_persona(base_url: str, cookie: str, persona_id: int) -> dict[str, Any]:
    response = requests.get(
        f"{base_url}/persona/{persona_id}",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def load_deployment_profile_summary() -> dict[str, Any]:
    deployment_profile = os.environ.get("SECURITY_PLATFORM_DEPLOYMENT_PROFILE", "live")
    try:
        with open(DEPLOYMENT_PROFILES_PATH, "r", encoding="utf-8") as handle:
            profiles_doc = yaml.safe_load(handle) or {}
    except Exception:
        profiles_doc = {}

    profiles = profiles_doc.get("profiles", {}) if isinstance(profiles_doc, dict) else {}
    profile = profiles.get(deployment_profile, {}) if isinstance(profiles, dict) else {}
    expectations = profile.get("expectations", {}) if isinstance(profile, dict) else {}
    if not isinstance(expectations, dict):
        expectations = {}
    required_env = profile.get("required_env", []) if isinstance(profile, dict) else []
    if not isinstance(required_env, list):
        required_env = []

    missing_required_env = [
        str(env_name)
        for env_name in required_env
        if str(env_name).strip() and not os.environ.get(str(env_name), "").strip()
    ]
    return {
        "deployment_profile": deployment_profile,
        "expected_security_tools_profile": expectations.get("security_tools_profile"),
        "required_env": [str(env_name) for env_name in required_env if str(env_name).strip()],
        "missing_required_env": missing_required_env,
    }


def threat_intel_tool_runtime_summary(tool: dict[str, Any]) -> dict[str, Any]:
    definition = tool.get("definition", {}) if isinstance(tool, dict) else {}
    servers = definition.get("servers", []) if isinstance(definition, dict) else []
    server_url = None
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server_url = servers[0].get("url")
    custom_headers = tool.get("custom_headers", []) if isinstance(tool, dict) else []
    header_keys = sorted(
        str(header.get("key"))
        for header in custom_headers
        if isinstance(header, dict) and header.get("key")
    )
    return {
        "server_url": server_url,
        "header_keys": header_keys,
    }


def expected_threat_intel_tool_server_url(deployment_profile_summary: dict[str, Any]) -> str | None:
    if deployment_profile_summary.get("expected_security_tools_profile") == "mock":
        return os.environ.get("SECURITY_TOOLS_MOCK_SERVER_URL") or None
    if deployment_profile_summary.get("expected_security_tools_profile") == "live":
        return os.environ.get("THREAT_INTEL_API_URL") or None
    return None


def tool_response_has_failure_markers(response_text: str) -> bool:
    lowered = response_text.lower()
    return any(
        marker in lowered
        for marker in [
            "工具调用失败",
            "服务连接被拒绝",
            "connection refused",
            "failed to call tool",
            "tool call failed",
            "threat intelligence service unavailable",
        ]
    )


def persona_live_response_looks_valid(response_text: str) -> bool:
    cleaned = response_text.strip()
    if not cleaned:
        return False
    lowered = cleaned.lower()
    refusal_markers = [
        "无法提供",
        "cannot comply",
        "i can't comply",
        "抱歉",
    ]
    return not any(marker in lowered for marker in refusal_markers)


def create_chat_session(
    base_url: str, cookie: str, persona_id: int, description: str
) -> str:
    response = requests.post(
        f"{base_url}/chat/create-chat-session",
        json={"persona_id": persona_id, "description": description},
        headers=session_headers(cookie),
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return str(response.json()["chat_session_id"])


def _parse_stream_response(response: requests.Response) -> dict[str, Any]:
    full_message = ""
    tool_call_debug: list[dict[str, Any]] = []
    error: str | None = None

    for line in response.iter_lines():
        if not line:
            continue
        packet = json.loads(line.decode("utf-8"))
        if packet.get("error"):
            error = str(packet["error"])
            continue

        obj = packet.get("obj") or {}
        packet_type = obj.get("type")
        if packet_type == "message_delta":
            full_message += obj.get("content", "")
        elif packet_type == "tool_call_debug":
            tool_call_debug.append(
                {
                    "tool_name": obj.get("tool_name"),
                    "tool_args": obj.get("tool_args") or {},
                }
            )

    return {
        "full_message": full_message,
        "tool_call_debug": tool_call_debug,
        "error": error,
    }


def send_chat_message(
    base_url: str,
    cookie: str,
    chat_session_id: str,
    message: str,
    *,
    forced_tool_id: int | None = None,
    mock_llm_response: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "chat_session_id": chat_session_id,
        "message": message,
        "parent_message_id": -1,
        "file_descriptors": [],
    }
    if forced_tool_id is not None:
        payload["forced_tool_id"] = forced_tool_id
    if mock_llm_response is not None:
        payload["mock_llm_response"] = mock_llm_response

    response = requests.post(
        f"{base_url}/chat/send-chat-message",
        json=payload,
        headers=session_headers(cookie),
        cookies={"fastapiusersauth": cookie},
        stream=True,
        timeout=120,
    )
    response.raise_for_status()
    return _parse_stream_response(response)


def _try_mock_llm_roundtrip(base_url: str, cookie: str, persona_id: int) -> bool:
    chat_session_id = create_chat_session(
        base_url,
        cookie,
        persona_id,
        description=f"smoke-mock-probe-{uuid.uuid4()}",
    )
    try:
        result = send_chat_message(
            base_url,
            cookie,
            chat_session_id,
            "mock probe",
            mock_llm_response=SMOKE_PROBE_TOKEN,
        )
    except requests.HTTPError:
        return False
    return result["error"] is None and SMOKE_PROBE_TOKEN in result["full_message"]


def run_smoke_test(base_url: str, cookie: str) -> dict[str, Any]:
    deployment_profile_summary = load_deployment_profile_summary()
    personas = {persona["name"]: persona for persona in list_personas(base_url, cookie)}
    openapi_tools = {tool["name"]: tool for tool in list_openapi_tools(base_url, cookie)}
    missing_personas = [
        scenario["persona_name"]
        for scenario in PERSONA_SMOKE_SCENARIOS
        if scenario["persona_name"] not in personas
    ]
    if missing_personas:
        return {"ok": False, "failures": [f"Missing personas: {', '.join(missing_personas)}"]}

    analyst = personas[ANALYST_PERSONA_NAME]
    analyst_detail = get_persona(base_url, cookie, int(analyst["id"]))
    threat_intel_tool = next(
        (tool for tool in analyst_detail.get("tools", []) if tool.get("name") == THREAT_INTEL_TOOL_NAME),
        None,
    )
    if threat_intel_tool is None:
        return {"ok": False, "failures": [f"Missing tool on persona {ANALYST_PERSONA_NAME}: {THREAT_INTEL_TOOL_NAME}"]}
    threat_intel_tool_config = openapi_tools.get(THREAT_INTEL_TOOL_NAME, threat_intel_tool)
    threat_intel_tool_summary = threat_intel_tool_runtime_summary(threat_intel_tool_config)

    use_mock_llm = _try_mock_llm_roundtrip(base_url, cookie, int(analyst["id"]))
    failures: list[str] = []
    persona_chat_previews: dict[str, str] = {}
    if deployment_profile_summary["missing_required_env"]:
        failures.append(
            "Deployment profile missing required env vars: "
            + ", ".join(deployment_profile_summary["missing_required_env"])
        )
    expected_tool_server_url = expected_threat_intel_tool_server_url(deployment_profile_summary)
    if (
        expected_tool_server_url
        and threat_intel_tool_summary["server_url"]
        and threat_intel_tool_summary["server_url"] != expected_tool_server_url
    ):
        failures.append(
            f"Threat-intel tool server mismatch: expected {expected_tool_server_url}, got {threat_intel_tool_summary['server_url']}"
        )
    observed_mock_requests: list[dict[str, Any]] = []
    if (
        deployment_profile_summary.get("expected_security_tools_profile") == "mock"
        and expected_tool_server_url
    ):
        observer_url = resolve_mock_server_observer_url(expected_tool_server_url)
        try:
            clear_mock_tool_requests(observer_url)
        except Exception as exc:
            failures.append(f"Unable to reset mock tool request log: {exc}")

    for scenario in PERSONA_SMOKE_SCENARIOS:
        persona = personas[scenario["persona_name"]]
        basic_session_id = create_chat_session(
            base_url,
            cookie,
            int(persona["id"]),
            description=f"smoke-basic-{uuid.uuid4()}",
        )
        if use_mock_llm:
            basic_result = send_chat_message(
                base_url,
                cookie,
                basic_session_id,
                scenario["prompt"],
                mock_llm_response=scenario["token"],
            )
        else:
            basic_result = send_chat_message(
                base_url,
                cookie,
                basic_session_id,
                scenario["prompt"],
            )

        persona_chat_previews[scenario["persona_name"]] = basic_result["full_message"][:200]
        if basic_result["error"] is not None:
            failures.append(
                f"Persona {scenario['persona_name']} basic chat returned error: {basic_result['error']}"
            )
        elif use_mock_llm and scenario["token"] not in basic_result["full_message"]:
            failures.append(
                f"Persona {scenario['persona_name']} did not return expected smoke token"
            )
        elif not use_mock_llm and not persona_live_response_looks_valid(
            basic_result["full_message"]
        ):
            failures.append(
                f"Persona {scenario['persona_name']} did not return a valid live response"
            )

    tool_session_id = create_chat_session(
        base_url,
        cookie,
        int(analyst["id"]),
        description=f"smoke-tool-{uuid.uuid4()}",
    )
    if use_mock_llm:
        tool_result = send_chat_message(
            base_url,
            cookie,
            tool_session_id,
            "请查询 8.8.8.8 的威胁情报。",
            forced_tool_id=int(threat_intel_tool["id"]),
            mock_llm_response=json.dumps(
                {"name": THREAT_INTEL_TOOL_NAME, "arguments": {"ip": "8.8.8.8"}}
            ),
        )
    else:
        tool_result = send_chat_message(
            base_url,
            cookie,
            tool_session_id,
            "请使用 threat_intel_lookup 查询 8.8.8.8 的威胁情报，并用一句话总结结果。",
            forced_tool_id=int(threat_intel_tool["id"]),
        )

    if tool_result["error"] is not None:
        failures.append(f"Tool smoke returned error: {tool_result['error']}")
    elif use_mock_llm:
        if not tool_result["tool_call_debug"]:
            failures.append("Tool smoke did not emit any tool_call_debug packet")
        elif tool_result["tool_call_debug"][0]["tool_name"] != THREAT_INTEL_TOOL_NAME:
            failures.append(
                f"Tool smoke invoked unexpected tool: {tool_result['tool_call_debug'][0]['tool_name']}"
            )
    else:
        tool_preview = tool_result["full_message"]
        if (
            deployment_profile_summary.get("expected_security_tools_profile") == "mock"
            and tool_response_has_failure_markers(tool_preview)
        ):
            failures.append(
                "Tool smoke response indicates mock threat-intel service failure"
            )
        if not any(
            marker in tool_preview
            for marker in ["8.8.8.8", "Google", "resolver", "DNS", "reputation"]
        ):
            failures.append("Tool smoke response did not contain expected threat-intel markers")
        if (
            deployment_profile_summary.get("expected_security_tools_profile") == "mock"
            and expected_tool_server_url
        ):
            observer_url = resolve_mock_server_observer_url(expected_tool_server_url)
            try:
                observed_mock_requests = list_mock_tool_requests(observer_url)
            except Exception as exc:
                failures.append(f"Unable to read mock tool request log: {exc}")
            else:
                if not any(
                    request.get("method") == "GET"
                    and request.get("path") == "/ip_addresses/8.8.8.8"
                    for request in observed_mock_requests
                    if isinstance(request, dict)
                ):
                    failures.append(
                        "Tool smoke did not produce the expected mock threat-intel request"
                    )

    return {
        "ok": not failures,
        "failures": failures,
        "summary": {
            "deployment_profile": deployment_profile_summary["deployment_profile"],
            "expected_security_tools_profile": deployment_profile_summary["expected_security_tools_profile"],
            "deployment_required_env": deployment_profile_summary["required_env"],
            "deployment_missing_required_env": deployment_profile_summary["missing_required_env"],
            "personas": [scenario["persona_name"] for scenario in PERSONA_SMOKE_SCENARIOS],
            "tool": THREAT_INTEL_TOOL_NAME,
            "tool_server_url": threat_intel_tool_summary["server_url"],
            "tool_header_keys": threat_intel_tool_summary["header_keys"],
            "expected_tool_server_url": expected_tool_server_url,
            "observed_mock_requests": observed_mock_requests,
            "use_mock_llm": use_mock_llm,
            "persona_chat_previews": persona_chat_previews,
            "tool_response_preview": tool_result["full_message"][:400],
            "tool_call_debug": tool_result["tool_call_debug"],
        },
    }


def print_human_result(result: dict[str, Any]) -> None:
    print("=== Post-Deploy Smoke Test ===")
    print(f"Deployment profile: {result['summary']['deployment_profile']}")
    print(
        "Expected security tools profile: "
        f"{result['summary']['expected_security_tools_profile'] or 'unknown'}"
    )
    if result["summary"]["deployment_required_env"]:
        print(
            "Deployment required env: "
            + ", ".join(result["summary"]["deployment_required_env"])
        )
    print("Personas:")
    for persona_name in result["summary"]["personas"]:
        preview = result["summary"]["persona_chat_previews"].get(persona_name, "[empty]")
        print(f"  - {persona_name}: {preview or '[empty]'}")
    print(f"Tool: {result['summary']['tool']}")
    print(
        f"Tool server: {result['summary']['tool_server_url'] or 'unknown'} "
        f"(expected {result['summary']['expected_tool_server_url'] or 'unknown'})"
    )
    print(
        f"Tool headers: {','.join(result['summary']['tool_header_keys']) or 'none'}"
    )
    if result["summary"]["observed_mock_requests"]:
        print(
            f"Observed mock requests: {len(result['summary']['observed_mock_requests'])}"
        )
    print(f"Mock LLM mode: {'ON' if result['summary']['use_mock_llm'] else 'OFF'}")
    print(f"Tool response preview: {result['summary']['tool_response_preview'] or '[empty]'}")
    if result["summary"]["tool_call_debug"]:
        print(f"Tool call debug: {result['summary']['tool_call_debug'][0]}")
    else:
        print("Tool call debug: []")

    if result["ok"]:
        print("\nResult: OK")
        return

    print("\nResult: FAILED")
    for failure in result["failures"]:
        print(f"  - {failure}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Post-deployment smoke test for the Onyx security platform"
    )
    parser.add_argument("--url", default=os.environ.get("ONYX_URL", "http://localhost:8080"))
    parser.add_argument(
        "--email",
        default=os.environ.get("ONYX_EMAIL", "security-admin@onyx.local"),
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("ONYX_PASSWORD", "admin123"),
    )
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    args = parser.parse_args()

    cookie = get_cookie(args.url, args.email, args.password)
    if not cookie:
        print("[ERROR] Login failed. Check credentials.")
        return 1

    result = run_smoke_test(args.url, cookie)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print_human_result(result)

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
