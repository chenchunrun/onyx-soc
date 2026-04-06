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
import uuid
from typing import Any

import requests


ANALYST_PERSONA_NAME = "安全事件分析师"
THREAT_INTEL_TOOL_NAME = "threat_intel_lookup"
SMOKE_TOKEN = "SMOKE_OK_ANALYST"


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


def get_persona(base_url: str, cookie: str, persona_id: int) -> dict[str, Any]:
    response = requests.get(
        f"{base_url}/persona/{persona_id}",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


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
            mock_llm_response=SMOKE_TOKEN,
        )
    except requests.HTTPError:
        return False
    return result["error"] is None and SMOKE_TOKEN in result["full_message"]


def run_smoke_test(base_url: str, cookie: str) -> dict[str, Any]:
    personas = {persona["name"]: persona for persona in list_personas(base_url, cookie)}
    analyst = personas.get(ANALYST_PERSONA_NAME)
    if analyst is None:
        return {"ok": False, "failures": [f"Missing persona: {ANALYST_PERSONA_NAME}"]}

    analyst_detail = get_persona(base_url, cookie, int(analyst["id"]))
    threat_intel_tool = next(
        (tool for tool in analyst_detail.get("tools", []) if tool.get("name") == THREAT_INTEL_TOOL_NAME),
        None,
    )
    if threat_intel_tool is None:
        return {"ok": False, "failures": [f"Missing tool on persona {ANALYST_PERSONA_NAME}: {THREAT_INTEL_TOOL_NAME}"]}

    use_mock_llm = _try_mock_llm_roundtrip(base_url, cookie, int(analyst["id"]))
    failures: list[str] = []

    basic_session_id = create_chat_session(
        base_url,
        cookie,
        int(analyst["id"]),
        description=f"smoke-basic-{uuid.uuid4()}",
    )
    if use_mock_llm:
        basic_result = send_chat_message(
            base_url,
            cookie,
            basic_session_id,
            "请回复 smoke token",
            mock_llm_response=SMOKE_TOKEN,
        )
    else:
        basic_result = send_chat_message(
            base_url,
            cookie,
            basic_session_id,
            f"请直接回复字符串 {SMOKE_TOKEN}，不要添加其他内容。",
        )

    if basic_result["error"] is not None:
        failures.append(f"Basic chat returned error: {basic_result['error']}")
    elif SMOKE_TOKEN not in basic_result["full_message"]:
        failures.append("Basic chat did not return the expected smoke token")

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
        if not any(
            marker in tool_preview
            for marker in ["8.8.8.8", "Google", "resolver", "DNS", "reputation"]
        ):
            failures.append("Tool smoke response did not contain expected threat-intel markers")

    return {
        "ok": not failures,
        "failures": failures,
        "summary": {
            "persona": ANALYST_PERSONA_NAME,
            "tool": THREAT_INTEL_TOOL_NAME,
            "use_mock_llm": use_mock_llm,
            "basic_chat_preview": basic_result["full_message"][:200],
            "tool_response_preview": tool_result["full_message"][:400],
            "tool_call_debug": tool_result["tool_call_debug"],
        },
    }


def print_human_result(result: dict[str, Any]) -> None:
    print("=== Post-Deploy Smoke Test ===")
    print(f"Persona: {result['summary']['persona']}")
    print(f"Tool: {result['summary']['tool']}")
    print(f"Mock LLM mode: {'ON' if result['summary']['use_mock_llm'] else 'OFF'}")
    print(f"Basic chat preview: {result['summary']['basic_chat_preview'] or '[empty]'}")
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
