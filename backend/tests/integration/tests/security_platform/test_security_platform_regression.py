from __future__ import annotations

import json
import os
import uuid
from collections.abc import Generator
from dataclasses import dataclass
from typing import Any

import pytest
import requests

from onyx.auth.schemas import UserRole
from tests.integration.common_utils.test_models import DATestUser
from tests.integration.tests.security_tools.conftest import clear_mock_requests
from tests.integration.tests.security_tools.conftest import get_mock_requests
from tests.integration.tests.security_tools.conftest import mock_security_tools_server  # noqa: F401

FRONTEND_API_URL = os.environ.get("ONYX_TEST_API_URL", "http://127.0.0.1:3000/api")
ADMIN_EMAIL = os.environ.get("ONYX_EMAIL", "security-admin@onyx.local")
ADMIN_PASSWORD = os.environ.get("ONYX_PASSWORD", "admin123")
SECURITY_DOCUMENT_SET_NAME = "安全知识库"
SECURITY_PERSONA_TOOL_REQUIREMENTS = {
    "安全事件分析师": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL"},
        "custom_tools": {"threat_intel_lookup", "create_security_ticket"},
    },
    "应急响应指挥官": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
        "custom_tools": {"send_security_alert", "create_security_ticket"},
    },
    "漏洞评估专家": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
        "custom_tools": {"threat_intel_lookup", "create_security_ticket"},
    },
    "合规审计员": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL"},
        "custom_tools": {"create_security_ticket"},
    },
}
USER_PERSONA_BY_EMAIL = {
    "commander@security.local": "应急响应指挥官",
    "analyst@security.local": "安全事件分析师",
    "vuln_expert@security.local": "漏洞评估专家",
    "auditor@security.local": "合规审计员",
}
PERSONA_CHAT_SCENARIOS = [
    ("安全事件分析师", "REGRESSION_OK_ANALYST"),
    ("应急响应指挥官", "REGRESSION_OK_COMMANDER"),
    ("漏洞评估专家", "REGRESSION_OK_VULN"),
    ("合规审计员", "REGRESSION_OK_COMPLIANCE"),
]
TOOL_INVOCATION_SCENARIOS = [
    {
        "persona_name": "应急响应指挥官",
        "tool_name": "send_security_alert",
        "prompt": "发送一条 phishing 安全告警。",
        "mock_llm_response": json.dumps(
            {
                "name": "send_security_alert",
                "arguments": {
                    "alert_type": "PHISHING",
                    "severity": "P1",
                    "title": "Regression phishing alert",
                    "description": "Regression test alert",
                    "source_system": "Onyx Integration Test",
                },
            }
        ),
        "expected_method": "POST",
        "expected_path_fragment": "/",
    },
    {
        "persona_name": "安全事件分析师",
        "tool_name": "create_security_ticket",
        "prompt": "为关键漏洞创建工单。",
        "mock_llm_response": json.dumps(
            {
                "name": "create_security_ticket",
                "arguments": {
                    "summary": "Regression vulnerability ticket",
                    "description": "Regression test ticket",
                    "priority": "CRITICAL",
                    "project_key": "SEC",
                },
            }
        ),
        "expected_method": "POST",
        "expected_path_fragment": "/issue",
    },
    {
        "persona_name": "安全事件分析师",
        "tool_name": "threat_intel_lookup",
        "prompt": "查询 8.8.8.8 的威胁情报。",
        "mock_llm_response": json.dumps(
            {
                "name": "threat_intel_lookup",
                "arguments": {"ip": "8.8.8.8"},
            }
        ),
        "expected_method": "GET",
        "expected_path_fragment": "/ip_addresses/8.8.8.8",
    },
]


@dataclass
class SeededSecurityPlatform:
    admin_user: DATestUser
    mock_server_url: str
    supports_mock_llm: bool


def _extract_cookie(response: requests.Response) -> str:
    cookie = response.cookies.get("fastapiusersauth")
    if cookie:
        return cookie

    set_cookie = response.headers.get("set-cookie", "")
    for part in set_cookie.split(","):
        part = part.strip()
        if "fastapiusersauth=" in part:
            return part.split(";")[0].split("=")[1]
    raise RuntimeError("Login succeeded but fastapiusersauth cookie was missing")


def _login_admin_user() -> DATestUser:
    response = requests.post(
        f"{FRONTEND_API_URL}/auth/login",
        data={"username": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )
    response.raise_for_status()
    cookie = _extract_cookie(response)

    user = DATestUser(
        id="",
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
        headers={"Content-Type": "application/json", "Cookie": f"fastapiusersauth={cookie}; "},
        role=UserRole.ADMIN,
        is_active=True,
        cookies={"fastapiusersauth": cookie},
    )
    me_response = requests.get(
        f"{FRONTEND_API_URL}/me",
        headers=user.headers,
        cookies=user.cookies,
        timeout=20,
    )
    me_response.raise_for_status()
    me = me_response.json()
    user.id = me["id"]
    user.role = UserRole(me["role"])
    return user


def _create_chat_session(user: DATestUser, persona_id: int, description: str) -> str:
    response = requests.post(
        f"{FRONTEND_API_URL}/chat/create-chat-session",
        json={"persona_id": persona_id, "description": description},
        headers=user.headers,
        cookies=user.cookies,
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


def _send_chat_message(
    user: DATestUser,
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
        f"{FRONTEND_API_URL}/chat/send-chat-message",
        json=payload,
        headers=user.headers,
        cookies=user.cookies,
        stream=True,
        timeout=120,
    )
    response.raise_for_status()
    return _parse_stream_response(response)


def _supports_mock_llm(user: DATestUser, persona_id: int) -> bool:
    chat_session_id = _create_chat_session(
        user,
        persona_id,
        description=f"regression-mock-probe-{uuid.uuid4()}",
    )
    try:
        result = _send_chat_message(
            user,
            chat_session_id,
            "mock probe",
            mock_llm_response="REGRESSION_MOCK_OK",
        )
    except requests.HTTPError:
        return False
    return result["error"] is None and "REGRESSION_MOCK_OK" in result["full_message"]


def _list_personas(user: DATestUser) -> list[dict[str, Any]]:
    response = requests.get(
        f"{FRONTEND_API_URL}/persona",
        headers=user.headers,
        cookies=user.cookies,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def _get_persona_detail(user: DATestUser, persona_id: int) -> dict[str, Any]:
    response = requests.get(
        f"{FRONTEND_API_URL}/persona/{persona_id}",
        headers=user.headers,
        cookies=user.cookies,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def _get_persona_map(user: DATestUser) -> dict[str, dict[str, Any]]:
    persona_map: dict[str, dict[str, Any]] = {}
    for persona in _list_personas(user):
        if persona["name"] in SECURITY_PERSONA_TOOL_REQUIREMENTS:
            persona_map[persona["name"]] = _get_persona_detail(user, int(persona["id"]))
    return persona_map


def _list_document_sets(user: DATestUser) -> list[dict[str, Any]]:
    response = requests.get(
        f"{FRONTEND_API_URL}/manage/document-set?get_editable=true",
        headers=user.headers,
        cookies=user.cookies,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def _get_document_set(user: DATestUser) -> dict[str, Any] | None:
    return next(
        (
            document_set
            for document_set in _list_document_sets(user)
            if document_set["name"] == SECURITY_DOCUMENT_SET_NAME
        ),
        None,
    )


def _list_users(user: DATestUser) -> list[dict[str, Any]]:
    response = requests.get(
        f"{FRONTEND_API_URL}/manage/users/accepted?page_num=0&page_size=100",
        headers=user.headers,
        cookies=user.cookies,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()["items"]


@pytest.fixture(scope="module")
def seeded_security_platform(
    mock_security_tools_server: str,
) -> Generator[SeededSecurityPlatform, None, None]:
    admin_user = _login_admin_user()
    analyst_id = int(_get_persona_map(admin_user)["安全事件分析师"]["id"])
    yield SeededSecurityPlatform(
        admin_user=admin_user,
        mock_server_url=mock_security_tools_server,
        supports_mock_llm=_supports_mock_llm(admin_user, analyst_id),
    )


def _tool_aliases(persona: dict[str, Any]) -> set[str]:
    aliases: set[str] = set()
    for tool in persona.get("tools", []):
        for field in ("name", "display_name", "in_code_tool_id"):
            value = tool.get(field)
            if value:
                aliases.add(str(value))
    return aliases


def test_security_platform_resource_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    document_set = _get_document_set(seeded_security_platform.admin_user)
    assert document_set is not None

    persona_map = _get_persona_map(seeded_security_platform.admin_user)
    assert set(persona_map.keys()) == set(SECURITY_PERSONA_TOOL_REQUIREMENTS.keys())

    for persona_name, persona in persona_map.items():
        assert persona["is_public"] is False, f"{persona_name} should be private"
        document_sets = persona.get("document_sets", [])
        document_set_names = {doc_set["name"] for doc_set in document_sets}
        assert SECURITY_DOCUMENT_SET_NAME in document_set_names


def test_security_platform_rbac_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    persona_map = _get_persona_map(seeded_security_platform.admin_user)
    document_set = _get_document_set(seeded_security_platform.admin_user)
    assert document_set is not None

    users = _list_users(seeded_security_platform.admin_user)
    user_by_email = {
        user["email"]: user for user in users if user["email"] in USER_PERSONA_BY_EMAIL
    }
    assert set(user_by_email.keys()) == set(USER_PERSONA_BY_EMAIL.keys())

    for email, persona_name in USER_PERSONA_BY_EMAIL.items():
        user = user_by_email[email]
        persona = persona_map[persona_name]
        expected_role = UserRole.ADMIN.value if persona_name == "应急响应指挥官" else UserRole.BASIC.value
        assert user["role"] == expected_role

        persona_user_ids = {linked_user["id"] for linked_user in persona.get("users", [])}
        document_set_user_ids = set(document_set.get("users", []))
        assert user["id"] in persona_user_ids
        assert user["id"] in document_set_user_ids


def test_security_platform_tool_matrix_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    persona_map = _get_persona_map(seeded_security_platform.admin_user)

    for persona_name, expected in SECURITY_PERSONA_TOOL_REQUIREMENTS.items():
        aliases = _tool_aliases(persona_map[persona_name])
        assert expected["builtin_tools"].issubset(aliases), (
            persona_name,
            expected["builtin_tools"],
            aliases,
        )
        assert expected["custom_tools"].issubset(aliases), (
            persona_name,
            expected["custom_tools"],
            aliases,
        )


@pytest.mark.parametrize(("persona_name", "token"), PERSONA_CHAT_SCENARIOS)
def test_security_platform_persona_chat_regression(
    seeded_security_platform: SeededSecurityPlatform,
    persona_name: str,
    token: str,
) -> None:
    if not seeded_security_platform.supports_mock_llm:
        pytest.skip("mock_llm_response is not enabled in the current deployment")

    persona_id = int(_get_persona_map(seeded_security_platform.admin_user)[persona_name]["id"])
    chat_session_id = _create_chat_session(
        seeded_security_platform.admin_user,
        persona_id,
        description=f"regression-chat-{persona_name}-{uuid.uuid4()}",
    )

    response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=f"请直接回复 {token}。",
        mock_llm_response=token,
    )

    assert response.error is None, f"Unexpected error for {persona_name}: {response.error}"
    assert token in response.full_message


@pytest.mark.parametrize("scenario", TOOL_INVOCATION_SCENARIOS)
def test_security_platform_tool_invocation_regression(
    seeded_security_platform: SeededSecurityPlatform,
    scenario: dict[str, Any],
) -> None:
    if not seeded_security_platform.supports_mock_llm:
        pytest.skip("mock_llm_response is not enabled in the current deployment")

    persona = _get_persona_map(seeded_security_platform.admin_user)[scenario["persona_name"]]
    persona_detail = _get_persona_detail(
        seeded_security_platform.admin_user, int(persona["id"])
    )
    tool_id = next(
        int(tool["id"])
        for tool in persona_detail.get("tools", [])
        if tool["name"] == scenario["tool_name"]
    )

    clear_mock_requests(seeded_security_platform.mock_server_url)
    chat_session_id = _create_chat_session(
        seeded_security_platform.admin_user,
        int(persona["id"]),
        description=f"regression-tool-{scenario['tool_name']}-{uuid.uuid4()}",
    )

    response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=scenario["prompt"],
        forced_tool_ids=[tool_id],
        mock_llm_response=scenario["mock_llm_response"],
    )

    assert response.error is None, f"Unexpected error: {response.error}"
    assert len(response.tool_call_debug) == 1
    assert response.tool_call_debug[0].tool_name == scenario["tool_name"]

    requests_received = get_mock_requests(seeded_security_platform.mock_server_url)
    assert len(requests_received) == 1
    request = requests_received[0]
    assert request["method"] == scenario["expected_method"]
    assert scenario["expected_path_fragment"] in request["path"]
