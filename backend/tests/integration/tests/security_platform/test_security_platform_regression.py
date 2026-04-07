from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import parse_qs
from urllib.parse import urlparse
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
REPO_ROOT = Path(__file__).resolve().parents[5]
PLAYBOOK_RUNNER = REPO_ROOT / "knowledge-base" / "run_security_playbook.py"
SECURITY_PERSONA_TOOL_REQUIREMENTS = {
    "安全事件分析师": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL"},
        "custom_tools": {
            "threat_intel_lookup",
            "create_security_ticket",
            "search_security_alerts",
            "isolate_endpoint_host",
            "lookup_asset_context",
        },
    },
    "应急响应指挥官": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
        "custom_tools": {
            "send_security_alert",
            "create_security_ticket",
            "search_security_alerts",
            "isolate_endpoint_host",
        },
    },
    "漏洞评估专家": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL", "Code Interpreter"},
        "custom_tools": {
            "threat_intel_lookup",
            "create_security_ticket",
            "lookup_asset_context",
        },
    },
    "合规审计员": {
        "builtin_tools": {"Internal Search", "Web Search", "Open URL"},
        "custom_tools": {"create_security_ticket", "lookup_asset_context"},
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
PERSONA_LIVE_CHAT_SCENARIOS = [
    (
        "安全事件分析师",
        "REGRESSION_LIVE_OK_ANALYST",
        "你是安全事件分析师。请直接回复字符串 REGRESSION_LIVE_OK_ANALYST，不要添加任何其他内容。",
    ),
    (
        "应急响应指挥官",
        "REGRESSION_LIVE_OK_COMMANDER",
        "你是应急响应指挥官。请直接回复字符串 REGRESSION_LIVE_OK_COMMANDER，不要添加任何其他内容。",
    ),
    (
        "漏洞评估专家",
        "REGRESSION_LIVE_OK_VULN",
        "你是漏洞评估专家。请直接回复字符串 REGRESSION_LIVE_OK_VULN，不要添加任何其他内容。",
    ),
    (
        "合规审计员",
        "REGRESSION_LIVE_OK_COMPLIANCE",
        "你是合规审计员。请直接回复字符串 REGRESSION_LIVE_OK_COMPLIANCE，不要添加任何其他内容。",
    ),
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
    {
        "persona_name": "安全事件分析师",
        "tool_name": "search_security_alerts",
        "prompt": "检索 powershell 告警。",
        "mock_llm_response": json.dumps(
            {
                "name": "search_security_alerts",
                "arguments": {
                    "query": "powershell",
                    "severity": "high",
                    "limit": 5,
                },
            }
        ),
        "expected_method": "GET",
        "expected_path_fragment": "/alerts/search",
    },
    {
        "persona_name": "安全事件分析师",
        "tool_name": "isolate_endpoint_host",
        "prompt": "隔离 finance-host-01 主机。",
        "mock_llm_response": json.dumps(
            {
                "name": "isolate_endpoint_host",
                "arguments": {
                    "host_id": "finance-host-01",
                    "reason": "Regression containment flow",
                },
            }
        ),
        "expected_method": "POST",
        "expected_path_fragment": "/hosts/finance-host-01/isolate",
    },
    {
        "persona_name": "漏洞评估专家",
        "tool_name": "lookup_asset_context",
        "prompt": "查询 finance-host-01 的资产上下文。",
        "mock_llm_response": json.dumps(
            {
                "name": "lookup_asset_context",
                "arguments": {
                    "hostname": "finance-host-01",
                    "limit": 3,
                },
            }
        ),
        "expected_method": "GET",
        "expected_path_fragment": "/assets/search",
    },
]

LIVE_TOOL_INVOCATION_SCENARIOS = [
    {
        "persona_name": "安全事件分析师",
        "tool_name": "search_security_alerts",
        "prompt": "请仅使用 search_security_alerts 查询 query=powershell、severity=high、limit=5，并用一句话总结结果。",
        "expected_method": "GET",
        "expected_path_fragment": "/alerts/search",
        "response_markers": ["ALERT-1001", "PowerShell", "finance-host-01"],
    },
    {
        "persona_name": "安全事件分析师",
        "tool_name": "isolate_endpoint_host",
        "prompt": "请仅使用 isolate_endpoint_host 隔离 host_id=finance-host-01，reason=Regression containment flow，并简要确认。",
        "expected_method": "POST",
        "expected_path_fragment": "/hosts/finance-host-01/isolate",
        "response_markers": ["finance-host-01", "queued", "isolate"],
    },
    {
        "persona_name": "漏洞评估专家",
        "tool_name": "lookup_asset_context",
        "prompt": "请仅使用 lookup_asset_context 查询 hostname=finance-host-01、limit=3，并简要总结资产上下文。",
        "expected_method": "GET",
        "expected_path_fragment": "/assets/search",
        "response_markers": ["finance-host-01", "Finance", "asset-001"],
    },
]

PLAYBOOK_EXECUTION_SCENARIOS = [
    {
        "playbook": "incident-triage-readonly",
        "inputs": {
            "incident_ip": "8.8.8.8",
            "asset_hostname": "finance-host-01",
            "alert_query": "powershell",
        },
        "expected_request_paths": [
            "/alerts/search",
            "/assets/search",
            "/ip_addresses/8.8.8.8",
        ],
        "expected_step_ids": [
            "search_alerts",
            "lookup_asset",
            "lookup_threat_intel",
            "commander_summary",
        ],
        "expected_step_tools": {
            "search_alerts": "search_security_alerts",
            "lookup_asset": "lookup_asset_context",
            "lookup_threat_intel": "threat_intel_lookup",
            "commander_summary": None,
        },
        "expected_markers": [
            "finance-host-01",
            "powershell",
            "Suspicious PowerShell",
            "8.8.8.8",
        ],
    },
    {
        "playbook": "incident-containment-and-ticketing",
        "inputs": {
            "incident_ip": "8.8.8.8",
            "asset_hostname": "finance-host-01",
            "host_id": "finance-host-01",
            "alert_query": "powershell",
        },
        "expected_request_paths": [
            "/alerts/search",
            "/assets/search",
            "/ip_addresses/8.8.8.8",
            "/issue",
            "/",
            "/hosts/finance-host-01/isolate",
        ],
        "expected_step_ids": [
            "search_alerts",
            "lookup_asset",
            "lookup_threat_intel",
            "create_ticket",
            "send_alert",
            "isolate_host",
        ],
        "expected_step_tools": {
            "search_alerts": "search_security_alerts",
            "lookup_asset": "lookup_asset_context",
            "lookup_threat_intel": "threat_intel_lookup",
            "create_ticket": "create_security_ticket",
            "send_alert": "send_security_alert",
            "isolate_host": "isolate_endpoint_host",
        },
        "expected_markers": [
            "queued",
            "finance-host-01",
            "SEC-",
            "8.8.8.8",
        ],
    },
]


@dataclass
class SeededSecurityPlatform:
    admin_user: DATestUser
    mock_server_url: str
    supports_mock_llm: bool
    default_text_model: str | None
    available_text_models: set[str]


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


def _get_llm_provider_state(user: DATestUser) -> tuple[str | None, set[str]]:
    response = requests.get(
        f"{FRONTEND_API_URL}/admin/llm/provider",
        headers=user.headers,
        cookies=user.cookies,
        timeout=20,
    )
    response.raise_for_status()
    data = response.json()

    default_text = data.get("default_text") or {}
    default_model = str(default_text.get("model_name", "")).strip() or None
    model_names: set[str] = set()

    for provider in data.get("providers", []):
        if not isinstance(provider, dict):
            continue
        for config in provider.get("model_configurations", []):
            if not isinstance(config, dict):
                continue
            model_name = str(config.get("name", "")).strip()
            if model_name:
                model_names.add(model_name)

    return default_model, model_names


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


def _run_playbook(
    playbook: str,
    inputs: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(PLAYBOOK_RUNNER),
        "--execute",
        "--json",
        "--playbook",
        playbook,
        "--url",
        FRONTEND_API_URL,
        "--email",
        ADMIN_EMAIL,
        "--password",
        ADMIN_PASSWORD,
        "--step-timeout-seconds",
        "20",
    ]
    for key, value in inputs.items():
        command.extend(["--input", f"{key}={value}"])
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )


def _find_mock_request(
    requests_received: list[dict[str, Any]],
    *,
    method: str,
    path_fragment: str | None = None,
    exact_path: str | None = None,
) -> dict[str, Any]:
    assert path_fragment or exact_path
    request = next(
        (
            request
            for request in requests_received
            if request["method"] == method
            and (
                (path_fragment is not None and path_fragment in request["path"])
                or (exact_path is not None and request["path"] == exact_path)
            )
        ),
        None,
    )
    assert request is not None, requests_received
    return request


def _query_params(path: str) -> dict[str, str]:
    parsed = urlparse(path)
    return {
        key: values[0]
        for key, values in parse_qs(parsed.query).items()
        if values
    }


def _verify_playbook_definitions() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(PLAYBOOK_RUNNER),
            "--verify-definitions",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


@pytest.fixture(scope="module")
def seeded_security_platform(
    mock_security_tools_server: str,
) -> Generator[SeededSecurityPlatform, None, None]:
    admin_user = _login_admin_user()
    analyst_id = int(_get_persona_map(admin_user)["安全事件分析师"]["id"])
    default_text_model, available_text_models = _get_llm_provider_state(admin_user)
    yield SeededSecurityPlatform(
        admin_user=admin_user,
        mock_server_url=mock_security_tools_server,
        supports_mock_llm=_supports_mock_llm(admin_user, analyst_id),
        default_text_model=default_text_model,
        available_text_models=available_text_models,
    )


def test_security_platform_playbook_definition_regression() -> None:
    process = _verify_playbook_definitions()

    assert process.returncode == 0, process.stderr or process.stdout
    assert "[OK] Verified" in process.stdout


def test_security_platform_glm5_configuration_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    assert "glm-5" in seeded_security_platform.available_text_models
    assert seeded_security_platform.default_text_model == "glm-5"


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


@pytest.mark.parametrize(
    ("persona_name", "token", "prompt"), PERSONA_LIVE_CHAT_SCENARIOS
)
def test_security_platform_persona_live_chat_regression(
    seeded_security_platform: SeededSecurityPlatform,
    persona_name: str,
    token: str,
    prompt: str,
) -> None:
    persona_id = int(_get_persona_map(seeded_security_platform.admin_user)[persona_name]["id"])
    chat_session_id = _create_chat_session(
        seeded_security_platform.admin_user,
        persona_id,
        description=f"regression-live-chat-{persona_name}-{uuid.uuid4()}",
    )

    response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=prompt,
    )

    assert response["error"] is None, f"Unexpected error for {persona_name}: {response['error']}"
    assert token in response["full_message"], (
        persona_name,
        token,
        response["full_message"],
    )


@pytest.mark.glm5_live
def test_security_platform_glm5_reasoning_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    if seeded_security_platform.default_text_model != "glm-5":
        pytest.skip(
            f"Current default text model is {seeded_security_platform.default_text_model!r}, not glm-5"
        )

    analyst = _get_persona_map(seeded_security_platform.admin_user)["安全事件分析师"]
    chat_session_id = _create_chat_session(
        seeded_security_platform.admin_user,
        int(analyst["id"]),
        description=f"regression-glm5-analyst-{uuid.uuid4()}",
    )

    response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=(
            "你正在处理一条安全告警。已知可疑 IP 为 8.8.8.8，资产主机名为 finance-host-01。"
            "请用中文给出简短研判，输出中必须包含“事件判断”和“下一步建议”两个小标题，"
            "并且必须显式提到 8.8.8.8 和 finance-host-01。"
        ),
    )

    assert response["error"] is None, response
    assert "事件判断" in response["full_message"], response["full_message"]
    assert "下一步建议" in response["full_message"], response["full_message"]
    assert "8.8.8.8" in response["full_message"], response["full_message"]
    assert "finance-host-01" in response["full_message"], response["full_message"]


@pytest.mark.glm5_live
def test_security_platform_glm5_tool_selection_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    if seeded_security_platform.default_text_model != "glm-5":
        pytest.skip(
            f"Current default text model is {seeded_security_platform.default_text_model!r}, not glm-5"
        )

    analyst = _get_persona_map(seeded_security_platform.admin_user)["安全事件分析师"]
    chat_session_id = _create_chat_session(
        seeded_security_platform.admin_user,
        int(analyst["id"]),
        description=f"regression-glm5-tool-selection-{uuid.uuid4()}",
    )

    clear_mock_requests(seeded_security_platform.mock_server_url)
    response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=(
            "请使用 search_security_alerts 查询 powershell 的高危告警，"
            "并用中文一句话总结结果。"
        ),
    )

    assert response["error"] is None, response

    requests_received = get_mock_requests(seeded_security_platform.mock_server_url)
    assert requests_received, "Expected GLM5 to trigger at least one mock security tool request"
    assert any("/alerts/search" in request["path"] for request in requests_received), requests_received
    assert any(
        marker in response["full_message"]
        for marker in ["finance-host-01", "PowerShell", "高危", "待处理"]
    ), response["full_message"]


@pytest.mark.glm5_live
def test_security_platform_glm5_multi_step_live_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    if seeded_security_platform.default_text_model != "glm-5":
        pytest.skip(
            f"Current default text model is {seeded_security_platform.default_text_model!r}, not glm-5"
        )

    analyst = _get_persona_map(seeded_security_platform.admin_user)["安全事件分析师"]
    chat_session_id = _create_chat_session(
        seeded_security_platform.admin_user,
        int(analyst["id"]),
        description=f"regression-glm5-multi-step-{uuid.uuid4()}",
    )

    clear_mock_requests(seeded_security_platform.mock_server_url)
    first_response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=(
            "请先查询 powershell 的高危告警，再查询 finance-host-01 的资产上下文，"
            "然后用中文给出简短研判。"
        ),
    )

    assert first_response["error"] is None, first_response
    first_requests = get_mock_requests(seeded_security_platform.mock_server_url)
    assert any("/alerts/search" in request["path"] for request in first_requests), first_requests
    assert any("/assets/search" in request["path"] for request in first_requests), first_requests
    assert "finance-host-01" in first_response["full_message"], first_response["full_message"]

    clear_mock_requests(seeded_security_platform.mock_server_url)
    second_response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=(
            "基于你刚才拿到的告警和资产信息，输出最终结论。"
            "结果中必须包含“事件判断”和“下一步建议”两个小标题。"
        ),
    )

    assert second_response["error"] is None, second_response
    assert "事件判断" in second_response["full_message"], second_response["full_message"]
    assert "下一步建议" in second_response["full_message"], second_response["full_message"]
    assert any(
        marker in second_response["full_message"]
        for marker in ["finance-host-01", "PowerShell", "高危", "Finance"]
    ), second_response["full_message"]


@pytest.mark.glm5_live
def test_security_platform_glm5_investigation_to_ticket_live_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    if seeded_security_platform.default_text_model != "glm-5":
        pytest.skip(
            f"Current default text model is {seeded_security_platform.default_text_model!r}, not glm-5"
        )

    analyst = _get_persona_map(seeded_security_platform.admin_user)["安全事件分析师"]
    chat_session_id = _create_chat_session(
        seeded_security_platform.admin_user,
        int(analyst["id"]),
        description=f"regression-glm5-investigation-ticket-{uuid.uuid4()}",
    )

    clear_mock_requests(seeded_security_platform.mock_server_url)
    first_response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=(
            "请先查询 powershell 的高危告警，再查询 finance-host-01 的资产上下文，"
            "最后用中文简要说明为什么这个事件值得继续跟进。"
        ),
    )

    assert first_response["error"] is None, first_response
    first_requests = get_mock_requests(seeded_security_platform.mock_server_url)
    assert any("/alerts/search" in request["path"] for request in first_requests), first_requests
    assert any("/assets/search" in request["path"] for request in first_requests), first_requests
    assert any(
        marker in first_response["full_message"]
        for marker in ["finance-host-01", "PowerShell", "高危", "Finance"]
    ), first_response["full_message"]

    clear_mock_requests(seeded_security_platform.mock_server_url)
    second_response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=(
            "基于你刚才拿到的上下文，请自主决定是否需要创建安全工单。"
            "如果需要，请直接使用 create_security_ticket 创建一条工单，"
            "并在回复中包含工单编号或创建结果，同时明确提到 finance-host-01。"
        ),
    )

    assert second_response["error"] is None, second_response
    second_requests = get_mock_requests(seeded_security_platform.mock_server_url)
    ticket_request = _find_mock_request(
        second_requests,
        method="POST",
        path_fragment="/issue",
    )
    assert ticket_request["body"]["project_key"] in {"SEC", "SOC"}
    assert "finance-host-01" in ticket_request["body"]["summary"]
    assert any(
        marker in second_response["full_message"]
        for marker in ["SEC-", "工单", "finance-host-01"]
    ), second_response["full_message"]


@pytest.mark.glm5_live
def test_security_platform_glm5_investigation_to_isolation_live_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    if seeded_security_platform.default_text_model != "glm-5":
        pytest.skip(
            f"Current default text model is {seeded_security_platform.default_text_model!r}, not glm-5"
        )

    analyst = _get_persona_map(seeded_security_platform.admin_user)["安全事件分析师"]
    chat_session_id = _create_chat_session(
        seeded_security_platform.admin_user,
        int(analyst["id"]),
        description=f"regression-glm5-investigation-isolation-{uuid.uuid4()}",
    )

    clear_mock_requests(seeded_security_platform.mock_server_url)
    first_response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=(
            "请先查询 powershell 的高危告警，再查询 finance-host-01 的资产上下文，"
            "然后用中文简要说明该主机是否存在立即处置的必要。"
        ),
    )

    assert first_response["error"] is None, first_response
    first_requests = get_mock_requests(seeded_security_platform.mock_server_url)
    assert any("/alerts/search" in request["path"] for request in first_requests), first_requests
    assert any("/assets/search" in request["path"] for request in first_requests), first_requests
    assert any(
        marker in first_response["full_message"]
        for marker in ["finance-host-01", "PowerShell", "高危", "Finance"]
    ), first_response["full_message"]

    clear_mock_requests(seeded_security_platform.mock_server_url)
    second_response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=(
            "如果你判断需要立即处置，请直接使用 isolate_endpoint_host 隔离 host_id=finance-host-01，"
            "reason 请明确写出与 powershell 告警相关，并在回复中确认隔离结果。"
        ),
    )

    assert second_response["error"] is None, second_response
    second_requests = get_mock_requests(seeded_security_platform.mock_server_url)
    isolate_request = _find_mock_request(
        second_requests,
        method="POST",
        path_fragment="/hosts/finance-host-01/isolate",
    )
    assert "finance-host-01" in isolate_request["body"]["reason"]
    assert "powershell" in isolate_request["body"]["reason"].lower()
    assert any(
        marker in second_response["full_message"]
        for marker in ["finance-host-01", "queued", "隔离", "isolate"]
    ), second_response["full_message"]


def test_security_platform_threat_intel_live_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    analyst = _get_persona_map(seeded_security_platform.admin_user)["安全事件分析师"]
    analyst_detail = _get_persona_detail(
        seeded_security_platform.admin_user, int(analyst["id"])
    )
    threat_intel_tool_id = next(
        int(tool["id"])
        for tool in analyst_detail.get("tools", [])
        if tool["name"] == "threat_intel_lookup"
    )

    chat_session_id = _create_chat_session(
        seeded_security_platform.admin_user,
        int(analyst["id"]),
        description=f"regression-live-tool-threat-intel-{uuid.uuid4()}",
    )

    response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message="请使用 threat_intel_lookup 查询 8.8.8.8 的威胁情报，并用一句话总结结果。",
        forced_tool_id=threat_intel_tool_id,
    )

    assert response["error"] is None, f"Unexpected error: {response['error']}"
    assert any(
        marker in response["full_message"]
        for marker in ["8.8.8.8", "Google", "resolver", "DNS", "reputation"]
    ), response["full_message"]


@pytest.mark.parametrize("scenario", LIVE_TOOL_INVOCATION_SCENARIOS)
def test_security_platform_live_tool_invocation_regression(
    seeded_security_platform: SeededSecurityPlatform,
    scenario: dict[str, Any],
) -> None:
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
        description=f"regression-live-tool-{scenario['tool_name']}-{uuid.uuid4()}",
    )

    response = _send_chat_message(
        seeded_security_platform.admin_user,
        chat_session_id,
        message=scenario["prompt"],
        forced_tool_id=tool_id,
    )

    assert response["error"] is None, f"Unexpected error: {response['error']}"
    requests_received = get_mock_requests(seeded_security_platform.mock_server_url)
    assert requests_received, f"No mock requests observed for {scenario['tool_name']}"
    matching_request = next(
        (
            request
            for request in requests_received
            if request["method"] == scenario["expected_method"]
            and scenario["expected_path_fragment"] in request["path"]
        ),
        None,
    )
    assert matching_request is not None, requests_received
    assert any(
        marker in response["full_message"] for marker in scenario["response_markers"]
    ), response["full_message"]


@pytest.mark.parametrize("scenario", PLAYBOOK_EXECUTION_SCENARIOS)
def test_security_platform_playbook_execution_regression(
    seeded_security_platform: SeededSecurityPlatform,
    scenario: dict[str, Any],
) -> None:
    clear_mock_requests(seeded_security_platform.mock_server_url)
    process = _run_playbook(
        playbook=scenario["playbook"],
        inputs=scenario["inputs"],
    )

    assert process.returncode == 0, process.stderr or process.stdout
    result = json.loads(process.stdout)
    assert result["ok"] is True, result
    assert result["failures"] == [], result

    observed_step_ids = [step["id"] for step in result["steps"]]
    assert observed_step_ids == scenario["expected_step_ids"], result["steps"]
    observed_step_tools = {step["id"]: step.get("tool") for step in result["steps"]}
    assert observed_step_tools == scenario["expected_step_tools"], result["steps"]

    rendered_output = json.dumps(result, ensure_ascii=False)
    for marker in scenario["expected_markers"]:
        assert marker in rendered_output, rendered_output

    requests_received = get_mock_requests(seeded_security_platform.mock_server_url)
    observed_paths = [request["path"] for request in requests_received]
    for expected_path in scenario["expected_request_paths"]:
        assert any(expected_path in path for path in observed_paths), observed_paths


def test_security_platform_containment_playbook_request_rendering_regression(
    seeded_security_platform: SeededSecurityPlatform,
) -> None:
    clear_mock_requests(seeded_security_platform.mock_server_url)
    process = _run_playbook(
        playbook="incident-containment-and-ticketing",
        inputs={
            "incident_ip": "8.8.8.8",
            "asset_hostname": "finance-host-01",
            "host_id": "finance-host-01",
            "alert_query": "powershell",
        },
    )

    assert process.returncode == 0, process.stderr or process.stdout
    result = json.loads(process.stdout)
    assert result["ok"] is True, result
    assert result["failures"] == [], result

    requests_received = get_mock_requests(seeded_security_platform.mock_server_url)
    assert len(requests_received) == 6, requests_received

    alerts_request = _find_mock_request(
        requests_received,
        method="GET",
        path_fragment="/alerts/search",
    )
    alerts_query = _query_params(alerts_request["path"])
    assert alerts_query["query"] == "powershell"
    assert alerts_query["severity"] == "high"
    assert alerts_query["limit"] == "5"

    asset_request = _find_mock_request(
        requests_received,
        method="GET",
        path_fragment="/assets/search",
    )
    asset_query = _query_params(asset_request["path"])
    assert asset_query["hostname"] == "finance-host-01"
    assert asset_query["limit"] == "1"

    threat_intel_request = _find_mock_request(
        requests_received,
        method="GET",
        path_fragment="/ip_addresses/8.8.8.8",
    )
    assert threat_intel_request["body"] is None

    create_ticket_request = _find_mock_request(
        requests_received,
        method="POST",
        path_fragment="/issue",
    )
    assert create_ticket_request["body"]["summary"] == "Security incident on finance-host-01"
    assert create_ticket_request["body"]["priority"] == "HIGH"
    assert create_ticket_request["body"]["project_key"] == "SEC"
    assert "Onyx playbook" in create_ticket_request["body"]["description"]

    send_alert_request = _find_mock_request(
        requests_received,
        method="POST",
        exact_path="/",
    )
    assert send_alert_request["body"]["alert_type"] == "UNAUTHORIZED_ACCESS"
    assert send_alert_request["body"]["severity"] == "P1"
    assert send_alert_request["body"]["title"] == "Incident escalation for finance-host-01"
    assert send_alert_request["body"]["source_system"] == "Onyx Security Platform"

    isolate_request = _find_mock_request(
        requests_received,
        method="POST",
        path_fragment="/hosts/finance-host-01/isolate",
    )
    assert isolate_request["body"]["reason"] == "Suspicious incident on finance-host-01"
    assert isolate_request["body"]["requested_by"] == "Onyx playbook"


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

    assert response["error"] is None, f"Unexpected error for {persona_name}: {response['error']}"
    assert token in response["full_message"]


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
        forced_tool_id=tool_id,
        mock_llm_response=scenario["mock_llm_response"],
    )

    assert response["error"] is None, f"Unexpected error: {response['error']}"
    assert len(response["tool_call_debug"]) == 1
    assert response["tool_call_debug"][0]["tool_name"] == scenario["tool_name"]

    requests_received = get_mock_requests(seeded_security_platform.mock_server_url)
    assert len(requests_received) == 1
    request = requests_received[0]
    assert request["method"] == scenario["expected_method"]
    assert scenario["expected_path_fragment"] in request["path"]
