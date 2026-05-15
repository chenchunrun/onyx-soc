"""
End-to-end integration tests for security tools.

Verifies the complete chain:
    persona → Onyx backend → HTTP call → mock server receives request

Tests:
- send_security_alert via emergency commander persona
- create_security_ticket via security analyst persona
- threat_intel_lookup via security analyst persona

Run with:
    python -m dotenv -f .vscode/.env run --
    pytest backend/tests/integration/tests/security_tools/ -v

Requires:
    - INTEGRATION_TESTS_MODE=true (set via .env)
    - Mock server running on TEST_WEB_HOSTNAME:MOCK_SECURITY_TOOLS_PORT (default 127.0.0.1:9999)
    - Security tools pointing to host.docker.internal:9999 (mock server inside Docker)
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import select

from onyx.db.engine.sql_engine import get_session_with_current_tenant
from onyx.db.models import Persona
from tests.integration.common_utils.managers.chat import ChatSessionManager
from tests.integration.common_utils.managers.persona import PersonaManager
from tests.integration.common_utils.test_models import DATestUser
from tests.integration.tests.security_tools.conftest import (
    clear_mock_requests,
    get_mock_requests,
)


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _get_persona_by_name(name: str) -> int:
    """Look up a persona ID by name, skipping the test if not found."""
    with get_session_with_current_tenant() as db_session:
        persona = db_session.execute(
            select(Persona).where(Persona.name == name)
        ).scalar_one_or_none()
        if persona is None:
            pytest.skip(f"Persona '{name}' not found in DB — ensure migration has seeded personas")
        return persona.id


def _get_tool_id_for_persona(
    user: DATestUser,
    persona_id: int,
    tool_name: str,
) -> int:
    persona = PersonaManager.get_one(
        persona_id=persona_id,
        user_performing_action=user,
    )[0]
    for tool in persona.tools:
        if tool.name == tool_name:
            return int(tool.id)
    pytest.skip(f"Tool '{tool_name}' is not attached to persona id={persona_id}")


def _force_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
) -> str:
    """Build a mock LLM response that forces a specific tool call."""
    return json.dumps({"name": tool_name, "arguments": arguments})


# ─── send_security_alert ─────────────────────────────────────────────────────


def test_send_security_alert_invocation(
    mock_security_tools_server: str,
    admin_user: DATestUser,
    llm_provider: None,
) -> None:
    """
    Verify send_security_alert is called when persona triggers the tool.

    Chain: persona 3 (应急响应指挥官) → sendSecurityAlert → POST / → mock server
    """
    persona_id = _get_persona_by_name("应急响应指挥官")
    tool_id = _get_tool_id_for_persona(admin_user, persona_id, "send_security_alert")

    # Clear previous requests
    clear_mock_requests(mock_security_tools_server)

    # Create chat session with emergency commander persona
    chat_session = ChatSessionManager.create(
        user_performing_action=admin_user,
        persona_id=persona_id,
        description="Security alert test",
    )

    # Force the tool call with mock LLM response
    mock_response = _force_tool_call(
        "sendSecurityAlert",
        {
            "requestBody": {
                "alert_type": "PHISHING",
                "severity": "P1",
                "title": "Test Phishing Alert",
                "description": "This is a test phishing alert for automated testing",
                "source_system": "Onyx Security Knowledge Base",
            }
        },
    )

    response = ChatSessionManager.send_message(
        chat_session_id=chat_session.id,
        message="Send a security alert about a phishing attempt",
        user_performing_action=admin_user,
        forced_tool_ids=[tool_id],
        mock_llm_response=mock_response,
    )

    # Verify no error
    assert response.error is None, f"Unexpected error: {response.error}"

    # Verify tool was called
    assert len(response.tool_call_debug) == 1, f"Expected 1 tool call, got {len(response.tool_call_debug)}"
    assert response.tool_call_debug[0].tool_name == "sendSecurityAlert"
    assert response.tool_call_debug[0].tool_args["requestBody"]["alert_type"] == "PHISHING"
    assert response.tool_call_debug[0].tool_args["requestBody"]["severity"] == "P1"

    # Verify request reached mock server
    requests_received = get_mock_requests(mock_security_tools_server)
    assert len(requests_received) == 1, f"Expected 1 request, got {len(requests_received)}"
    req = requests_received[0]
    assert req["method"] == "POST"
    assert req["path"] in ("/", "/webhook")
    assert req["body"]["alert_type"] == "PHISHING"
    assert req["body"]["severity"] == "P1"


# ─── create_security_ticket ──────────────────────────────────────────────────


def test_create_security_ticket_invocation(
    mock_security_tools_server: str,
    admin_user: DATestUser,
    llm_provider: None,
) -> None:
    """
    Verify create_security_ticket is called when persona triggers the tool.

    Chain: persona 2 (安全事件分析师) → createSecurityTicket → POST /issue → mock server
    """
    persona_id = _get_persona_by_name("安全事件分析师")
    tool_id = _get_tool_id_for_persona(admin_user, persona_id, "create_security_ticket")
    clear_mock_requests(mock_security_tools_server)

    chat_session = ChatSessionManager.create(
        user_performing_action=admin_user,
        persona_id=persona_id,
        description="Ticket creation test",
    )

    mock_response = _force_tool_call(
        "createSecurityTicket",
        {
            "requestBody": {
                "summary": "CVE-2024-1234 Critical Vulnerability Assessment",
                "description": "Automated ticket creation from security analysis",
                "priority": "CRITICAL",
                "project_key": "SEC",
                "labels": ["security", "vulnerability", "automated"],
            }
        },
    )

    response = ChatSessionManager.send_message(
        chat_session_id=chat_session.id,
        message="Create a security ticket for a critical vulnerability",
        user_performing_action=admin_user,
        forced_tool_ids=[tool_id],
        mock_llm_response=mock_response,
    )

    assert response.error is None, f"Unexpected error: {response.error}"
    assert len(response.tool_call_debug) == 1, f"Expected 1 tool call, got {len(response.tool_call_debug)}"
    assert response.tool_call_debug[0].tool_name == "createSecurityTicket"
    assert response.tool_call_debug[0].tool_args["requestBody"]["priority"] == "CRITICAL"

    # Verify request reached mock server
    requests_received = get_mock_requests(mock_security_tools_server)
    assert len(requests_received) == 1, f"Expected 1 request, got {len(requests_received)}"
    req = requests_received[0]
    assert req["method"] == "POST", f"Expected POST, got {req['method']}"
    assert req["path"] == "/issue", f"Expected /issue, got {req['path']}"
    assert req["body"]["priority"] == "CRITICAL", f"Expected CRITICAL, got {req['body'].get('priority')}"
    assert req["body"]["project_key"] == "SEC", f"Expected SEC, got {req['body'].get('project_key')}"


# ─── threat_intel_lookup ─────────────────────────────────────────────────────


def test_threat_intel_ip_lookup(
    mock_security_tools_server: str,
    admin_user: DATestUser,
    llm_provider: None,
) -> None:
    """
    Verify threat_intel_lookup is called for IP lookups.

    Chain: persona 2 (安全事件分析师) → lookupIP → GET /ip_addresses/{ip} → VirusTotal
    """
    persona_id = _get_persona_by_name("安全事件分析师")
    tool_id = _get_tool_id_for_persona(admin_user, persona_id, "threat_intel_lookup")
    clear_mock_requests(mock_security_tools_server)

    chat_session = ChatSessionManager.create(
        user_performing_action=admin_user,
        persona_id=persona_id,
        description="Threat intel IP lookup test",
    )

    mock_response = _force_tool_call(
        "lookupIP",
        {"ip": "1.2.3.4"},
    )

    response = ChatSessionManager.send_message(
        chat_session_id=chat_session.id,
        message="Check the reputation of IP 1.2.3.4",
        user_performing_action=admin_user,
        forced_tool_ids=[tool_id],
        mock_llm_response=mock_response,
    )

    assert response.error is None, f"Unexpected error: {response.error}"
    assert len(response.tool_call_debug) == 1, f"Expected 1 tool call, got {len(response.tool_call_debug)}"
    assert response.tool_call_debug[0].tool_name == "lookupIP"
    args = response.tool_call_debug[0].tool_args
    assert "ip" in args, f"Expected 'ip' in tool args, got: {args}"

    # Verify request reached mock server
    requests_received = get_mock_requests(mock_security_tools_server)
    assert len(requests_received) == 1, f"Expected 1 request, got {len(requests_received)}"
    req = requests_received[0]
    assert req["method"] == "GET", f"Expected GET, got {req['method']}"
    assert "/ip_addresses/" in req["path"], f"Expected /ip_addresses/{{ip}}, got {req['path']}"


def test_threat_intel_domain_lookup(
    mock_security_tools_server: str,
    admin_user: DATestUser,
    llm_provider: None,
) -> None:
    """
    Verify threat_intel_lookup is called for domain lookups.

    Chain: persona 2 (安全事件分析师) → lookupDomain → GET /domains/{domain} → VirusTotal
    """
    persona_id = _get_persona_by_name("安全事件分析师")
    tool_id = _get_tool_id_for_persona(admin_user, persona_id, "threat_intel_lookup")
    clear_mock_requests(mock_security_tools_server)

    chat_session = ChatSessionManager.create(
        user_performing_action=admin_user,
        persona_id=persona_id,
        description="Threat intel domain lookup test",
    )

    mock_response = _force_tool_call(
        "lookupDomain",
        {"domain": "malicious-phishing-site.com"},
    )

    response = ChatSessionManager.send_message(
        chat_session_id=chat_session.id,
        message="Look up threat intelligence for domain malicious-phishing-site.com",
        user_performing_action=admin_user,
        forced_tool_ids=[tool_id],
        mock_llm_response=mock_response,
    )

    assert response.error is None, f"Unexpected error: {response.error}"
    assert len(response.tool_call_debug) == 1, f"Expected 1 tool call, got {len(response.tool_call_debug)}"
    assert response.tool_call_debug[0].tool_name == "lookupDomain"

    # Verify request reached mock server
    requests_received = get_mock_requests(mock_security_tools_server)
    assert len(requests_received) == 1, f"Expected 1 request, got {len(requests_received)}"
    req = requests_received[0]
    assert req["method"] == "GET", f"Expected GET, got {req['method']}"
    assert "/domains/" in req["path"], f"Expected /domains/{{domain}}, got {req['path']}"


def test_threat_intel_hash_lookup(
    mock_security_tools_server: str,
    admin_user: DATestUser,
    llm_provider: None,
) -> None:
    """
    Verify threat_intel_lookup is called for file hash lookups.

    Chain: persona 2 (安全事件分析师) → lookupFileHash → GET /files/{hash} → VirusTotal
    """
    persona_id = _get_persona_by_name("安全事件分析师")
    tool_id = _get_tool_id_for_persona(admin_user, persona_id, "threat_intel_lookup")
    clear_mock_requests(mock_security_tools_server)

    chat_session = ChatSessionManager.create(
        user_performing_action=admin_user,
        persona_id=persona_id,
        description="Threat intel hash lookup test",
    )

    mock_response = _force_tool_call(
        "lookupFileHash",
        {"hash": "44d88612fea8a8f36de82e1278abb02f"},
    )

    response = ChatSessionManager.send_message(
        chat_session_id=chat_session.id,
        message="Check threat intelligence for file hash 44d88612fea8a8f36de82e1278abb02f",
        user_performing_action=admin_user,
        forced_tool_ids=[tool_id],
        mock_llm_response=mock_response,
    )

    assert response.error is None, f"Unexpected error: {response.error}"
    assert len(response.tool_call_debug) == 1, f"Expected 1 tool call, got {len(response.tool_call_debug)}"
    assert response.tool_call_debug[0].tool_name == "lookupFileHash"

    # Verify request reached mock server
    requests_received = get_mock_requests(mock_security_tools_server)
    assert len(requests_received) == 1, f"Expected 1 request, got {len(requests_received)}"
    req = requests_received[0]
    assert req["method"] == "GET", f"Expected GET, got {req['method']}"
    assert "/files/" in req["path"], f"Expected /files/{{hash}}, got {req['path']}"
