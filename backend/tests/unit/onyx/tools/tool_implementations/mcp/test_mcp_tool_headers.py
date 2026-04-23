import pytest

from onyx.tools.tool_implementations.mcp.mcp_tool import filter_request_mcp_headers


def test_filter_request_mcp_headers_default_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_REQUEST_HEADER_ALLOWLIST", raising=False)

    filtered_headers, blocked_headers = filter_request_mcp_headers(
        {
            "Authorization": "Bearer token",
            "X-Api-Key": "key-value",
            "Cookie": "session=abc",
            "X-Internal-Trace": "trace-id",
            "Host": "internal.service",
        }
    )

    assert filtered_headers == {
        "Authorization": "Bearer token",
        "X-Api-Key": "key-value",
    }
    assert blocked_headers == ["Cookie", "X-Internal-Trace", "Host"]


def test_filter_request_mcp_headers_env_allowlist_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "MCP_REQUEST_HEADER_ALLOWLIST",
        "x-custom-auth, x-onyx-safe-header",
    )

    filtered_headers, blocked_headers = filter_request_mcp_headers(
        {
            "X-Custom-Auth": "custom-token",
            "X-Onyx-Safe-Header": "safe",
            "X-Forwarded-For": "1.1.1.1",
        }
    )

    assert filtered_headers == {
        "X-Custom-Auth": "custom-token",
        "X-Onyx-Safe-Header": "safe",
    }
    assert blocked_headers == ["X-Forwarded-For"]
