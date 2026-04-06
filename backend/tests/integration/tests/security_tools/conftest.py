"""
pytest fixtures for security tools integration tests.

Sets up:
- Mock security tools server (runs on localhost:9999)
- Admin user authenticated against Onyx API
- LLM provider for chat sessions

Run with:
    python -m dotenv -f .vscode/.env run --
    pytest backend/tests/integration/tests/security_tools/ -v

Requires:
    - INTEGRATION_TESTS_MODE=true (set via .env)
    - Tools 11/12 pointing to host.docker.internal:9999 (inside Docker)
    - Tool 13 pointing to https://www.virustotal.com/api/v3 (real API)
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path

import pytest
import requests

from tests.integration.common_utils.managers.llm_provider import LLMProviderManager
from tests.integration.common_utils.managers.user import UserManager
from tests.integration.common_utils.test_models import DATestUser

# Mock server config
MOCK_SERVER_HOST = os.getenv("TEST_WEB_HOSTNAME", "127.0.0.1")
MOCK_SERVER_PORT = int(os.getenv("MOCK_SECURITY_TOOLS_PORT", "9999"))
MOCK_SERVER_URL = f"http://{MOCK_SERVER_HOST}:{MOCK_SERVER_PORT}"

MOCK_SERVER_SCRIPT = (
    Path(__file__).resolve().parents[5]
    / "knowledge-base"
    / "security-automation"
    / "mock_tools_server.py"
)

# Security tool IDs (assigned in DB migration / setup)
SECURITY_ALERT_TOOL_ID = 11
CREATE_TICKET_TOOL_ID = 12
THREAT_INTEL_TOOL_ID = 13


def _wait_for_port(host: str, port: int, process: subprocess.Popen[bytes], timeout_seconds: float = 10.0) -> None:
    """Wait for a TCP port to become available."""
    start = time.monotonic()
    while time.monotonic() - start < timeout_seconds:
        if process.poll() is not None:
            raise RuntimeError("Mock server process exited unexpectedly during startup")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return
            except OSError:
                time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for port {port} to accept connections")


def _kill_port(host: str, port: int) -> None:
    """Kill any process listening on the given host:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((host, port))
        except OSError:
            return  # Port is free
    # Port is in use — find and kill the process
    try:
        result = subprocess.run(
            ["lsof", "-i", f":{port}", "-t"],
            capture_output=True, text=True, timeout=5
        )
        for pid in result.stdout.strip().split("\n"):
            if pid:
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except (OSError, ValueError):
                    pass
        time.sleep(0.5)  # Give the process time to exit
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass  # lsof not available on all systems



def _wait_for_health(url: str, timeout: float = 5.0) -> None:
    """Wait for the mock server health endpoint to return OK."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            resp = requests.get(f"{url}/health", timeout=1)
            if resp.status_code == 200:
                return
        except (requests.RequestException, OSError):
            pass
        time.sleep(0.2)
    raise TimeoutError(f"Timed out waiting for mock server health at {url}")


# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def mock_security_tools_server() -> Generator[str, None, None]:
    """
    Start the mock security tools server for the test module duration.

    The server listens on TEST_WEB_HOSTNAME:MOCK_SECURITY_TOOLS_PORT
    (default 127.0.0.1:9999).

    Returns the base URL of the mock server.
    """
    if not MOCK_SERVER_SCRIPT.exists():
        pytest.skip(f"Mock server script not found: {MOCK_SERVER_SCRIPT}")

    _kill_port(MOCK_SERVER_HOST, MOCK_SERVER_PORT)
    process = subprocess.Popen(
        [sys.executable, str(MOCK_SERVER_SCRIPT), "--port", str(MOCK_SERVER_PORT)],
        cwd=MOCK_SERVER_SCRIPT.parent,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        _wait_for_port(MOCK_SERVER_HOST, MOCK_SERVER_PORT, process)
        _wait_for_health(MOCK_SERVER_URL)
        yield MOCK_SERVER_URL
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


@pytest.fixture(scope="module")
def admin_user() -> DATestUser:
    """Create and authenticate an admin user for API calls."""
    user = UserManager.create(name="security_tools_admin")
    return user


@pytest.fixture(scope="module")
def llm_provider(admin_user: DATestUser) -> None:
    """Ensure an LLM provider exists for chat sessions.

    Aligned with root conftest: raises on failure rather than silently swallowing.
    The test will fail with a clear error if OPENAI_API_KEY is missing.
    """
    LLMProviderManager.create(
        user_performing_action=admin_user,
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def get_mock_requests(base_url: str) -> list[dict]:
    """Retrieve all requests received by the mock server."""
    resp = requests.get(f"{base_url}/__requests__", timeout=5)
    resp.raise_for_status()
    return resp.json()


def clear_mock_requests(base_url: str) -> None:
    """Clear all requests received by the mock server."""
    resp = requests.delete(f"{base_url}/__requests__", timeout=5)
    resp.raise_for_status()


# Expose the port constant for direct import by test modules
SEC_MOCK_SERVER_PORT = MOCK_SERVER_PORT
