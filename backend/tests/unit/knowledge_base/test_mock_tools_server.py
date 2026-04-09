from __future__ import annotations

from unittest.mock import Mock
from unittest.mock import patch

from importlib.util import module_from_spec
from importlib.util import spec_from_file_location
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[4]
    / "knowledge-base"
    / "security-automation"
    / "mock_tools_server.py"
)
SPEC = spec_from_file_location("mock_tools_server", MODULE_PATH)
assert SPEC and SPEC.loader
module = module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def test_extract_gateway_token_supports_x_apikey() -> None:
    headers = {"x-apikey": "test-gateway-key"}
    assert module.extract_gateway_token(headers) == "test-gateway-key"


def test_extract_gateway_token_supports_bearer_authorization() -> None:
    headers = {"Authorization": "Bearer test-gateway-key"}
    assert module.extract_gateway_token(headers) == "test-gateway-key"


def test_is_gateway_authorized_allows_when_no_gateway_key_configured() -> None:
    with patch.dict(module.os.environ, {}, clear=True):
        assert module.is_gateway_authorized({}) is True


def test_is_gateway_authorized_rejects_mismatched_gateway_key() -> None:
    with patch.dict(
        module.os.environ, {"SECURITY_TOOLS_GATEWAY_API_KEY": "expected-key"}, clear=True
    ):
        assert module.is_gateway_authorized({"x-apikey": "wrong-key"}) is False


def test_get_threat_intel_mode_reports_virustotal_when_key_present() -> None:
    with patch.dict(module.os.environ, {"VIRUSTOTAL_API_KEY": "vt-key"}, clear=True):
        assert module.get_threat_intel_mode() == "virustotal"


def test_forward_virustotal_lookup_uses_official_endpoint_and_header() -> None:
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"data": {"id": "1.2.3.4"}}

    with patch.dict(
        module.os.environ,
        {
            "VIRUSTOTAL_API_KEY": "vt-key",
            "VIRUSTOTAL_BASE_URL": "https://www.virustotal.com/api/v3",
        },
        clear=True,
    ):
        with patch.object(module.requests, "get", return_value=response) as mock_get:
            status_code, payload = module.forward_virustotal_lookup(
                "ip_addresses", "1.2.3.4"
            )

    assert status_code == 200
    assert payload == {"data": {"id": "1.2.3.4"}}
    mock_get.assert_called_once_with(
        "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
        headers={"x-apikey": "vt-key"},
        timeout=20,
    )
