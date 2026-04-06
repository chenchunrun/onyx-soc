from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "verify_security_platform_acceptance.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "verify_security_platform_acceptance", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_evaluate_acceptance_returns_ok_for_complete_state() -> None:
    module = _load_module()

    personas = [
        {
            "name": "安全事件分析师",
            "tools": [
                {"display_name": "Internal Search"},
                {"display_name": "Web Search"},
                {"display_name": "Open URL"},
                {"name": "threat_intel_lookup"},
                {"name": "create_security_ticket"},
            ],
        },
        {
            "name": "应急响应指挥官",
            "tools": [
                {"display_name": "Internal Search"},
                {"display_name": "Web Search"},
                {"display_name": "Open URL"},
                {"display_name": "Code Interpreter"},
                {"name": "send_security_alert"},
                {"name": "create_security_ticket"},
            ],
        },
        {
            "name": "漏洞评估专家",
            "tools": [
                {"display_name": "Internal Search"},
                {"display_name": "Web Search"},
                {"display_name": "Open URL"},
                {"display_name": "Code Interpreter"},
                {"name": "threat_intel_lookup"},
                {"name": "create_security_ticket"},
            ],
        },
        {
            "name": "合规审计员",
            "tools": [
                {"display_name": "Internal Search"},
                {"display_name": "Web Search"},
                {"display_name": "Open URL"},
                {"name": "create_security_ticket"},
            ],
        },
    ]

    db_state = {
        "persona_rows": {
            "安全事件分析师": {"id": 2, "is_public": False},
            "应急响应指挥官": {"id": 3, "is_public": False},
            "漏洞评估专家": {"id": 4, "is_public": False},
            "合规审计员": {"id": 5, "is_public": False},
        },
        "document_set_id": 1,
        "user_rows": {
            "analyst@security.local": "u-1",
            "commander@security.local": "u-2",
            "vuln_expert@security.local": "u-3",
            "auditor@security.local": "u-4",
        },
        "persona_user_links": {
            (2, "u-1"),
            (3, "u-2"),
            (4, "u-3"),
            (5, "u-4"),
        },
        "document_set_links": {
            (1, "u-1"),
            (1, "u-2"),
            (1, "u-3"),
            (1, "u-4"),
        },
    }

    result = module.evaluate_acceptance(
        document_sets=[{"id": 1, "name": "安全知识库"}],
        personas=personas,
        openapi_tools=[
            {"name": "create_security_ticket"},
            {"name": "send_security_alert"},
            {"name": "threat_intel_lookup"},
        ],
        db_state=db_state,
    )

    assert result["ok"] is True
    assert result["failures"] == []


def test_evaluate_acceptance_reports_missing_tools_and_links() -> None:
    module = _load_module()

    result = module.evaluate_acceptance(
        document_sets=[],
        personas=[
            {
                "name": "安全事件分析师",
                "tools": [{"display_name": "Internal Search"}],
            }
        ],
        openapi_tools=[{"name": "create_security_ticket"}],
        db_state={
            "persona_rows": {
                "安全事件分析师": {"id": 2, "is_public": True},
            },
            "document_set_id": None,
            "user_rows": {
                "analyst@security.local": "u-1",
            },
            "persona_user_links": set(),
            "document_set_links": set(),
        },
    )

    assert result["ok"] is False
    assert any("Missing document set" in failure for failure in result["failures"])
    assert any("Missing OpenAPI tools" in failure for failure in result["failures"])
    assert any("Missing personas" in failure for failure in result["failures"])
    assert any("missing tools" in failure for failure in result["failures"])
    assert any("Missing security users" in failure for failure in result["failures"])
    assert any("must be private" in failure for failure in result["failures"])
