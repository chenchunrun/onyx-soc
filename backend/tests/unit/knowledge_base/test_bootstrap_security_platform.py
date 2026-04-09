from __future__ import annotations

import importlib.util
from argparse import Namespace
import io
from pathlib import Path
import sys
from contextlib import redirect_stdout


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "knowledge-base" / "bootstrap_security_platform.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "bootstrap_security_platform", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_select_stages_defaults_to_full_order() -> None:
    module = _load_module()

    stages = module.select_stages(
        Namespace(stage=None, verify=False, dry_run=False)
    )

    assert stages == [
        module.STAGE_KNOWLEDGE_BASE,
        module.STAGE_THREAT_INTEL,
        module.STAGE_DOCUMENT_SET,
        module.STAGE_PERSONAS,
        module.STAGE_TOOLS,
        module.STAGE_PLAYBOOKS,
        module.STAGE_RBAC,
    ]


def test_select_stages_includes_acceptance_for_verify_mode() -> None:
    module = _load_module()

    stages = module.select_stages(
        Namespace(stage=None, verify=True, dry_run=False)
    )

    assert stages == [
        module.STAGE_KNOWLEDGE_BASE,
        module.STAGE_THREAT_INTEL,
        module.STAGE_DOCUMENT_SET,
        module.STAGE_PERSONAS,
        module.STAGE_TOOLS,
        module.STAGE_PLAYBOOKS,
        module.STAGE_RBAC,
        module.STAGE_ACCEPTANCE,
    ]


def test_build_personas_command_uses_expected_mode_flags() -> None:
    module = _load_module()
    monkey_args = Namespace(verify=False, dry_run=True)
    command = module.build_personas_command(monkey_args)
    assert command[-1] == "--dry-run"

    monkey_args = Namespace(verify=True, dry_run=False)
    command = module.build_personas_command(monkey_args)
    assert command[-1] == "--verify"

    monkey_args = Namespace(verify=False, dry_run=False)
    command = module.build_personas_command(monkey_args)
    assert command[-1] == "--apply"


def test_build_rbac_command_uses_precheck_for_dry_run() -> None:
    module = _load_module()
    args = Namespace(verify=False, dry_run=True, db_password=None)

    command = module.build_rbac_command(args)

    assert command[-1] == "--precheck"


def test_build_document_set_command_uses_expected_mode_flags() -> None:
    module = _load_module()

    args = Namespace(verify=False, dry_run=True)
    command = module.build_document_set_command(args)
    assert command[-1] == "--dry-run"

    args = Namespace(verify=True, dry_run=False)
    command = module.build_document_set_command(args)
    assert command[-1] == "--verify"


def test_build_threat_intel_command_uses_expected_mode_flags() -> None:
    module = _load_module()

    args = Namespace(verify=False, dry_run=True, threat_intel_limit=None)
    command = module.build_threat_intel_command(args)
    assert command[-1] == "--dry-run"

    args = Namespace(verify=True, dry_run=False, threat_intel_limit=5)
    command = module.build_threat_intel_command(args)
    assert command[-3:] == ["--verify", "--limit", "5"]

    args = Namespace(verify=False, dry_run=False, threat_intel_limit=None)
    command = module.build_threat_intel_command(args)
    assert command[-1] == "--apply"


def test_build_acceptance_command_passes_db_password() -> None:
    module = _load_module()

    command = module.build_acceptance_command(
        Namespace(db_password="secret", verify=True, dry_run=False)
    )

    assert "--json" in command
    assert command[-2:] == ["--db-password", "secret"]
    assert command[1].endswith("verify_security_platform_acceptance.py")


def test_build_playbooks_command_uses_verify_definitions() -> None:
    module = _load_module()

    command = module.build_playbooks_command(
        Namespace(db_password=None, verify=True, dry_run=False)
    )

    assert command[1].endswith("run_security_playbook.py")
    assert command[-1] == "--verify-definitions"


def test_build_smoke_command_targets_post_deploy_smoke_test() -> None:
    module = _load_module()

    command = module.build_smoke_command(
        Namespace(db_password=None, verify=True, dry_run=False)
    )

    assert command[1].endswith("post_deploy_smoke_test.py")


def test_build_env_applies_deployment_profile_env(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "selected_deployment_profile",
        lambda args: {
            "env": {
                "SECURITY_PLATFORM_DEPLOYMENT_PROFILE": "demo",
                "THREAT_INTEL_SOURCE_PROFILE": "mock",
                "SECURITY_TOOLS_PROFILE": "mock",
            },
            "required_env": [],
        },
    )

    env = module.build_env(
        Namespace(
            url="http://example.com",
            email="a@example.com",
            password="secret",
            db_password="pg",
            deployment_profile="demo",
        )
    )

    assert env["ONYX_URL"] == "http://example.com"
    assert env["SECURITY_PLATFORM_DEPLOYMENT_PROFILE"] == "demo"
    assert env["THREAT_INTEL_SOURCE_PROFILE"] == "mock"
    assert env["SECURITY_TOOLS_PROFILE"] == "mock"


def test_selected_deployment_profile_name_defaults_to_live() -> None:
    module = _load_module()

    result = module.selected_deployment_profile_name(Namespace(deployment_profile="live"))

    assert result == "live"


def test_validate_deployment_profile_reports_missing_required_env(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "selected_deployment_profile",
        lambda args: {
            "env": {"SECURITY_PLATFORM_DEPLOYMENT_PROFILE": "demo"},
            "required_env": ["SECURITY_TOOLS_MOCK_SERVER_URL", "SECURITY_TOOLS_MOCK_API_KEY"],
            "expectations": {},
        },
    )

    errors = module.validate_deployment_profile(
        Namespace(dry_run=False, deployment_profile="demo"),
        {
            "SECURITY_PLATFORM_DEPLOYMENT_PROFILE": "demo",
            "SECURITY_TOOLS_MOCK_SERVER_URL": "",
        },
    )

    assert errors == [
        "Deployment profile is missing required env vars: SECURITY_TOOLS_MOCK_SERVER_URL, SECURITY_TOOLS_MOCK_API_KEY"
    ]


def test_validate_deployment_profile_rejects_localhost_mock_server_for_demo(
    monkeypatch,
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "selected_deployment_profile",
        lambda args: {
            "env": {"SECURITY_PLATFORM_DEPLOYMENT_PROFILE": "demo"},
            "required_env": ["SECURITY_TOOLS_MOCK_SERVER_URL"],
            "expectations": {},
        },
    )
    monkeypatch.setattr(
        module,
        "selected_deployment_profile_name",
        lambda args: "demo",
    )

    errors = module.validate_deployment_profile(
        Namespace(dry_run=False, deployment_profile="demo"),
        {
            "SECURITY_PLATFORM_DEPLOYMENT_PROFILE": "demo",
            "SECURITY_TOOLS_MOCK_SERVER_URL": "http://localhost:9999",
        },
    )

    assert errors == [
        "Deployment profile demo requires SECURITY_TOOLS_MOCK_SERVER_URL to be reachable from Docker containers; use host.docker.internal instead of http://localhost:9999"
    ]


def test_validate_deployment_profile_rejects_localhost_gateway_for_gateway(
    monkeypatch,
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "selected_deployment_profile",
        lambda args: {
            "env": {"SECURITY_PLATFORM_DEPLOYMENT_PROFILE": "gateway"},
            "required_env": ["SECURITY_TOOLS_GATEWAY_URL"],
            "expectations": {},
        },
    )
    monkeypatch.setattr(
        module,
        "selected_deployment_profile_name",
        lambda args: "gateway",
    )

    errors = module.validate_deployment_profile(
        Namespace(dry_run=False, deployment_profile="gateway"),
        {
            "SECURITY_PLATFORM_DEPLOYMENT_PROFILE": "gateway",
            "SECURITY_TOOLS_GATEWAY_URL": "http://localhost:9999",
        },
    )

    assert errors == [
        "Deployment profile gateway requires SECURITY_TOOLS_GATEWAY_URL to be reachable from Docker containers; use host.docker.internal instead of http://localhost:9999"
    ]


def test_main_continues_in_verify_mode_with_profile_errors(monkeypatch) -> None:
    module = _load_module()
    captured_stages: list[str] = []

    monkeypatch.setattr(
        module,
        "parse_args",
        lambda: Namespace(
            apply=False,
            verify=True,
            dry_run=False,
            stage=[module.STAGE_ACCEPTANCE],
            url="http://example.com",
            email="a@example.com",
            password="secret",
            db_password=None,
            threat_intel_limit=None,
            deployment_profile="live",
        ),
    )
    monkeypatch.setattr(module, "build_env", lambda args: {})
    monkeypatch.setattr(module, "select_stages", lambda args: [module.STAGE_ACCEPTANCE])
    monkeypatch.setattr(module, "validate_deployment_profile", lambda args, env: ["fake-error"])
    monkeypatch.setattr(module, "print_plan", lambda args, stages: None)
    monkeypatch.setattr(module, "print_summary", lambda results: None)
    monkeypatch.setattr(
        module,
        "run_stage",
        lambda name, command, env: captured_stages.append(name)
        or module.StageResult(name=name, command=command, returncode=0),
    )

    rc = module.main()

    assert rc == 0
    assert captured_stages == [module.STAGE_ACCEPTANCE]


def test_print_summary_includes_acceptance_health_and_actions() -> None:
    module = _load_module()
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        module.print_summary(
            [
                module.StageResult(
                    name=module.STAGE_ACCEPTANCE,
                    command=["python", "verify_security_platform_acceptance.py", "--json"],
                    returncode=1,
                    parsed_json={
                        "health": {
                            "overall_status": "failing",
                            "failing_checks": 1,
                            "warning_checks": 0,
                        },
                        "summary": {
                            "historical_package_count": 2,
                            "historical_package_total_items": 203,
                        },
                        "recommended_next_actions": [
                            "Fill the missing required env vars for the selected deployment profile."
                        ],
                    },
                )
            ]
        )

    output = buffer.getvalue()
    assert "- acceptance: FAILED" in output
    assert "health: failing (failing=1, warning=0)" in output
    assert "historical packages: count=2, items=203" in output
    assert "Fill the missing required env vars for the selected deployment profile." in output
