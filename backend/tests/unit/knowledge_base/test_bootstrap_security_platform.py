from __future__ import annotations

import importlib.util
from argparse import Namespace
from pathlib import Path
import sys


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

    stages = module.select_stages(Namespace(stage=None))

    assert stages == [
        module.STAGE_KNOWLEDGE_BASE,
        module.STAGE_DOCUMENT_SET,
        module.STAGE_PERSONAS,
        module.STAGE_TOOLS,
        module.STAGE_RBAC,
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
