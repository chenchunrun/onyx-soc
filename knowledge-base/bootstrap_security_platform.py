#!/usr/bin/env python3
"""
Bootstrap script for the Onyx security platform customization layer.

This orchestrates the existing setup scripts so a new environment can be
initialized with a single command while still allowing stage-by-stage runs.

Examples:
    python bootstrap_security_platform.py --dry-run
    python bootstrap_security_platform.py --apply
    python bootstrap_security_platform.py --verify
    python bootstrap_security_platform.py --apply --stage tools --stage rbac
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent
SECURITY_AUTOMATION_DIR = ROOT / "security-automation"
SSO_RBAC_DIR = ROOT / "sso-rbac"
VENV_PYTHON = ROOT.parent / ".venv" / "bin" / "python"
DEPLOYMENT_PROFILES_PATH = ROOT.parent / "docs" / "security-platform" / "deployment-profiles.yaml"

STAGE_KNOWLEDGE_BASE = "knowledge-base"
STAGE_THREAT_INTEL = "threat-intel"
STAGE_DOCUMENT_SET = "document-set"
STAGE_PERSONAS = "personas"
STAGE_TOOLS = "tools"
STAGE_RBAC = "rbac"
STAGE_ACCEPTANCE = "acceptance"
STAGE_SMOKE = "smoke"
ALL_STAGES = [
    STAGE_KNOWLEDGE_BASE,
    STAGE_THREAT_INTEL,
    STAGE_DOCUMENT_SET,
    STAGE_PERSONAS,
    STAGE_TOOLS,
    STAGE_RBAC,
    STAGE_ACCEPTANCE,
    STAGE_SMOKE,
]
DEFAULT_STAGES_APPLY = [
    STAGE_KNOWLEDGE_BASE,
    STAGE_THREAT_INTEL,
    STAGE_DOCUMENT_SET,
    STAGE_PERSONAS,
    STAGE_TOOLS,
    STAGE_RBAC,
]
DEFAULT_STAGES_VERIFY = DEFAULT_STAGES_APPLY + [STAGE_ACCEPTANCE]


@dataclass
class StageResult:
    name: str
    command: list[str]
    returncode: int

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def build_env(args: argparse.Namespace) -> dict[str, str]:
    env = os.environ.copy()
    if args.url:
        env["ONYX_URL"] = args.url
    if args.email:
        env["ONYX_EMAIL"] = args.email
    if args.password:
        env["ONYX_PASSWORD"] = args.password
    if args.db_password:
        env["POSTGRES_PASSWORD"] = args.db_password
    for key, value in selected_deployment_profile(args).get("env", {}).items():
        env[str(key)] = str(value)
    return env


def load_deployment_profiles() -> dict[str, Any]:
    with open(DEPLOYMENT_PROFILES_PATH, "r", encoding="utf-8") as handle:
        profiles = yaml.safe_load(handle)
    if not isinstance(profiles, dict):
        raise ValueError(f"Invalid deployment profiles: {DEPLOYMENT_PROFILES_PATH}")
    defined_profiles = profiles.get("profiles")
    if not isinstance(defined_profiles, dict) or not defined_profiles:
        raise ValueError(
            f"Deployment profiles {DEPLOYMENT_PROFILES_PATH} must define profiles"
        )
    return profiles


def selected_deployment_profile_name(args: argparse.Namespace) -> str:
    return str(
        getattr(args, "deployment_profile", None)
        or os.environ.get("SECURITY_PLATFORM_DEPLOYMENT_PROFILE", "live")
    )


def selected_deployment_profile(args: argparse.Namespace) -> dict[str, Any]:
    profiles = load_deployment_profiles()["profiles"]
    profile_name = selected_deployment_profile_name(args)
    if profile_name not in profiles:
        supported = ", ".join(sorted(profiles))
        raise ValueError(
            f"Unsupported deployment profile: {profile_name}. Supported: {supported}"
        )
    profile = profiles[profile_name]
    if not isinstance(profile, dict):
        raise ValueError(f"Invalid deployment profile config for {profile_name}")
    env_mapping = profile.get("env", {})
    if env_mapping is None:
        profile["env"] = {}
    elif not isinstance(env_mapping, dict):
        raise ValueError(f"Deployment profile {profile_name} must define env as a mapping")
    return profile


def run_stage(name: str, command: list[str], env: dict[str, str]) -> StageResult:
    print(f"\n=== Stage: {name} ===")
    print("Command:", " ".join(command))
    completed = subprocess.run(command, cwd=ROOT, env=env, check=False)
    return StageResult(name=name, command=command, returncode=completed.returncode)


def get_python_executable() -> str:
    if VENV_PYTHON.exists():
        return str(VENV_PYTHON)
    return sys.executable


def build_knowledge_base_command(args: argparse.Namespace) -> list[str]:
    command = [get_python_executable(), str(ROOT / "upload_to_onyx.py")]
    if args.verify:
        command.append("--verify")
    elif args.dry_run:
        command.append("--dry-run")
    return command


def build_tools_command(args: argparse.Namespace) -> list[str]:
    command = [get_python_executable(), str(SECURITY_AUTOMATION_DIR / "setup_security_tools.py")]
    if args.verify:
        command.append("--list-tools")
    elif args.dry_run:
        command.append("--dry-run")
    else:
        command.append("--apply")
    return command


def build_threat_intel_command(args: argparse.Namespace) -> list[str]:
    command = [get_python_executable(), str(ROOT / "setup_security_threat_intel.py")]
    if args.verify:
        command.append("--verify")
    elif args.dry_run:
        command.append("--dry-run")
    else:
        command.append("--apply")
    if getattr(args, "threat_intel_limit", None):
        command.extend(["--limit", str(args.threat_intel_limit)])
    return command


def build_personas_command(args: argparse.Namespace) -> list[str]:
    command = [get_python_executable(), str(ROOT / "setup_security_personas.py")]
    if args.verify:
        command.append("--verify")
    elif args.dry_run:
        command.append("--dry-run")
    else:
        command.append("--apply")
    return command


def build_document_set_command(args: argparse.Namespace) -> list[str]:
    command = [get_python_executable(), str(ROOT / "setup_security_document_set.py")]
    if args.verify:
        command.append("--verify")
    elif args.dry_run:
        command.append("--dry-run")
    else:
        command.append("--apply")
    return command


def build_rbac_command(args: argparse.Namespace) -> list[str]:
    command = [get_python_executable(), str(SSO_RBAC_DIR / "provision_security_team.py")]
    if args.verify:
        command.append("--verify")
    elif args.dry_run:
        command.append("--precheck")
    else:
        command.append("--apply")
    if args.db_password:
        command.extend(["--db-password", args.db_password])
    return command


def build_acceptance_command(args: argparse.Namespace) -> list[str]:
    command = [get_python_executable(), str(ROOT / "verify_security_platform_acceptance.py")]
    if args.db_password:
        command.extend(["--db-password", args.db_password])
    return command


def build_smoke_command(args: argparse.Namespace) -> list[str]:
    return [get_python_executable(), str(ROOT / "post_deploy_smoke_test.py")]


def select_stages(args: argparse.Namespace) -> list[str]:
    if args.stage:
        return args.stage
    if args.verify:
        return DEFAULT_STAGES_VERIFY
    return DEFAULT_STAGES_APPLY


def print_plan(args: argparse.Namespace, stages: list[str]) -> None:
    if args.verify:
        mode = "verify"
    elif args.dry_run:
        mode = "dry-run"
    else:
        mode = "apply"
    print(f"Bootstrap mode: {mode}")
    print(f"Stages: {', '.join(stages)}")
    print(f"Deployment profile: {selected_deployment_profile_name(args)}")
    if args.url:
        print(f"Onyx URL: {args.url}")
    if args.email:
        print(f"Onyx user: {args.email}")
    if args.db_password:
        print("Postgres password: provided via CLI")


def print_summary(results: list[StageResult]) -> None:
    print("\n=== Summary ===")
    for result in results:
        status = "OK" if result.ok else "FAILED"
        print(f"- {result.name}: {status}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Unified bootstrap for the Onyx security platform customization"
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what each stage would do without applying changes",
    )
    mode_group.add_argument(
        "--apply",
        action="store_true",
        help="Apply all selected stages",
    )
    mode_group.add_argument(
        "--verify",
        action="store_true",
        help="Verify the current state of all selected stages",
    )
    parser.add_argument(
        "--stage",
        action="append",
        choices=ALL_STAGES,
        help="Run only the specified stage. Can be provided multiple times.",
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("ONYX_URL", "http://localhost:8080"),
        help="Onyx base URL for API-based stages",
    )
    parser.add_argument(
        "--email",
        default=os.environ.get("ONYX_EMAIL", "security-admin@onyx.local"),
        help="Onyx admin email for API-based stages",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("ONYX_PASSWORD", "admin123"),
        help="Onyx admin password for API-based stages",
    )
    parser.add_argument(
        "--db-password",
        default=os.environ.get("POSTGRES_PASSWORD"),
        help="PostgreSQL password for the RBAC provisioning stage",
    )
    parser.add_argument(
        "--threat-intel-limit",
        type=int,
        default=None,
        help="Limit the number of threat-intel feed files processed by the threat-intel stage",
    )
    parser.add_argument(
        "--deployment-profile",
        choices=["live", "demo"],
        default=os.environ.get("SECURITY_PLATFORM_DEPLOYMENT_PROFILE", "live"),
        help="High-level deployment profile. 'demo' switches both threat-intel and tool integrations to local/mock-friendly modes.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    env = build_env(args)
    stages = select_stages(args)
    print_plan(args, stages)

    results: list[StageResult] = []

    for stage in stages:
        if stage == STAGE_KNOWLEDGE_BASE:
            result = run_stage(stage, build_knowledge_base_command(args), env)
        elif stage == STAGE_THREAT_INTEL:
            result = run_stage(stage, build_threat_intel_command(args), env)
        elif stage == STAGE_DOCUMENT_SET:
            result = run_stage(stage, build_document_set_command(args), env)
        elif stage == STAGE_PERSONAS:
            result = run_stage(stage, build_personas_command(args), env)
        elif stage == STAGE_TOOLS:
            result = run_stage(stage, build_tools_command(args), env)
        elif stage == STAGE_RBAC:
            result = run_stage(stage, build_rbac_command(args), env)
        elif stage == STAGE_ACCEPTANCE:
            if args.dry_run:
                print("[ERROR] The acceptance stage is only available with --apply or --verify.")
                return 1
            result = run_stage(stage, build_acceptance_command(args), env)
        elif stage == STAGE_SMOKE:
            if args.dry_run:
                print("[ERROR] The smoke stage is only available with --apply or --verify.")
                return 1
            result = run_stage(stage, build_smoke_command(args), env)
        else:
            print(f"[ERROR] Unknown stage: {stage}")
            return 1

        results.append(result)
        if not result.ok:
            print(f"[ERROR] Stage failed: {stage}")
            print_summary(results)
            return 1

    print_summary(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
