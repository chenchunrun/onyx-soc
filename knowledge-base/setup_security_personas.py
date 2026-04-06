#!/usr/bin/env python3
"""
Create or update the standard security personas used by the Onyx security platform.

Examples:
    python setup_security_personas.py --dry-run
    python setup_security_personas.py --apply
    python setup_security_personas.py --verify
"""

from __future__ import annotations

import argparse
import os
from typing import Any

import requests


SECURITY_PERSONAS = [
    {
        "name": "安全事件分析师",
        "description": "面向 SOC 分析场景，负责安全告警研判、IoC 核查、攻击链梳理和处置建议输出。",
        "system_prompt": (
            "你是企业安全事件分析师。你的目标是快速判断安全事件真实性、影响范围和优先级。"
            "优先基于知识库、检索结果和工具返回内容给出结论，明确区分事实、推断和待验证项。"
            "输出应包含事件判断、关键证据、影响范围、下一步建议。"
        ),
        "task_prompt": (
            "聚焦事件分析、IoC 研判、威胁归因和处置建议。"
            "如信息不足，先说明缺失信息，再给出最小化的下一步调查动作。"
        ),
        "document_set_name": "安全知识库",
        "tool_names": ["Internal Search", "Web Search", "Open URL"],
        "is_public": False,
        "display_priority": 20,
    },
    {
        "name": "应急响应指挥官",
        "description": "面向应急响应指挥场景，负责决策协调、分阶段处置、沟通升级和恢复建议。",
        "system_prompt": (
            "你是企业应急响应指挥官。你的目标是基于现有事实快速形成处置决策，"
            "组织分阶段响应动作，并控制业务影响。回答需要突出优先级、分工、升级路径和恢复策略。"
        ),
        "task_prompt": (
            "聚焦应急分级、处置节奏、跨团队协同和升级汇报。"
            "默认给出短期止损、中期修复和后续复盘建议。"
        ),
        "document_set_name": "安全知识库",
        "tool_names": ["Internal Search", "Web Search", "Open URL", "Code Interpreter"],
        "is_public": False,
        "display_priority": 10,
    },
    {
        "name": "漏洞评估专家",
        "description": "面向漏洞管理场景，负责漏洞影响评估、利用条件分析、修复优先级和缓解建议。",
        "system_prompt": (
            "你是企业漏洞评估专家。你的目标是评估漏洞可利用性、影响面、修复优先级和临时缓解措施。"
            "输出应包含漏洞概述、影响判断、利用条件、优先级和修复建议。"
        ),
        "task_prompt": (
            "聚焦 CVE 研判、资产影响评估、补丁优先级和缓解方案。"
            "如存在不确定性，明确说明判断依据和未确认项。"
        ),
        "document_set_name": "安全知识库",
        "tool_names": ["Internal Search", "Web Search", "Open URL", "Code Interpreter"],
        "is_public": False,
        "display_priority": 30,
    },
    {
        "name": "合规审计员",
        "description": "面向审计与合规场景，负责控制项核查、基线比对、证据清单整理和整改建议。",
        "system_prompt": (
            "你是企业合规审计员。你的目标是依据制度、基线和审计要求，"
            "输出结构化的合规判断、证据要求、差距说明和整改建议。"
        ),
        "task_prompt": (
            "聚焦合规核查、控制项映射、证据缺口和整改建议。"
            "优先输出审计可追踪的条目化结论。"
        ),
        "document_set_name": "安全知识库",
        "tool_names": ["Internal Search", "Web Search", "Open URL"],
        "is_public": False,
        "display_priority": 40,
    },
]


def get_cookie(base_url: str, email: str, password: str) -> str | None:
    try:
        response = requests.post(
            f"{base_url}/auth/login",
            data={"username": email, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        if response.status_code == 204:
            cookie = response.headers.get("set-cookie", "")
            for part in cookie.split(","):
                part = part.strip()
                if "fastapiusersauth=" in part:
                    return part.split(";")[0].split("=")[1]
    except Exception as exc:
        print(f"  [WARN] Login failed: {exc}")
    return None


def list_personas(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/admin/persona",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def list_document_sets(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/manage/document-set?get_editable=true",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def list_tools(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/tool",
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def build_persona_payload(
    persona_config: dict[str, Any],
    document_set_id: int,
    tool_ids: list[int],
) -> dict[str, Any]:
    return {
        "name": persona_config["name"],
        "description": persona_config["description"],
        "document_set_ids": [document_set_id],
        "is_public": persona_config["is_public"],
        "llm_model_provider_override": None,
        "llm_model_version_override": None,
        "starter_messages": None,
        "users": [],
        "groups": [],
        "tool_ids": tool_ids,
        "remove_image": None,
        "uploaded_image_id": None,
        "icon_name": None,
        "search_start_date": None,
        "label_ids": [],
        "is_featured": False,
        "display_priority": persona_config["display_priority"],
        "user_file_ids": [],
        "hierarchy_node_ids": [],
        "document_ids": [],
        "system_prompt": persona_config["system_prompt"],
        "replace_base_system_prompt": False,
        "task_prompt": persona_config["task_prompt"],
        "datetime_aware": True,
    }


def create_persona(base_url: str, cookie: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(
        f"{base_url}/persona",
        json=payload,
        cookies={"fastapiusersauth": cookie},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def update_persona(
    base_url: str, cookie: str, persona_id: int, payload: dict[str, Any]
) -> dict[str, Any]:
    response = requests.patch(
        f"{base_url}/persona/{persona_id}",
        json=payload,
        cookies={"fastapiusersauth": cookie},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def verify_personas(base_url: str, cookie: str) -> int:
    personas = list_personas(base_url, cookie)
    persona_names = {persona["name"] for persona in personas}
    missing = [config["name"] for config in SECURITY_PERSONAS if config["name"] not in persona_names]

    print(f"Configured personas found: {len(SECURITY_PERSONAS) - len(missing)}/{len(SECURITY_PERSONAS)}")
    for config in SECURITY_PERSONAS:
        status = "OK" if config["name"] in persona_names else "MISSING"
        print(f"  - {config['name']}: {status}")

    return 1 if missing else 0


def apply_personas(base_url: str, cookie: str, dry_run: bool) -> int:
    existing_personas = {
        persona["name"]: persona for persona in list_personas(base_url, cookie)
    }
    document_sets = {
        document_set["name"]: document_set for document_set in list_document_sets(base_url, cookie)
    }
    tools = {tool["display_name"]: tool for tool in list_tools(base_url, cookie)}

    errors = 0

    for config in SECURITY_PERSONAS:
        document_set = document_sets.get(config["document_set_name"])
        if not document_set:
            print(f"  [ERROR] Missing document set: {config['document_set_name']} for {config['name']}")
            errors += 1
            continue

        resolved_tools: list[int] = []
        missing_tools: list[str] = []
        for tool_name in config["tool_names"]:
            tool = tools.get(tool_name)
            if tool:
                resolved_tools.append(tool["id"])
            else:
                missing_tools.append(tool_name)

        payload = build_persona_payload(
            persona_config=config,
            document_set_id=document_set["id"],
            tool_ids=resolved_tools,
        )

        if dry_run:
            action = "update" if config["name"] in existing_personas else "create"
            print(f"  [DRY RUN] Would {action} persona: {config['name']}")
            print(f"    document_set_id={document_set['id']} tool_ids={resolved_tools}")
            if missing_tools:
                print(f"    missing_tools={missing_tools}")
            continue

        try:
            if config["name"] in existing_personas:
                persona_id = existing_personas[config["name"]]["id"]
                update_persona(base_url, cookie, persona_id, payload)
                print(f"  [OK] Updated persona: {config['name']} (id={persona_id})")
            else:
                result = create_persona(base_url, cookie, payload)
                print(f"  [OK] Created persona: {config['name']} (id={result['id']})")

            if missing_tools:
                print(f"  [WARN] Persona created without missing tools: {missing_tools}")
        except Exception as exc:
            print(f"  [ERROR] Failed to apply persona {config['name']}: {exc}")
            errors += 1

    return 1 if errors else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or update standard security personas"
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--dry-run", action="store_true")
    mode_group.add_argument("--apply", action="store_true")
    mode_group.add_argument("--verify", action="store_true")
    parser.add_argument("--url", default=os.environ.get("ONYX_URL", "http://localhost:8080"))
    parser.add_argument(
        "--email",
        default=os.environ.get("ONYX_EMAIL", "security-admin@onyx.local"),
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("ONYX_PASSWORD", "admin123"),
    )
    args = parser.parse_args()

    print(f"Logging in as {args.email}...")
    cookie = get_cookie(args.url, args.email, args.password)
    if not cookie:
        print("[ERROR] Login failed. Check credentials.")
        return 1
    print("[OK] Logged in.\n")

    if args.verify:
        return verify_personas(args.url, cookie)

    return apply_personas(args.url, cookie, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
