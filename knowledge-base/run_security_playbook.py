#!/usr/bin/env python3
"""Execute security persona playbooks against an Onyx deployment."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
import os
from pathlib import Path
from queue import Empty
from queue import Queue
import re
import sys
import threading
import uuid
from typing import Any
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.parse import urlunparse

import requests
import yaml

ROOT = Path(__file__).resolve().parent
PLAYBOOKS_DIR = ROOT.parent / "docs" / "security-platform" / "playbooks"
SECURITY_TOOL_INTEGRATIONS_DIR = (
    ROOT.parent
    / "backend"
    / "onyx"
    / "server"
    / "manage"
    / "security_platform"
    / "tool_configs"
)
SECURITY_PERSONA_NAMES = {
    "安全事件分析师",
    "应急响应指挥官",
    "漏洞评估专家",
    "合规审计员",
    "威胁狩猎工程师",
    "恶意软件分析师",
    "检测工程师",
}
SUPPORTED_EXECUTION_MODES = {"chat", "direct", "template"}


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


def session_headers(cookie: str) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Cookie": f"fastapiusersauth={cookie}; ",
    }


def list_personas(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/persona",
        headers=session_headers(cookie),
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def get_persona(base_url: str, cookie: str, persona_id: int) -> dict[str, Any]:
    response = requests.get(
        f"{base_url}/persona/{persona_id}",
        headers=session_headers(cookie),
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def list_openapi_tools(base_url: str, cookie: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{base_url}/tool/openapi",
        headers=session_headers(cookie),
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def create_chat_session(base_url: str, cookie: str, persona_id: int, description: str) -> str:
    response = requests.post(
        f"{base_url}/chat/create-chat-session",
        json={"persona_id": persona_id, "description": description},
        headers=session_headers(cookie),
        cookies={"fastapiusersauth": cookie},
        timeout=20,
    )
    response.raise_for_status()
    return str(response.json()["chat_session_id"])


def parse_stream_response(response: requests.Response) -> dict[str, Any]:
    full_message = ""
    tool_call_debug: list[dict[str, Any]] = []
    custom_tool_events: list[dict[str, Any]] = []
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
        elif packet_type in {"custom_tool_start", "custom_tool_args", "custom_tool_delta"}:
            custom_tool_events.append(
                {
                    "type": packet_type,
                    "tool_name": obj.get("tool_name"),
                    "tool_args": obj.get("tool_args") or {},
                    "response_type": obj.get("response_type"),
                    "data": obj.get("data"),
                    "error": obj.get("error"),
                }
            )

    return {
        "full_message": full_message,
        "tool_call_debug": tool_call_debug,
        "custom_tool_events": custom_tool_events,
        "error": error,
    }


def send_chat_message(
    base_url: str,
    cookie: str,
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
        f"{base_url}/chat/send-chat-message",
        json=payload,
        headers=session_headers(cookie),
        cookies={"fastapiusersauth": cookie},
        stream=True,
        timeout=120,
    )
    response.raise_for_status()
    return parse_stream_response(response)


def send_chat_message_with_timeout(
    base_url: str,
    cookie: str,
    chat_session_id: str,
    message: str,
    *,
    forced_tool_id: int | None = None,
    step_timeout_seconds: int = 90,
    mock_llm_response: str | None = None,
) -> dict[str, Any]:
    result_queue: Queue[tuple[str, Any]] = Queue(maxsize=1)

    def _worker() -> None:
        try:
            result = send_chat_message(
                base_url,
                cookie,
                chat_session_id,
                message,
                forced_tool_id=forced_tool_id,
                mock_llm_response=mock_llm_response,
            )
            result_queue.put(("ok", result))
        except Exception as exc:
            result_queue.put(("error", exc))

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

    try:
        status, payload = result_queue.get(timeout=step_timeout_seconds)
    except Empty:
        return {
            "full_message": "",
            "tool_call_debug": [],
            "error": f"step_timeout_after_{step_timeout_seconds}s",
        }

    if status == "error":
        raise payload
    return payload


def load_playbook_definition(playbook_name: str) -> dict[str, Any]:
    playbook_path = PLAYBOOKS_DIR / f"{playbook_name}.yaml"
    if not playbook_path.exists():
        raise FileNotFoundError(f"Playbook not found: {playbook_name}")
    data = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid playbook definition: {playbook_path}")
    return data


def list_playbooks() -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for path in sorted(PLAYBOOKS_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue
        items.append(
            {
                "name": str(data.get("name", path.stem)),
                "display_name": str(data.get("display_name", path.stem)),
                "path": str(path),
            }
        )
    return items


def parse_inputs(raw_inputs: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in raw_inputs:
        if "=" not in raw:
            raise ValueError(f"Invalid --input value: {raw}. Expected key=value")
        key, value = raw.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"Invalid --input key in: {raw}")
        parsed[key] = value.strip()
    return parsed


def load_declared_tool_bindings() -> dict[str, set[str]]:
    tool_bindings: dict[str, set[str]] = {}
    for path in sorted(SECURITY_TOOL_INTEGRATIONS_DIR.glob("*.yaml")):
        if path.name == "profiles.yaml":
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue
        tool_name = str(data.get("name", "")).strip()
        if not tool_name:
            continue
        persona_bindings = {
            str(persona_name).strip()
            for persona_name in data.get("persona_bindings", [])
            if str(persona_name).strip()
        }
        tool_bindings[tool_name] = persona_bindings
    return tool_bindings


def extract_template_references(value: Any) -> list[str]:
    references: list[str] = []
    if isinstance(value, str):
        references.extend(
            match.group(1).strip()
            for match in PLACEHOLDER_PATTERN.finditer(value)
            if match.group(1).strip()
        )
        return references
    if isinstance(value, list):
        for item in value:
            references.extend(extract_template_references(item))
        return references
    if isinstance(value, dict):
        for item in value.values():
            references.extend(extract_template_references(item))
    return references


def validate_template_reference(
    reference: str,
    *,
    input_names: set[str],
    available_step_ids: set[str],
) -> str | None:
    if reference.startswith("inputs."):
        input_name = reference.split(".", 2)[1].strip()
        if input_name not in input_names:
            return f"Unknown input reference: {reference}"
        return None
    if reference.startswith("steps."):
        parts = reference.split(".", 2)
        if len(parts) < 3 or not parts[1].strip():
            return f"Invalid step reference: {reference}"
        if parts[1].strip() not in available_step_ids:
            return f"Unknown or future step reference: {reference}"
        return None
    return f"Unsupported template reference root: {reference}"


def validate_playbook(playbook: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    declared_tool_bindings = load_declared_tool_bindings()
    input_names = {
        str(item.get("name", "")).strip()
        for item in playbook.get("inputs", [])
        if isinstance(item, dict) and str(item.get("name", "")).strip()
    }
    if not str(playbook.get("name", "")).strip():
        errors.append("Missing playbook name")
    steps = playbook.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("Playbook must define non-empty steps")
        return errors

    step_ids: set[str] = set()
    for step in steps:
        if not isinstance(step, dict):
            errors.append("Each step must be a mapping")
            continue
        step_id = str(step.get("id", "")).strip()
        persona = str(step.get("persona", "")).strip()
        prompt = str(step.get("prompt", "")).strip()
        mock_llm_response = step.get("mock_llm_response")
        execution_mode = str(step.get("execution_mode", "")).strip() or "chat"
        response_template = step.get("response_template")
        tool_name = str(step.get("tool", "")).strip()
        tool_args = step.get("tool_args")
        if not step_id:
            errors.append("Step missing id")
        elif step_id in step_ids:
            errors.append(f"Duplicate step id: {step_id}")
        if execution_mode not in SUPPORTED_EXECUTION_MODES:
            errors.append(
                f"Step {step_id or '<unknown>'} has unsupported execution_mode={execution_mode}"
            )
        if persona and persona not in SECURITY_PERSONA_NAMES:
            errors.append(
                f"Step {step_id or '<unknown>'} references unsupported persona {persona}"
            )
        if execution_mode != "template" and not persona:
            errors.append(f"Step {step_id or '<unknown>'} missing persona")
        if execution_mode != "template" and not prompt:
            errors.append(f"Step {step_id or '<unknown>'} missing prompt")
        if execution_mode == "template" and not str(response_template or "").strip():
            errors.append(
                f"Step {step_id or '<unknown>'} with execution_mode=template missing response_template"
            )
        if mock_llm_response is not None:
            try:
                json.loads(str(mock_llm_response))
            except Exception:
                errors.append(
                    f"Step {step_id or '<unknown>'} has invalid mock_llm_response JSON"
                )
        if tool_name:
            if tool_name not in declared_tool_bindings:
                errors.append(
                    f"Step {step_id or '<unknown>'} references unknown tool {tool_name}"
                )
            elif persona and persona not in declared_tool_bindings[tool_name]:
                errors.append(
                    f"Step {step_id or '<unknown>'} uses tool {tool_name} not bound to persona {persona}"
                )
        if execution_mode == "direct":
            if not tool_name:
                errors.append(
                    f"Step {step_id or '<unknown>'} with execution_mode=direct missing tool"
                )
            if not isinstance(tool_args, dict) or not tool_args:
                errors.append(
                    f"Step {step_id or '<unknown>'} with execution_mode=direct missing tool_args"
                )

        references_to_validate: list[str] = []
        references_to_validate.extend(extract_template_references(prompt))
        references_to_validate.extend(extract_template_references(response_template))
        references_to_validate.extend(extract_template_references(tool_args))
        references_to_validate.extend(extract_template_references(mock_llm_response))
        for reference in references_to_validate:
            error = validate_template_reference(
                reference,
                input_names=input_names,
                available_step_ids=step_ids,
            )
            if error:
                errors.append(f"Step {step_id or '<unknown>'}: {error}")

        if step_id and step_id not in step_ids:
            step_ids.add(step_id)
    return errors


def get_path_value(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, Mapping):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if 0 <= index < len(current) else None
        else:
            return None
        if current is None:
            return None
    return current


PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")


def render_template(template: str, context: dict[str, Any]) -> str:
    def _replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        value = get_path_value(context, key)
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    return PLACEHOLDER_PATTERN.sub(_replace, template)


def render_structure(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return render_template(value, context)
    if isinstance(value, list):
        return [render_structure(item, context) for item in value]
    if isinstance(value, dict):
        return {
            str(key): render_structure(item, context)
            for key, item in value.items()
        }
    return value


def resolve_host_accessible_url(url: str) -> str:
    explicit_runner_url = os.environ.get(
        "SECURITY_TOOLS_DIRECT_RUNNER_BASE_URL", ""
    ).strip()
    if explicit_runner_url:
        return explicit_runner_url.rstrip("/")

    parsed = urlparse(url)
    if parsed.hostname != "host.docker.internal":
        return url.rstrip("/")

    host = "127.0.0.1"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urlunparse(
        (
            parsed.scheme,
            netloc,
            "",
            "",
            "",
            "",
        )
    ).rstrip("/")


def required_inputs(playbook: dict[str, Any]) -> list[str]:
    inputs = playbook.get("inputs", [])
    if not isinstance(inputs, list):
        return []
    return [
        str(item.get("name", "")).strip()
        for item in inputs
        if isinstance(item, dict) and item.get("required") and str(item.get("name", "")).strip()
    ]


def example_inputs(playbook: dict[str, Any]) -> dict[str, str]:
    raw_inputs = playbook.get("example_inputs", {})
    if not isinstance(raw_inputs, dict):
        return {}
    return {
        str(key).strip(): str(value).strip()
        for key, value in raw_inputs.items()
        if str(key).strip()
    }


def resolve_runtime(
    base_url: str,
    cookie: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    personas = {persona["name"]: persona for persona in list_personas(base_url, cookie)}
    openapi_tools = {tool["name"]: tool for tool in list_openapi_tools(base_url, cookie)}
    return personas, openapi_tools


def execute_playbook(
    playbook: dict[str, Any],
    base_url: str,
    cookie: str,
    inputs: dict[str, str],
    *,
    step_timeout_seconds: int = 90,
    show_progress: bool = False,
    stop_on_failure: bool = True,
) -> dict[str, Any]:
    personas, openapi_tools = resolve_runtime(base_url, cookie)
    context: dict[str, Any] = {"inputs": inputs, "steps": {}}
    failures: list[str] = []
    sessions: dict[str, str] = {}
    step_results: list[dict[str, Any]] = []

    for step in playbook["steps"]:
        step_id = str(step["id"])
        persona_name = str(step["persona"])
        tool_name = str(step.get("tool", "")).strip() or None
        execution_mode = str(step.get("execution_mode", "")).strip() or "chat"
        prompt = render_template(str(step.get("prompt", "")), context)
        mock_llm_response = step.get("mock_llm_response")
        if mock_llm_response is not None:
            mock_llm_response = str(mock_llm_response)
        forced_tool_id = None
        persona = None
        if execution_mode != "template":
            persona = personas.get(persona_name)
            if persona is None:
                failures.append(f"Step {step_id}: missing persona {persona_name}")
                continue

            if persona_name not in sessions:
                sessions[persona_name] = create_chat_session(
                    base_url,
                    cookie,
                    int(persona["id"]),
                    description=f"playbook-{playbook['name']}-{persona_name}-{uuid.uuid4()}",
                )
        if tool_name:
            tool = openapi_tools.get(tool_name)
            if tool is None:
                failures.append(f"Step {step_id}: missing tool {tool_name}")
                continue
            forced_tool_id = int(tool["id"])
        if show_progress:
            tool_suffix = f" tool={tool_name}" if tool_name else ""
            print(
                f"[RUN] Step {step_id} persona={persona_name}{tool_suffix} mode={execution_mode}",
                flush=True,
            )

        if execution_mode == "template":
            result = {
                "full_message": render_template(
                    str(step.get("response_template", "")), context
                ),
                "tool_call_debug": [],
                "custom_tool_events": [],
                "error": None,
            }
        elif tool_name and execution_mode == "direct":
            try:
                result = execute_direct_tool_step(tool, step, context, step_timeout_seconds)
            except Exception as exc:
                failures.append(f"Step {step_id}: direct_tool_failed:{exc}")
                if show_progress:
                    print(f"[FAIL] Step {step_id} direct_tool_failed:{exc}", flush=True)
                if stop_on_failure:
                    break
                continue
        else:
            try:
                result = send_chat_message_with_timeout(
                    base_url,
                    cookie,
                    sessions[persona_name],
                    prompt,
                    forced_tool_id=forced_tool_id,
                    step_timeout_seconds=step_timeout_seconds,
                    mock_llm_response=mock_llm_response,
                )
            except Exception as exc:
                failures.append(f"Step {step_id}: request_failed:{exc}")
                if show_progress:
                    print(f"[FAIL] Step {step_id} request_failed:{exc}", flush=True)
                if stop_on_failure:
                    break
                continue

        step_record = {
            "id": step_id,
            "persona": persona_name,
            "tool": tool_name,
            "execution_mode": execution_mode,
            "prompt": prompt,
            **result,
        }
        if (
            tool_name
            and execution_mode != "direct"
            and not any(
            debug.get("tool_name") == tool_name for debug in result.get("tool_call_debug", [])
        )
        ):
            step_record["warning"] = f"tool_not_observed:{tool_name}"
            failures.append(f"Step {step_id}: tool_not_observed:{tool_name}")

        context["steps"][step_id] = step_record
        step_results.append(step_record)
        if result.get("error"):
            failures.append(f"Step {step_id}: {result['error']}")
            if show_progress:
                print(f"[FAIL] Step {step_id} error={result['error']}", flush=True)
            if stop_on_failure:
                break
        elif step_record.get("warning"):
            if show_progress:
                print(f"[FAIL] Step {step_id} {step_record['warning']}", flush=True)
            if stop_on_failure:
                break
        elif show_progress:
            preview = result.get("full_message", "")[:120].replace("\n", " ")
            print(f"[OK] Step {step_id} response={preview}", flush=True)

    return {
        "ok": not failures,
        "playbook": playbook["name"],
        "inputs": inputs,
        "steps": step_results,
        "failures": failures,
    }


def _pick_openapi_operation(
    definition: dict[str, Any],
    rendered_args: dict[str, Any] | None = None,
) -> tuple[str, str, dict[str, Any]]:
    paths = definition.get("paths", {})
    if not isinstance(paths, dict) or not paths:
        raise ValueError("tool definition has no paths")
    candidates: list[tuple[int, str, str, dict[str, Any]]] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ["get", "post", "put", "patch", "delete"]:
            operation = path_item.get(method)
            if isinstance(operation, dict):
                score = 0
                if rendered_args is not None:
                    parameters = operation.get("parameters", [])
                    if not isinstance(parameters, list):
                        parameters = []
                    parameter_names = {
                        str(parameter.get("name", "")).strip()
                        for parameter in parameters
                        if isinstance(parameter, dict)
                        and str(parameter.get("name", "")).strip()
                    }
                    required_parameter_names = {
                        str(parameter.get("name", "")).strip()
                        for parameter in parameters
                        if isinstance(parameter, dict)
                        and str(parameter.get("name", "")).strip()
                        and bool(parameter.get("required"))
                    }
                    rendered_arg_names = {
                        str(name).strip()
                        for name in rendered_args.keys()
                        if str(name).strip()
                    }
                    if required_parameter_names and not required_parameter_names.issubset(
                        rendered_arg_names
                    ):
                        continue
                    score = len(parameter_names & rendered_arg_names)
                candidates.append((score, method.upper(), str(path), operation))
    if candidates:
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1], candidates[0][2], candidates[0][3]
    raise ValueError("tool definition has no supported operation")


def execute_direct_tool_step(
    tool: dict[str, Any],
    step: dict[str, Any],
    context: dict[str, Any],
    step_timeout_seconds: int,
) -> dict[str, Any]:
    definition = tool.get("definition", {}) or {}
    servers = definition.get("servers", []) if isinstance(definition, dict) else []
    if not isinstance(servers, list) or not servers or not isinstance(servers[0], dict):
        raise ValueError("tool definition missing server")
    base_url = resolve_host_accessible_url(str(servers[0].get("url", "")).rstrip("/"))
    if not base_url:
        raise ValueError("tool definition missing server url")

    rendered_args = render_structure(step.get("tool_args", {}), context)
    if not isinstance(rendered_args, dict):
        raise ValueError("tool_args must render to an object")
    method, path_template, operation = _pick_openapi_operation(definition, rendered_args)
    parameters = operation.get("parameters", [])
    if not isinstance(parameters, list):
        parameters = []

    path = path_template
    query_params: dict[str, Any] = {}
    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name", "")).strip()
        location = str(parameter.get("in", "")).strip()
        if not name or name not in rendered_args:
            continue
        value = rendered_args[name]
        if location == "path":
            path = path.replace(f"{{{name}}}", str(value))
        elif location == "query":
            query_params[name] = value

    url = f"{base_url}{path}"
    if query_params:
        url = f"{url}?{urlencode(query_params, doseq=True)}"

    request_body = None
    if method in {"POST", "PUT", "PATCH"}:
        query_keys = {
            str(parameter.get("name", "")).strip()
            for parameter in parameters
            if isinstance(parameter, dict) and str(parameter.get("in", "")).strip() == "query"
        }
        path_keys = {
            str(parameter.get("name", "")).strip()
            for parameter in parameters
            if isinstance(parameter, dict) and str(parameter.get("in", "")).strip() == "path"
        }
        request_body = {
            key: value
            for key, value in rendered_args.items()
            if key not in query_keys and key not in path_keys
        }

    headers = {
        str(header.get("key")): str(header.get("value"))
        for header in tool.get("custom_headers", []) or []
        if isinstance(header, dict) and header.get("key")
    }

    response = requests.request(
        method,
        url,
        headers=headers or None,
        json=request_body,
        timeout=step_timeout_seconds,
    )
    response.raise_for_status()
    try:
        data = response.json()
    except Exception:
        data = response.text

    return {
        "full_message": json.dumps(data, ensure_ascii=False),
        "tool_call_debug": [
            {
                "tool_name": tool["name"],
                "tool_args": rendered_args,
            }
        ],
        "custom_tool_events": [
            {
                "type": "direct_tool_result",
                "tool_name": tool["name"],
                "tool_args": rendered_args,
                "response_type": "json" if not isinstance(data, str) else "text",
                "data": data,
                "error": None,
            }
        ],
        "error": None,
    }


def print_human_result(result: dict[str, Any]) -> None:
    print(f"Playbook: {result['playbook']}")
    print(f"Inputs: {json.dumps(result['inputs'], ensure_ascii=False)}")
    for step in result["steps"]:
        print(f"- Step {step['id']} ({step['persona']})")
        if step.get("tool"):
            print(f"  tool={step['tool']}")
        if step.get("warning"):
            print(f"  warning={step['warning']}")
        if step.get("error"):
            print(f"  error={step['error']}")
        if step.get("custom_tool_events"):
            print(
                "  custom_tool_events="
                + json.dumps(step["custom_tool_events"][:3], ensure_ascii=False)
            )
        preview = step.get("full_message", "")[:300].replace("\n", " ")
        print(f"  response={preview}")
    print(f"Result: {'OK' if result['ok'] else 'FAILED'}")
    for failure in result.get("failures", []):
        print(f"  - {failure}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run security persona playbooks")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list-playbooks", action="store_true")
    mode.add_argument("--show-playbook")
    mode.add_argument("--verify-definitions", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--playbook")
    parser.add_argument("--input", action="append", default=[])
    parser.add_argument("--url", default=os.environ.get("ONYX_URL", "http://localhost:8080"))
    parser.add_argument("--email", default=os.environ.get("ONYX_EMAIL", "security-admin@onyx.local"))
    parser.add_argument("--password", default=os.environ.get("ONYX_PASSWORD", "admin123"))
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--step-timeout-seconds",
        type=int,
        default=90,
        help="Wall-clock timeout for each step during --execute",
    )
    parser.add_argument(
        "--continue-on-failure",
        action="store_true",
        help="Continue executing remaining steps after a step failure",
    )
    args = parser.parse_args()

    if args.list_playbooks:
        for item in list_playbooks():
            print(f"- {item['name']}: {item['display_name']}")
        return 0

    if args.show_playbook:
        playbook = load_playbook_definition(args.show_playbook)
        print(yaml.safe_dump(playbook, allow_unicode=True, sort_keys=False))
        return 0

    if args.verify_definitions:
        errors: list[str] = []
        for item in list_playbooks():
            playbook = load_playbook_definition(item["name"])
            playbook_errors = validate_playbook(playbook)
            for error in playbook_errors:
                errors.append(f"{item['name']}: {error}")
            sample_inputs = example_inputs(playbook)
            missing = [
                name for name in required_inputs(playbook) if name not in sample_inputs
            ]
            if missing:
                errors.append(
                    f"{item['name']}: example_inputs missing required keys: {', '.join(missing)}"
                )
                continue
            preview_context = {"inputs": sample_inputs, "steps": {}}
            for step in playbook.get("steps", []):
                if not isinstance(step, dict):
                    continue
                render_template(str(step.get("prompt", "")), preview_context)
        if errors:
            for error in errors:
                print(f"[ERROR] {error}")
            return 1
        print(f"[OK] Verified {len(list_playbooks())} playbook definitions")
        return 0

    if not args.playbook:
        raise SystemExit("--playbook is required with --dry-run/--execute")

    playbook = load_playbook_definition(args.playbook)
    definition_errors = validate_playbook(playbook)
    if definition_errors:
        for error in definition_errors:
            print(f"[ERROR] {error}")
        return 1

    inputs = parse_inputs(args.input)
    missing = [name for name in required_inputs(playbook) if name not in inputs]
    if missing:
        print(f"[ERROR] Missing required inputs: {', '.join(missing)}")
        return 1

    if args.dry_run:
        preview_context = {"inputs": inputs, "steps": {}}
        preview = []
        for step in playbook["steps"]:
            preview.append(
                {
                    "id": step["id"],
                    "persona": step["persona"],
                    "tool": step.get("tool"),
                    "prompt": render_template(str(step["prompt"]), preview_context),
                }
            )
        result = {"playbook": playbook["name"], "inputs": inputs, "steps": preview}
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print_human_result({**result, "ok": True, "failures": []})
        return 0

    cookie = get_cookie(args.url, args.email, args.password)
    if not cookie:
        print("[ERROR] Login failed. Check credentials.")
        return 1

    result = execute_playbook(
        playbook,
        args.url,
        cookie,
        inputs,
        step_timeout_seconds=args.step_timeout_seconds,
        show_progress=not args.json,
        stop_on_failure=not args.continue_on_failure,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human_result(result)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
