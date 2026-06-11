"""Load MCP server metadata from pre-exported JSON snapshots."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcts.discovery.json5_util import load_json5
from mcts.mcp.models import MCPPrompt, MCPResource, MCPServerInfo, MCPTool


class StaticJsonError(RuntimeError):
    """Raised when a snapshot file cannot be parsed."""


def load_snapshot(
    tools_path: Path | None = None,
    prompts_path: Path | None = None,
    resources_path: Path | None = None,
    instructions_path: Path | None = None,
    snapshot_path: Path | None = None,
) -> MCPServerInfo:
    """Build MCPServerInfo from tools/list-style JSON files."""
    if snapshot_path is not None:
        return _load_combined_snapshot(snapshot_path)

    tools = _load_tools(tools_path) if tools_path else []
    prompts = _load_prompts(prompts_path) if prompts_path else []
    resources = _load_resources(resources_path) if resources_path else []
    instructions = _load_instructions(instructions_path) if instructions_path else None

    if not any([tools, prompts, resources, instructions]):
        raise StaticJsonError("Provide --snapshot or at least one of tools/prompts/resources JSON")

    return MCPServerInfo(
        name="static-snapshot",
        tools=tools,
        prompts=prompts,
        resources=resources,
        instructions=instructions,
        transport="static-json",
        discovery_mode="static-json",
    )


def _load_combined_snapshot(path: Path) -> MCPServerInfo:
    payload = _read_json(path)
    if isinstance(payload, list):
        tools = _validate_tool_rows(payload)
        return MCPServerInfo(
            name="static-snapshot",
            tools=[_tool_from_dict(row) for row in tools],
            transport="static-json",
            discovery_mode="static-json",
        )
    if not isinstance(payload, dict):
        raise StaticJsonError(f"Snapshot must be object or array: {path}")
    if _looks_like_scan_report(payload):
        raise StaticJsonError("Invalid snapshot: file looks like a scan report, not a tools/list snapshot")

    prompts = _extract_list(payload, ("prompts",))
    resources = _extract_list(payload, ("resources",))
    instructions = payload.get("instructions")
    if isinstance(instructions, dict):
        instructions = instructions.get("text") or instructions.get("instructions")
    tools = _extract_snapshot_tools(payload)

    if not any([tools, prompts, resources, instructions]):
        raise StaticJsonError(
            "Invalid snapshot: expected tools/list export or combined snapshot "
            "with tools, prompts, resources, or instructions"
        )

    return MCPServerInfo(
        name=str(payload.get("name") or payload.get("server_name") or "static-snapshot"),
        tools=[_tool_from_dict(row) for row in tools],
        prompts=[_prompt_from_dict(row) for row in prompts],
        resources=[_resource_from_dict(row) for row in resources],
        instructions=str(instructions) if instructions else None,
        transport="static-json",
        discovery_mode="static-json",
    )


def _looks_like_scan_report(payload: dict[str, Any]) -> bool:
    return "score" in payload and "findings" in payload


def _extract_snapshot_tools(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("tools", "items"):
        if key in payload:
            value = payload.get(key)
            if isinstance(value, list):
                return _validate_tool_rows(value)
            raise StaticJsonError(f"Invalid snapshot: {key} must be an array")

    result = payload.get("result")
    if isinstance(result, dict) and "tools" in result:
        tools = result.get("tools")
        if isinstance(tools, list):
            return _validate_tool_rows(tools)
        raise StaticJsonError("Invalid snapshot: result.tools must be an array")

    return []


def _validate_tool_rows(rows: list[Any]) -> list[dict[str, Any]]:
    if not rows:
        raise StaticJsonError("Invalid snapshot: tools array is empty")

    tools: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise StaticJsonError(f"Invalid snapshot: tools[{index}] must be an object")
        name = row.get("name")
        if not isinstance(name, str) or not name.strip():
            raise StaticJsonError(f"Invalid snapshot: tools[{index}] missing required 'name' field")
        tools.append(row)
    return tools


def _read_json(path: Path) -> Any:
    try:
        if path.suffix.lower() in (".json5", ".jsonc"):
            return load_json5(path)
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise StaticJsonError(f"Invalid snapshot JSON: {path}") from exc


def _extract_list(payload: dict[str, Any], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
        if isinstance(value, dict):
            nested = value.get("tools") or value.get("prompts") or value.get("resources")
            if isinstance(nested, list):
                return [row for row in nested if isinstance(row, dict)]
    return []


def _load_tools(path: Path) -> list[MCPTool]:
    return [_tool_from_dict(row) for row in _read_json(path) if isinstance(row, dict)]


def _load_prompts(path: Path) -> list[MCPPrompt]:
    payload = _read_json(path)
    rows = payload if isinstance(payload, list) else _extract_list(payload, ("prompts",))
    return [_prompt_from_dict(row) for row in rows]


def _load_resources(path: Path) -> list[MCPResource]:
    payload = _read_json(path)
    rows = payload if isinstance(payload, list) else _extract_list(payload, ("resources",))
    return [_resource_from_dict(row) for row in rows]


def _load_instructions(path: Path) -> str | None:
    payload = _read_json(path)
    if isinstance(payload, str):
        return payload.strip() or None
    if isinstance(payload, dict):
        text = payload.get("instructions") or payload.get("text")
        return str(text).strip() if text else None
    return None


def _tool_from_dict(row: dict[str, Any]) -> MCPTool:
    schema = row.get("inputSchema") or row.get("input_schema") or {}
    if not isinstance(schema, dict):
        schema = {}
    return MCPTool(
        name=str(row.get("name") or "unknown"),
        description=str(row.get("description") or ""),
        input_schema=schema,
        discovered_via="static-json",
    )


def _prompt_from_dict(row: dict[str, Any]) -> MCPPrompt:
    args = row.get("arguments") or []
    if not isinstance(args, list):
        args = []
    return MCPPrompt(
        name=str(row.get("name") or "unknown"),
        description=str(row.get("description") or ""),
        arguments=[a for a in args if isinstance(a, dict)],
    )


def _resource_from_dict(row: dict[str, Any]) -> MCPResource:
    return MCPResource(
        uri=str(row.get("uri") or ""),
        name=str(row.get("name") or ""),
        description=str(row.get("description") or ""),
        mime_type=row.get("mimeType") or row.get("mime_type"),
    )
