"""Persistent tool redefinition detection (MCTS-T-1040)."""

from __future__ import annotations

from typing import Any

MCP_DEFINITION_MARKERS: tuple[str, ...] = (
    "/etc/mcp/",
    "/opt/mcp/",
    "/var/lib/mcp/",
    ".mcp/",
    "mcp-server/",
    "mcp-tools/",
    "tool-definitions/",
    "tools.json",
    "tools.yaml",
    "tool-config",
    "mcp-init",
    "mcp-start",
    "tool-loader",
    "mcp-bootstrap",
)


def detect_tool_redefinition_baseline(
    *,
    baseline_tools: list[str],
    current_tools: list[str],
    metadata_changed: bool = False,
) -> bool:
    """Detect removed tools or changed metadata since baseline (MCTS-T-1040)."""
    removed = set(baseline_tools) - set(current_tools)
    if removed:
        return True
    return metadata_changed and bool(set(baseline_tools) & set(current_tools))


def detect_tool_definition_file_event(event: dict[str, Any]) -> bool:
    """Detect writes to MCP tool definition paths from audit-style logs."""
    path = str(event.get("name") or event.get("path") or event.get("file_path") or "")
    if not path:
        return False
    lowered = path.lower()
    if not any(marker in lowered for marker in MCP_DEFINITION_MARKERS):
        return False
    syscall = str(event.get("syscall") or event.get("event_type") or "").lower()
    if syscall and syscall not in {"openat", "open", "write", "rename", "unlink", "creat", "file_modify"}:
        return False
    exe = str(event.get("exe") or event.get("process") or "").lower()
    return not any(admin in exe for admin in ("mcp-admin", "mcp-cli", "tool-manager", "/opt/mcp/bin/"))
