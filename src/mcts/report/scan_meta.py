"""Scan report metadata: notices, scope, and discovery context."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from mcts.core.config import ScanConfig
from mcts.core.target import ScanTarget, TargetKind
from mcts.reporting.models import ScanReport

ScanScope = Literal["entrypoint", "repository", "config-static", "live", "snapshot"]

_TOOL_NOTICE = (
    "Static scan — MCP server was not started; tools/list was not called. "
    "For tool names and schemas use --live --i-understand-live-risk, --snapshot, or scan an entrypoint file."
)

_CONFIG_STATIC_NOTICE = (
    "Config-static scan: analyzed repository files; did not execute the server command or args. "
    "All config servers may share the same score until --live is used."
)


def infer_scan_scope(config: ScanConfig) -> ScanScope:
    if config.live or config.remote_url:
        return "live"
    if config.snapshot_path or any(
        [
            config.snapshot_tools,
            config.snapshot_prompts,
            config.snapshot_resources,
            config.snapshot_instructions,
        ]
    ):
        return "snapshot"
    if config.config_path and config.config_server:
        target = ScanTarget(config.target)
        if target.kind == TargetKind.DIRECTORY:
            return "config-static"
    target = ScanTarget(config.target)
    if target.kind == TargetKind.FILE:
        return "entrypoint"
    return "repository"


def is_config_static_scan(config: ScanConfig) -> bool:
    return bool(config.config_path and config.config_server and not config.live and not config.remote_url)


def build_scan_notes(config: ScanConfig) -> list[str]:
    notes: list[str] = []
    if is_config_static_scan(config):
        rel_config = _rel_path(config.config_path) if config.config_path else ""
        notes.append(f"{_CONFIG_STATIC_NOTICE} (config={rel_config}, server={config.config_server})")
    return notes


def needs_tool_discovery_notice(report: ScanReport, *, live: bool, snapshot: bool) -> bool:
    if live or snapshot:
        return False
    if report.server.tools:
        return False
    mode = report.server.discovery_mode or "static"
    return mode in ("static", "empty", "config-static", "static-json")


def tool_discovery_notice_text(server, *, scan_scope: str) -> str | None:
    """Return notice text for JSON/SARIF when static scan found zero tools."""
    if scan_scope in ("live", "snapshot"):
        return None
    if server.tools:
        return None
    mode = server.discovery_mode or "static"
    if mode in ("live", "static-json"):
        return None
    return _TOOL_NOTICE


def tool_discovery_context(report: ScanReport, *, live: bool, snapshot: bool) -> dict:
    show = needs_tool_discovery_notice(report, live=live, snapshot=snapshot)
    return {
        "show_banner": show,
        "message": _TOOL_NOTICE if show else "",
        "tools_discovered": len(report.server.tools),
    }


def _rel_path(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return str(path)
