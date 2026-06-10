"""Orchestrate multi-language static MCP discovery."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.core.target import ScanTarget, TargetKind
from mcts.discovery.instruction_files import MARKDOWN_SUFFIXES, discover_instruction_surfaces
from mcts.discovery.static import StaticDiscovery
from mcts.discovery.static_go import GO_EXTENSIONS, GoStaticDiscovery
from mcts.discovery.static_js import JS_EXTENSIONS, JsStaticDiscovery
from mcts.discovery.static_merge import merge_static_server_info
from mcts.discovery.static_rust import RUST_EXTENSIONS, RustStaticDiscovery
from mcts.mcp.models import MCPServerInfo


def discover_static(config: ScanConfig) -> MCPServerInfo:
    """Run static discovery for all languages enabled in config."""
    target = ScanTarget(config.target)
    langs = {language.lower() for language in config.languages}

    if target.kind == TargetKind.FILE:
        suffix = target.path.suffix.lower()
        if suffix in MARKDOWN_SUFFIXES:
            return discover_instruction_surfaces(config)
        if suffix == ".py" and _python_enabled(langs):
            return merge_static_server_info(
                StaticDiscovery(config).discover(),
                discover_instruction_surfaces(config),
            )
        if suffix in JS_EXTENSIONS and _js_enabled(langs):
            return merge_static_server_info(
                JsStaticDiscovery(config).discover(),
                discover_instruction_surfaces(config),
            )
        if suffix in GO_EXTENSIONS and _go_enabled(langs):
            return merge_static_server_info(
                GoStaticDiscovery(config).discover(),
                discover_instruction_surfaces(config),
            )
        if suffix in RUST_EXTENSIONS and _rust_enabled(langs):
            return merge_static_server_info(
                RustStaticDiscovery(config).discover(),
                discover_instruction_surfaces(config),
            )
        empty = MCPServerInfo(name=target.path.stem, discovery_mode="empty")
        return merge_static_server_info(empty, discover_instruction_surfaces(config))

    results: list[MCPServerInfo] = []
    if _python_enabled(langs):
        results.append(StaticDiscovery(config).discover())
    if _js_enabled(langs):
        results.append(JsStaticDiscovery(config).discover())
    if _go_enabled(langs):
        results.append(GoStaticDiscovery(config).discover())
    if _rust_enabled(langs):
        results.append(RustStaticDiscovery(config).discover())
    results.append(discover_instruction_surfaces(config))

    if not results:
        return MCPServerInfo(name=target.path.name, discovery_mode="empty")
    return merge_static_server_info(*results)


def _python_enabled(langs: set[str]) -> bool:
    return "python" in langs


def _js_enabled(langs: set[str]) -> bool:
    return "typescript" in langs or "javascript" in langs or "js" in langs


def _go_enabled(langs: set[str]) -> bool:
    return "go" in langs or "golang" in langs


def _rust_enabled(langs: set[str]) -> bool:
    return "rust" in langs or "rs" in langs
