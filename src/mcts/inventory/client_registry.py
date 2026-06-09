"""Well-known MCP client config and skill directory registry."""

from __future__ import annotations

import sys

ClientPath = tuple[str, str]

CLIENT_CONFIG_PATHS: dict[str, tuple[ClientPath, ...]] = {
    "linux": (
        ("cursor", "~/.cursor/mcp.json"),
        ("vscode", "~/.vscode/mcp.json"),
        ("claude", "~/.config/Claude/claude_desktop_config.json"),
        ("windsurf", "~/.codeium/windsurf/mcp_config.json"),
        ("gemini", "~/.config/gemini/mcp.json"),
        ("gemini", "~/.gemini/settings.json"),
        ("codex", "~/.codex/mcp.json"),
        ("codex", "~/.config/codex/mcp.json"),
        ("cline", "~/.cline/mcp_settings.json"),
        ("cline", "~/.config/cline/mcp.json"),
        ("openclaw", "~/.openclaw/mcp.json"),
        ("zed", "~/.config/zed/settings.json"),
        ("roo", "~/.roo/mcp.json"),
        ("continue", "~/.continue/config.json"),
        ("amazonq", "~/.aws/amazonq/mcp.json"),
        ("amazonq", "~/.amazonq/mcp.json"),
    ),
    "darwin": (
        ("cursor", "~/.cursor/mcp.json"),
        ("vscode", "~/.vscode/mcp.json"),
        ("claude", "~/Library/Application Support/Claude/claude_desktop_config.json"),
        ("windsurf", "~/.codeium/windsurf/mcp_config.json"),
        ("gemini", "~/.config/gemini/mcp.json"),
        ("gemini", "~/.gemini/settings.json"),
        ("codex", "~/.codex/mcp.json"),
        ("codex", "~/.config/codex/mcp.json"),
        ("cline", "~/.cline/mcp_settings.json"),
        (
            "cline",
            "~/Library/Application Support/Code/User/globalStorage/"
            "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        ),
        ("openclaw", "~/.openclaw/mcp.json"),
        ("zed", "~/.config/zed/settings.json"),
        ("roo", "~/.roo/mcp.json"),
        ("continue", "~/.continue/config.json"),
        ("amazonq", "~/.aws/amazonq/mcp.json"),
        ("amazonq", "~/.amazonq/mcp.json"),
        ("vscode", "~/Library/Application Support/Code/User/settings.json"),
    ),
    "win32": (
        ("cursor", "~/.cursor/mcp.json"),
        ("vscode", "~/.vscode/mcp.json"),
        ("claude", "~/AppData/Roaming/Claude/claude_desktop_config.json"),
        ("windsurf", "~/.codeium/windsurf/mcp_config.json"),
        ("gemini", "~/.config/gemini/mcp.json"),
        ("codex", "~/.codex/mcp.json"),
        ("cline", "~/.cline/mcp_settings.json"),
        ("openclaw", "~/.openclaw/mcp.json"),
        ("zed", "~/.config/zed/settings.json"),
        ("roo", "~/.roo/mcp.json"),
        ("continue", "~/.continue/config.json"),
        ("amazonq", "~/.aws/amazonq/mcp.json"),
        ("vscode", "~/AppData/Roaming/Code/User/settings.json"),
    ),
}

SKILL_DIR_CANDIDATES: dict[str, tuple[str, ...]] = {
    "cursor": ("~/.cursor/skills", ".cursor/skills"),
    "claude": ("~/.claude/skills", ".claude/skills"),
    "windsurf": ("~/.codeium/windsurf/skills", ".windsurf/skills"),
    "vscode": ("~/.vscode/skills", ".vscode/skills"),
    "gemini": ("~/.gemini/skills", ".gemini/skills"),
    "codex": ("~/.codex/skills", ".codex/skills"),
    "cline": ("~/.cline/skills", ".cline/skills"),
    "openclaw": ("~/.openclaw/skills", ".openclaw/skills"),
    "zed": ("~/.config/zed/skills", ".zed/skills"),
    "roo": ("~/.roo/skills", ".roo/skills"),
    "continue": ("~/.continue/skills", ".continue/skills"),
    "amazonq": ("~/.amazonq/skills", ".amazonq/skills"),
}


def platform_key() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform == "win32":
        return "win32"
    return "linux"


def config_paths_for_platform() -> tuple[ClientPath, ...]:
    return CLIENT_CONFIG_PATHS.get(platform_key(), CLIENT_CONFIG_PATHS["linux"])
