"""Tests for MCP client discovery."""

from pathlib import Path

from mcpaudit.mcp.client import MCPClient


def test_discover_tools_from_example_server(example_server_path: Path) -> None:
    client = MCPClient(example_server_path)
    info = client.discover()

    assert info.name == "server"
    tool_names = {tool.name for tool in info.tools}
    assert "read_file" in tool_names
    assert "delete_all_users" in tool_names
    assert len(info.tools) >= 5
