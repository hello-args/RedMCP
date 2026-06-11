"""Tests for shared MCP tool file-access vs SQL classification."""

from __future__ import annotations

from mcts.analyzers.path_validation import PathValidationAnalyzer
from mcts.analyzers.tool_abuse import ToolAbuseAnalyzer
from mcts.analyzers.tool_classification import is_file_access_tool, is_sql_database_tool
from mcts.mcp.models import MCPServerInfo, MCPTool


def _tool(**kwargs: object) -> MCPTool:
    defaults: dict[str, object] = {
        "name": "read_file",
        "description": "Read a file from disk",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
        },
    }
    defaults.update(kwargs)
    return MCPTool(**defaults)  # type: ignore[arg-type]


def _server(tools: list[MCPTool]) -> MCPServerInfo:
    return MCPServerInfo(name="test", tools=tools, source_files={})


def test_read_query_with_sql_schema_is_not_file_tool() -> None:
    tool = _tool(
        name="read_query",
        description="Run a read-only Snowflake SQL query",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
        },
    )
    assert is_sql_database_tool(tool)
    assert not is_file_access_tool(tool)


def test_read_file_with_path_schema_is_file_tool() -> None:
    tool = _tool(name="read_file", description="Read a file from an allowed directory")
    assert not is_sql_database_tool(tool)
    assert is_file_access_tool(tool)


def test_run_query_name_is_not_file_tool() -> None:
    tool = _tool(
        name="run_query",
        description="Execute SQL against the analytics warehouse",
        input_schema={
            "type": "object",
            "properties": {"sql": {"type": "string"}},
        },
    )
    assert is_sql_database_tool(tool)
    assert not is_file_access_tool(tool)


def test_tool_abuse_skips_read_query() -> None:
    tool = _tool(
        name="read_query",
        description="Execute a JDBC SELECT statement",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
        },
    )
    findings = ToolAbuseAnalyzer().analyze(_server([tool]))
    assert not findings


def test_tool_abuse_flags_read_file() -> None:
    findings = ToolAbuseAnalyzer().analyze(_server([_tool()]))
    assert any(f.analyzer == "tool_abuse" and f.tool == "read_file" for f in findings)


def test_path_validation_skips_read_query() -> None:
    tool = _tool(
        name="read_query",
        description="Query Snowflake tables",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
        },
    )
    findings = PathValidationAnalyzer().analyze(_server([tool]))
    assert not findings


def test_path_validation_flags_read_file_without_guards() -> None:
    findings = PathValidationAnalyzer().analyze(_server([_tool()]))
    assert any(f.analyzer == "path_validation" and f.tool == "read_file" for f in findings)
