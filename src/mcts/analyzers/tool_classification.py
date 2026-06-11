"""Shared heuristics for classifying MCP tools as file-access vs database access."""

from __future__ import annotations

import re

from mcts.mcp.models import MCPTool

SQL_TOOL_NAMES = frozenset(
    {
        "read_query",
        "run_query",
        "execute_sql",
        "execute_query",
        "query_database",
        "sql_query",
    }
)

SQL_TOOL_MARKERS = (
    "sql",
    "query",
    "snowflake",
    "database",
    "jdbc",
    "postgres",
    "mysql",
    "sqlite",
)

SQL_SCHEMA_PARAMS = frozenset({"query", "sql", "statement", "sql_query"})

FILE_SCHEMA_PARAMS = frozenset(
    {
        "path",
        "filepath",
        "file_path",
        "filename",
        "directory",
        "dir",
    }
)

FILE_TOOL_NAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bread_file\b", re.I),
    re.compile(r"\bfile_read\b", re.I),
    re.compile(r"\bread_path\b", re.I),
    re.compile(r"\bpath_read\b", re.I),
    re.compile(r"\bload_file\b", re.I),
    re.compile(r"\bopen_file\b", re.I),
    re.compile(r"\bwrite_file\b", re.I),
    re.compile(r"\bfile_write\b", re.I),
    re.compile(r"\bget_file\b", re.I),
    re.compile(r"\blist_dir\b", re.I),
    re.compile(r"\blist_directory\b", re.I),
)

FILE_TOOL_TOKEN = re.compile(r"\b(read|file|path|open|load|fetch)\b", re.I)


def _schema_param_names(tool: MCPTool) -> set[str]:
    schema = tool.input_schema or {}
    if not isinstance(schema, dict):
        return set()
    props = schema.get("properties")
    if not isinstance(props, dict):
        return set()
    return {str(name).lower() for name in props}


def is_sql_database_tool(tool: MCPTool) -> bool:
    """Return True when the tool appears to execute SQL rather than read files."""
    if tool.name.lower() in SQL_TOOL_NAMES:
        return True

    schema_params = _schema_param_names(tool)
    has_sql_schema = bool(schema_params & SQL_SCHEMA_PARAMS)
    has_file_schema = bool(schema_params & FILE_SCHEMA_PARAMS)

    if has_sql_schema and not has_file_schema:
        return True

    haystack = f"{tool.name} {tool.description}".lower()
    if any(marker in haystack for marker in SQL_TOOL_MARKERS):
        return not (has_file_schema and not has_sql_schema)

    return False


def is_file_access_tool(tool: MCPTool) -> bool:
    """Return True when the tool likely reads or writes local filesystem paths."""
    if is_sql_database_tool(tool):
        return False

    schema_params = _schema_param_names(tool)
    has_file_schema = bool(schema_params & FILE_SCHEMA_PARAMS)
    has_sql_schema = bool(schema_params & SQL_SCHEMA_PARAMS)

    if has_file_schema and not has_sql_schema:
        return True

    if any(pattern.search(tool.name) for pattern in FILE_TOOL_NAME_PATTERNS):
        return True

    haystack = f"{tool.name} {tool.description}"
    if FILE_TOOL_TOKEN.search(haystack) and has_file_schema:
        return True

    return bool(re.search(r"\bfile\s+(?:path|system|access|read|write)\b", haystack, re.I))
