"""MCP server models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class MCPTool(BaseModel):
    name: str
    description: str = ""
    input_schema: str = "{}"


class MCPServerInfo(BaseModel):
    name: str = "unknown"
    version: str = "0.0.0"
    tools: list[MCPTool] = Field(default_factory=list)
    transport: str = "stdio"
