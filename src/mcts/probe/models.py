"""MCP probe models."""

from __future__ import annotations

from pydantic import BaseModel, Field

from mcts.probe.auth import RemoteAuth


class LiveServerConfig(BaseModel):
    """Launch parameters for a stdio MCP server."""

    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    server_name: str = "live-server"
    stderr_file: str | None = None


class RemoteServerConfig(BaseModel):
    """Connection parameters for a remote MCP server."""

    url: str
    transport: str = "streamable-http"
    auth: RemoteAuth | None = None
    server_name: str = "remote-server"
