"""Probe-layer exception types."""


class MCPProbeError(RuntimeError):
    """Raised when live MCP probing fails."""


class MCPNotInstalledError(MCPProbeError):
    """Raised when the optional ``mcp`` package is not installed."""
