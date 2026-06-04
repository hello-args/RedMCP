"""Minimal low-risk MCP server for MCPAudit scoring demos."""


def create_app():
    mcp = type("MCP", (), {"tool": staticmethod(lambda **kw: lambda f: f)})()

    @mcp.tool()
    def greet(name: str) -> str:
        """Return a greeting for the given name."""
        return f"Hello, {name}"

    return mcp


if __name__ == "__main__":
    create_app()
