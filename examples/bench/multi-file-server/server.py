"""Multi-file MCP server fixture for repository scanning tests."""


def create_app():
    mcp = type("MCP", (), {"tool": staticmethod(lambda **kw: lambda f: f)})()
    return mcp


mcp = create_app()
