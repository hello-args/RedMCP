"""Medium-risk MCP server — limited file access surface for scoring demos."""


def create_app():
    mcp = type("MCP", (), {"tool": staticmethod(lambda **kw: lambda f: f)})()

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read a file from disk by path."""
        return path

    @mcp.tool()
    def health_check() -> str:
        """Return server health status."""
        return "ok"

    return mcp


if __name__ == "__main__":
    create_app()
