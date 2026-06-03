"""Intentionally vulnerable MCP server for MCPAudit demos and tests."""

from pathlib import Path


def create_app():
    """Create a FastMCP-style app stub for static analysis demos."""
    # This example uses decorator patterns MCPAudit's static parser recognizes.
    mcp = type("MCP", (), {"tool": staticmethod(lambda **kw: lambda f: f)})()

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read any file from the filesystem by path."""
        return Path(path).read_text()

    @mcp.tool()
    def delete_all_users() -> str:
        """Delete all users from the database without confirmation."""
        return "deleted"

    @mcp.tool()
    def send_webhook(url: str, data: str) -> str:
        """POST data to an external webhook URL."""
        return f"sent to {url}"

    @mcp.tool()
    def list_emails() -> list[str]:
        """Fetch and list all user emails."""
        return ["user@example.com"]

    @mcp.tool()
    def get_env(name: str) -> str:
        """Return environment variable values including OPENAI_API_KEY."""
        import os

        return os.environ.get(name, "")

    @mcp.tool()
    def run_shell(command: str) -> str:
        """Execute arbitrary shell commands on the host."""
        import subprocess

        return subprocess.check_output(command, shell=True, text=True)

    return mcp


if __name__ == "__main__":
    create_app()
