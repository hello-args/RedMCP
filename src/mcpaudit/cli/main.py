"""MCPAudit command-line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from mcpaudit import __version__
from mcpaudit.core.config import ScanConfig
from mcpaudit.core.scanner import Scanner
from mcpaudit.reporting.html import write_html_report

app = typer.Typer(
    name="mcpaudit",
    help="Offensive security testing framework for MCP servers.",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"mcpaudit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """MCPAudit — scan MCP servers for security vulnerabilities."""


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(help="Path to MCP server entrypoint or server URL"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write JSON report to file"),
    ] = None,
    fail_on_critical: Annotated[
        bool,
        typer.Option("--fail-on-critical", help="Exit with code 1 if critical findings exist"),
    ] = False,
) -> None:
    """Run a full security scan against an MCP server."""
    config = ScanConfig(target=target, output=output, fail_on_critical=fail_on_critical)
    scanner = Scanner(config)
    report = scanner.run()
    scanner.print_summary(report)

    if output:
        output.write_text(report.model_dump_json(indent=2))
        console.print(f"[green]Report written to[/green] {output}")

    if fail_on_critical and report.summary.critical > 0:
        raise typer.Exit(code=1)


@app.command()
def report(
    input_file: Annotated[
        Path,
        typer.Argument(help="JSON report from a previous scan"),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="HTML report path"),
    ] = Path("security-report.html"),
) -> None:
    """Generate an HTML security report from scan results."""
    from mcpaudit.reporting.models import ScanReport

    data = ScanReport.model_validate_json(input_file.read_text())
    write_html_report(data, output)
    console.print(f"[green]HTML report written to[/green] {output}")


@app.command()
def fuzz(
    target: Annotated[
        Path,
        typer.Argument(help="Path to MCP server entrypoint or server URL"),
    ],
) -> None:
    """Fuzz an MCP server with generated attack payloads. (Coming soon)"""
    console.print("[yellow]Fuzzer not yet implemented.[/yellow] Track progress in the roadmap.")


@app.command()
def pentest(
    target: Annotated[
        Path,
        typer.Argument(help="Path to MCP server entrypoint or server URL"),
    ],
) -> None:
    """Run AI-assisted penetration testing. (Coming soon)"""
    console.print("[yellow]MCPAudit Agent pentest not yet implemented.[/yellow]")


def run() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    run()
