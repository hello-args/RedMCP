"""MCTS command-line interface."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from mcts import __version__
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.report.data import category_gate_failures, parse_category_gates
from mcts.reporting.html import write_html_report
from mcts.reporting.sarif import write_sarif_report
from mcts.ui.progress import print_scan_command, run_with_progress
from mcts.ui.report_renderer import ReportRenderer
from mcts.ui.theme import ThemeName, get_theme

app = typer.Typer(
    name="mcts",
    help="Model Context Threat Scanner for MCP servers.",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"mcts {__version__}")
        raise typer.Exit()


def _write_report(report, output: Path, output_format: str) -> None:
    fmt = output_format.lower()
    if fmt == "sarif":
        output.write_text(write_sarif_report(report))
    else:
        output.write_text(report.model_dump_json(indent=2))


def _check_gates(report, config: ScanConfig) -> None:
    if config.fail_on_critical and report.summary.critical > 0:
        raise typer.Exit(code=1)
    if config.min_score is not None and report.score.overall < config.min_score:
        console.print(f"[red]Score {report.score.overall} is below minimum {config.min_score}[/red]")
        raise typer.Exit(code=1)
    if config.max_critical is not None and report.summary.critical > config.max_critical:
        console.print(
            f"[red]Critical findings ({report.summary.critical}) exceed maximum ({config.max_critical})[/red]"
        )
        raise typer.Exit(code=1)
    category_failures = category_gate_failures(report.findings, config.fail_on_category)
    if category_failures:
        console.print("[red]Category risk thresholds exceeded:[/red]")
        for failure in category_failures:
            console.print(f"  [red]•[/red] {failure}")
        raise typer.Exit(code=1)


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """MCTS (Model Context Threat Scanner) — scan MCP servers for security threats."""


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(
            help="Path to MCP server entrypoint or repo directory (use . with --config)",
        ),
    ],
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Write report to file (JSON or SARIF)"),
    ] = None,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: json or sarif",
            case_sensitive=False,
        ),
    ] = "json",
    live: Annotated[
        bool,
        typer.Option("--live", help="Connect to a live stdio MCP server (requires consent)"),
    ] = False,
    command: Annotated[
        Optional[str],
        typer.Option("--command", help="Command to launch the MCP server (live mode)"),
    ] = None,
    args: Annotated[
        Optional[str],
        typer.Option("--args", help="Comma-separated args for --command (live mode)"),
    ] = None,
    config: Annotated[
        Optional[Path],
        typer.Option("--config", help="MCP client config JSON (Cursor, Claude, VS Code)"),
    ] = None,
    server: Annotated[
        Optional[str],
        typer.Option("--server", help="Server name inside --config mcpServers"),
    ] = None,
    understand_live_risk: Annotated[
        bool,
        typer.Option(
            "--i-understand-live-risk",
            help="Consent to live MCP probing (starts a real server subprocess)",
        ),
    ] = False,
    fail_on_critical: Annotated[
        bool,
        typer.Option("--fail-on-critical", help="Exit with code 1 if critical findings exist"),
    ] = False,
    min_score: Annotated[
        Optional[int],
        typer.Option("--min-score", help="Exit 1 if security score is below this value (0-100)"),
    ] = None,
    max_critical: Annotated[
        Optional[int],
        typer.Option("--max-critical", help="Exit 1 if critical finding count exceeds this"),
    ] = None,
    fail_on_category: Annotated[
        Optional[list[str]],
        typer.Option(
            "--fail-on-category",
            help="Exit 1 when category risk score reaches threshold (e.g. permissions:10). Repeatable.",
        ),
    ] = None,
    theme: Annotated[
        str,
        typer.Option(
            "--theme",
            help="Terminal theme: cyber, minimal, github",
            case_sensitive=False,
        ),
    ] = ThemeName.CYBER.value,
    no_progress: Annotated[
        bool,
        typer.Option("--no-progress", help="Skip pre-report progress animation"),
    ] = False,
    languages: Annotated[
        Optional[str],
        typer.Option(
            "--languages",
            help="Comma-separated discovery languages: python, typescript (default: both)",
        ),
    ] = None,
    baseline: Annotated[
        Optional[Path],
        typer.Option("--baseline", help="Compare tool metadata against a saved baseline JSON"),
    ] = None,
    save_baseline: Annotated[
        Optional[Path],
        typer.Option("--save-baseline", help="Write current tool metadata snapshot to JSON"),
    ] = None,
    sigma_rules_path: Annotated[
        Optional[Path],
        typer.Option(
            "--sigma-rules-path",
            help="Extra MCTS techniques directory for Sigma YAML rules",
        ),
    ] = None,
    semantic_secrets: Annotated[
        bool,
        typer.Option(
            "--semantic-secrets",
            help="Enable semantic credential detection (MCTS-M-025 / MCTS-T-1022)",
        ),
    ] = False,
    runtime_events: Annotated[
        Optional[Path],
        typer.Option(
            "--runtime-events",
            help="JSON file with runtime/probe telemetry events for RuntimeEventsAnalyzer",
        ),
    ] = None,
    behavioral_probe: Annotated[
        bool,
        typer.Option(
            "--behavioral-probe",
            help="Enable multi-turn MCTS-T-1026 behavioral probe events (auto with --live)",
        ),
    ] = False,
) -> None:
    """Run a full security scan against an MCP server."""
    import json

    from mcts.probe.consent import LiveProbeConsentError, live_consent_granted
    from mcts.probe.session import MCPProbeError

    if target == Path(".") and config is None:
        console.print("[red]Error:[/red] Provide a target path or --config with --server.")
        raise typer.Exit(code=2)

    if live and not live_consent_granted(flag=understand_live_risk):
        console.print(
            "[red]Live probing requires consent.[/red] Pass --i-understand-live-risk "
            "or set MCTS_LIVE_OK=1 in CI."
        )
        raise typer.Exit(code=2)

    if config and not server:
        console.print("[red]Error:[/red] --config requires --server.")
        raise typer.Exit(code=2)

    scan_target = config if (config and target == Path(".")) else target
    live_args = [part.strip() for part in args.split(",") if part.strip()] if args else []
    language_list = (
        [part.strip() for part in languages.split(",") if part.strip()]
        if languages
        else ["python", "typescript"]
    )

    try:
        resolved_theme = get_theme(theme)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    try:
        category_gates = parse_category_gates(fail_on_category)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    output_format = format.lower()
    if output_format not in ("json", "sarif"):
        console.print(f"[red]Error:[/red] Unknown format {format!r}. Use json or sarif.")
        raise typer.Exit(code=2)

    runtime_event_rows: list[dict] = []
    if runtime_events is not None:
        if not runtime_events.exists():
            console.print(f"[red]Error:[/red] Runtime events file not found: {runtime_events}")
            raise typer.Exit(code=2)
        payload = json.loads(runtime_events.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            runtime_event_rows = [row for row in payload if isinstance(row, dict)]
        elif isinstance(payload, dict):
            nested = payload.get("runtime_events")
            if isinstance(nested, list):
                runtime_event_rows = [row for row in nested if isinstance(row, dict)]
            else:
                console.print(
                    "[red]Error:[/red] Runtime events JSON must be an array or "
                    "an object with a runtime_events array."
                )
                raise typer.Exit(code=2)
        else:
            console.print("[red]Error:[/red] Runtime events JSON must be an array.")
            raise typer.Exit(code=2)

    config_obj = ScanConfig(
        target=scan_target,
        output=output,
        output_format=output_format,
        fail_on_critical=fail_on_critical,
        min_score=min_score,
        max_critical=max_critical,
        fail_on_category=category_gates,
        theme=resolved_theme.name.value,
        no_progress=no_progress,
        live=live,
        live_command=command,
        live_args=live_args,
        config_path=config,
        config_server=server,
        live_consent=understand_live_risk,
        languages=language_list,
        baseline_path=baseline,
        save_baseline_path=save_baseline,
        sigma_rules_path=sigma_rules_path,
        semantic_secrets=semantic_secrets,
        runtime_events=runtime_event_rows,
        behavioral_probe=behavioral_probe or live,
    )
    scanner = Scanner(config_obj)
    command_label = f"mcts scan {scan_target}"
    if live:
        command_label += " --live"
    renderer = ReportRenderer(resolved_theme, console=console)
    term_width = renderer._terminal_width()

    print_scan_command(console, resolved_theme, command_label, terminal_width=term_width)

    def _execute_scan():
        return scanner.run()

    try:
        started = time.perf_counter()
        report = run_with_progress(
            _execute_scan,
            theme=resolved_theme,
            console=console,
            enabled=not no_progress,
            terminal_width=term_width,
        )
    except (LiveProbeConsentError, MCPProbeError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    duration = time.perf_counter() - started

    if not no_progress:
        console.print()

    renderer.render(
        report,
        command=command_label,
        duration_seconds=duration,
        analyzers_run=scanner.analyzers_run_count(),
    )

    if output:
        _write_report(report, output, output_format)
        renderer.render_saved_notice(str(output))

    _check_gates(report, config_obj)


@app.command()
def inventory(
    scan: Annotated[
        bool,
        typer.Option("--scan", help="Static-scan each discovered server entrypoint for tools"),
    ] = False,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Write inventory JSON report"),
    ] = None,
    theme: Annotated[
        str,
        typer.Option("--theme", help="Terminal theme: cyber, minimal, github"),
    ] = ThemeName.CYBER.value,
) -> None:
    """Discover MCP servers configured in Cursor, Claude, VS Code, and Windsurf."""
    from mcts.analyzers.cross_server import CrossServerAnalyzer
    from mcts.inventory.runner import enrich_with_tool_names, run_inventory
    from mcts.taxonomy.mapper import enrich_findings

    try:
        resolved_theme = get_theme(theme)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    report = run_inventory()
    entries = enrich_with_tool_names(report.entries) if scan else report.entries

    shadow_findings = enrich_findings(CrossServerAnalyzer(entries).analyze_inventory(entries))

    console.print(f"[bold]MCP inventory[/bold] — {report.config_files_found} config file(s)")
    for client in report.clients_scanned:
        console.print(f"  • {client}")
    for entry in entries:
        tools = f" ({len(entry.tools)} tools)" if entry.tools else ""
        console.print(f"  [{entry.client}] {entry.server_name}{tools} — {entry.config_path}")

    if shadow_findings:
        console.print(f"\n[yellow]Cross-server shadowing:[/yellow] {len(shadow_findings)} finding(s)")
        for finding in shadow_findings[:5]:
            console.print(f"  • {finding.title}")

    payload = {
        "clients_scanned": report.clients_scanned,
        "config_files_found": report.config_files_found,
        "entries": [entry.model_dump() for entry in entries],
        "shadow_findings": [f.model_dump() for f in shadow_findings],
    }
    if output:
        import json

        output.write_text(json.dumps(payload, indent=2))
        ReportRenderer(resolved_theme, console=console).render_saved_notice(str(output))

    if shadow_findings and any(f.severity.value in ("critical", "high") for f in shadow_findings):
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
    theme: Annotated[
        str,
        typer.Option("--theme", help="Terminal theme: cyber, minimal, github"),
    ] = ThemeName.CYBER.value,
) -> None:
    """Generate an HTML security report from scan results."""
    from mcts.reporting.models import ScanReport

    try:
        resolved_theme = get_theme(theme)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    data = ScanReport.model_validate_json(input_file.read_text())
    write_html_report(data, output)
    renderer = ReportRenderer(resolved_theme, console=console)
    renderer.render_saved_notice(str(output))


@app.command()
def fuzz(
    target: Annotated[
        Path,
        typer.Argument(
            help="Path to MCP server entrypoint (use . with --config)",
        ),
    ],
    fuzz_level: Annotated[
        str,
        typer.Option(
            "--fuzz-level",
            help="Fuzz intensity: safe (read-only protocol), standard, aggressive",
            case_sensitive=False,
        ),
    ] = "safe",
    command: Annotated[
        Optional[str],
        typer.Option("--command", help="Command to launch the MCP server"),
    ] = None,
    args: Annotated[
        Optional[str],
        typer.Option("--args", help="Comma-separated args for --command"),
    ] = None,
    config: Annotated[
        Optional[Path],
        typer.Option("--config", help="MCP client config JSON"),
    ] = None,
    server: Annotated[
        Optional[str],
        typer.Option("--server", help="Server name inside --config mcpServers"),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Write fuzz findings JSON"),
    ] = None,
    understand_live_risk: Annotated[
        bool,
        typer.Option(
            "--i-understand-live-risk",
            help="Consent to start a live MCP server subprocess",
        ),
    ] = False,
    understand_fuzz_risk: Annotated[
        bool,
        typer.Option(
            "--i-understand-fuzz-risk",
            help="Consent for aggressive fuzz (may invoke tools/call)",
        ),
    ] = False,
    theme: Annotated[
        str,
        typer.Option("--theme", help="Terminal theme: cyber, minimal, github"),
    ] = ThemeName.CYBER.value,
) -> None:
    """Run safe read-only MCP protocol fuzz probes against a stdio server."""
    import json

    from mcts.analyzers.runtime_events import events_from_fuzz_findings
    from mcts.fuzz.payloads import FuzzLevel
    from mcts.fuzz.runner import FuzzRunner
    from mcts.probe.consent import live_consent_granted
    from mcts.taxonomy.mapper import enrich_findings

    if target == Path(".") and config is None:
        console.print("[red]Error:[/red] Provide a target path or --config with --server.")
        raise typer.Exit(code=2)

    if not live_consent_granted(flag=understand_live_risk):
        console.print(
            "[red]Fuzzing requires live server consent.[/red] Pass --i-understand-live-risk "
            "or set MCTS_LIVE_OK=1 in CI."
        )
        raise typer.Exit(code=2)

    if config and not server:
        console.print("[red]Error:[/red] --config requires --server.")
        raise typer.Exit(code=2)

    level = fuzz_level.lower()
    if level not in {item.value for item in FuzzLevel}:
        console.print(f"[red]Error:[/red] Unknown fuzz level {fuzz_level!r}.")
        raise typer.Exit(code=2)

    if level == FuzzLevel.AGGRESSIVE.value and not understand_fuzz_risk:
        console.print(
            "[red]Aggressive fuzz requires --i-understand-fuzz-risk "
            "(may invoke tools/call with test payloads).[/red]"
        )
        raise typer.Exit(code=2)

    scan_target = config if (config and target == Path(".")) else target
    live_args = [part.strip() for part in args.split(",") if part.strip()] if args else []

    try:
        resolved_theme = get_theme(theme)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    fuzz_config = ScanConfig(
        target=scan_target,
        live_command=command,
        live_args=live_args,
        config_path=config,
        config_server=server,
        live_consent=understand_live_risk,
        fuzz_level=level,
        fuzz_consent=understand_fuzz_risk,
        theme=resolved_theme.name.value,
    )

    try:
        result = FuzzRunner(fuzz_config).run()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except RuntimeError as exc:
        console.print(f"[red]Fuzz failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    findings = enrich_findings(result.findings)
    runtime_event_rows = events_from_fuzz_findings(findings)
    console.print(f"[bold]MCTS fuzz[/bold] — level={result.level.value}, probes={result.probes_run}")
    if not findings:
        console.print("[green]No fuzz findings — server handled probes cleanly.[/green]")
    else:
        for finding in findings:
            console.print(f"  [{finding.severity.value}] {finding.title}")

    payload = {
        "target": str(scan_target),
        "fuzz_level": result.level.value,
        "probes_run": result.probes_run,
        "runtime_events": runtime_event_rows,
        "findings": [f.model_dump() for f in findings],
    }
    if output:
        output.write_text(json.dumps(payload, indent=2))
        ReportRenderer(resolved_theme, console=console).render_saved_notice(str(output))

    if any(f.severity.value in ("critical", "high") for f in findings):
        raise typer.Exit(code=1)


@app.command()
def pentest(
    target: Annotated[
        Path,
        typer.Argument(help="Path to MCP server entrypoint or server URL"),
    ],
) -> None:
    """Run AI-assisted penetration testing. (Coming soon)"""
    console.print("[yellow]MCTS Agent pentest not yet implemented.[/yellow]")


def run() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    run()
