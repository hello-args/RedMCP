"""MCTS command-line interface."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from mcts import __version__
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.output.analysis_dir import (
    ANALYSIS_DIR_NAME,
    analysis_path,
    resolve_output_path,
    resolve_report_input_path,
)
from mcts.output.artifacts import persist_scan_artifacts
from mcts.report.data import category_gate_failures, parse_category_gates
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


def _write_report(
    report,
    output: Path,
    output_format: str,
    *,
    target: str = "",
    remote_url: str | None = None,
) -> None:
    import json

    fmt = output_format.lower()
    if fmt == "sarif":
        output.write_text(write_sarif_report(report))
    elif fmt == "raw":
        payload = {
            "target": target,
            "remote_url": remote_url,
            "scan_results": report.model_dump(mode="json"),
        }
        output.write_text(json.dumps(payload, indent=2))
    else:
        output.write_text(report.model_dump_json(indent=2))


def _print_discovery_warnings(server, stderr_file: str | None) -> None:
    if not server.discovery_warnings:
        return
    console.print("[yellow]Warning:[/yellow] Live MCP discovery was incomplete:")
    for warning in server.discovery_warnings:
        console.print(f"  [yellow]•[/yellow] {warning}")
    if not stderr_file:
        console.print(
            "  [dim]Tip: pass --stderr-file PATH when probing stdio servers to capture server stderr.[/dim]"
        )


def _check_strict_live(report, config: ScanConfig) -> None:
    if not config.strict_live:
        return
    warnings = report.server.discovery_warnings
    if not warnings:
        return
    console.print("[red]Error:[/red] --strict-live: live discovery did not complete successfully.")
    for warning in warnings:
        console.print(f"  [red]•[/red] {warning}")
    raise typer.Exit(code=2)


def _print_startup_error(exc) -> None:
    from rich.panel import Panel

    from mcts.probe.startup_errors import MCPStartupError

    if not isinstance(exc, MCPStartupError):
        return
    lines = [f"Category: {exc.category_label}"]
    if exc.detected_line:
        lines.append(f"Detected: {exc.detected_line}")
    lines.append(f"Suggested fix: {exc.suggestion}")
    console.print(
        Panel(
            "\n".join(lines),
            title="MCP SERVER FAILED TO START",
            border_style="red",
        )
    )


def _print_discovery_hints(target: Path) -> None:
    from mcts.discovery.onboarding import format_discovery_hints

    root = target.expanduser().resolve()
    if not root.is_dir():
        return
    hints = format_discovery_hints(root)
    if not hints:
        return
    console.print("[cyan]ℹ[/cyan] MCP discovery hints:")
    for line in hints.splitlines():
        console.print(f"  [dim]{line}[/dim]")


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
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """MCTS (Model Context Threat Scanner) — scan MCP servers for security threats."""
    from mcts._install_warning import maybe_warn_venv_install

    maybe_warn_venv_install(console)


@app.command()
def scan(
    target: Annotated[
        Path | None,
        typer.Argument(
            help="Path to MCP server entrypoint or repo directory (omit with --machine-wide)",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=f"Report file path (default: {ANALYSIS_DIR_NAME}/scan-report.json or .sarif)",
        ),
    ] = None,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: json, sarif, or raw (envelope)",
            case_sensitive=False,
        ),
    ] = "json",
    live: Annotated[
        bool,
        typer.Option("--live", help="Connect to a live stdio MCP server (requires consent)"),
    ] = False,
    command: Annotated[
        str | None,
        typer.Option("--command", help="Command to launch the MCP server (live mode)"),
    ] = None,
    args: Annotated[
        str | None,
        typer.Option("--args", help="Comma-separated args for --command (live mode)"),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="MCP client config JSON (Cursor, Claude, VS Code)"),
    ] = None,
    server: Annotated[
        str | None,
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
        int | None,
        typer.Option("--min-score", help="Exit 1 if security score is below this value (0-100)"),
    ] = None,
    max_critical: Annotated[
        int | None,
        typer.Option("--max-critical", help="Exit 1 if critical finding count exceeds this"),
    ] = None,
    fail_on_category: Annotated[
        list[str] | None,
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
        str | None,
        typer.Option(
            "--languages",
            help="Comma-separated discovery languages: python, typescript (default: both)",
        ),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option("--baseline", help="Compare tool metadata against a saved baseline JSON"),
    ] = None,
    save_baseline: Annotated[
        Path | None,
        typer.Option("--save-baseline", help="Write current tool metadata snapshot to JSON"),
    ] = None,
    sigma_rules_path: Annotated[
        Path | None,
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
        Path | None,
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
    url: Annotated[
        str | None,
        typer.Option("--url", help="Remote MCP server URL (SSE or streamable HTTP)"),
    ] = None,
    transport: Annotated[
        str,
        typer.Option("--transport", help="Remote transport: streamable-http or sse"),
    ] = "streamable-http",
    bearer_token: Annotated[
        str | None,
        typer.Option("--bearer-token", help="Bearer token for remote MCP server"),
    ] = None,
    header: Annotated[
        list[str] | None,
        typer.Option("--header", help="Custom HTTP header (Name: Value). Repeatable."),
    ] = None,
    surfaces: Annotated[
        str | None,
        typer.Option(
            "--surfaces",
            help="Comma-separated surfaces: tool,prompt,resource,instruction",
        ),
    ] = None,
    resource_mime: Annotated[
        str | None,
        typer.Option(
            "--resource-mime",
            help="Comma-separated MIME types to scan for resources (e.g. text/plain,application/json)",
        ),
    ] = None,
    snapshot: Annotated[
        Path | None,
        typer.Option("--snapshot", help="Static JSON snapshot (tools/list export)"),
    ] = None,
    expand_vars: Annotated[
        str,
        typer.Option("--expand-vars", help="Env expansion: auto, linux, mac, windows, off"),
    ] = "auto",
    pip_audit: Annotated[
        bool,
        typer.Option("--pip-audit", help="Run pip-audit on Python dependencies"),
    ] = False,
    npm_audit: Annotated[
        bool,
        typer.Option("--npm-audit", help="Run npm audit on Node dependencies"),
    ] = False,
    protocol_probe: Annotated[
        bool,
        typer.Option("--protocol-probe", help="Active MCPS protocol checks on --url"),
    ] = False,
    stderr_file: Annotated[
        str | None,
        typer.Option("--stderr-file", help="Capture live server stderr to file"),
    ] = None,
    strict_live: Annotated[
        bool,
        typer.Option(
            "--strict-live",
            help="Exit 2 when live discovery is incomplete (e.g. list_tools failed after initialize)",
        ),
    ] = False,
    enable_yara: Annotated[
        bool,
        typer.Option("--yara", help="Enable YARA metadata analyzer"),
    ] = False,
    enable_llm: Annotated[
        bool,
        typer.Option("--llm-judge", help="Enable opt-in LLM-as-judge analyzer"),
    ] = False,
    enable_llm_triage: Annotated[
        bool,
        typer.Option(
            "--llm-triage",
            help="Enable LLM metadata triage (malicious/safe/suspect; requires MCTS_LLM_API_KEY)",
        ),
    ] = False,
    enable_semgrep: Annotated[
        bool,
        typer.Option(
            "--semgrep",
            help="Enable Semgrep SAST adapter (requires semgrep CLI on PATH)",
        ),
    ] = False,
    semgrep_rules: Annotated[
        Path | None,
        typer.Option("--semgrep-rules", help="Custom Semgrep rules file or directory"),
    ] = None,
    enable_cloud: Annotated[
        bool,
        typer.Option("--cloud-inspect", help="Enable opt-in cloud ML inspect API"),
    ] = False,
    enable_virustotal: Annotated[
        bool,
        typer.Option("--virustotal", help="Enable VirusTotal hash lookup"),
    ] = False,
    terminal_format: Annotated[
        str | None,
        typer.Option(
            "--terminal-format",
            help="Terminal layout: table, by_tool, by_analyzer, by_severity, summary",
        ),
    ] = None,
    tool_filter: Annotated[
        str | None,
        typer.Option("--tool-filter", help="Comma-separated tool names to scan"),
    ] = None,
    analyzer_filter: Annotated[
        str | None,
        typer.Option("--analyzer-filter", help="Comma-separated analyzer names"),
    ] = None,
    severity_filter: Annotated[
        str | None,
        typer.Option("--severity-filter", help="Comma-separated severities to show"),
    ] = None,
    analyzers: Annotated[
        str | None,
        typer.Option("--analyzers", help="Comma-separated analyzers to run (subset)"),
    ] = None,
    hide_safe: Annotated[
        bool,
        typer.Option("--hide-safe", help="Hide low-severity informational findings in terminal output"),
    ] = False,
    auto: Annotated[
        bool,
        typer.Option("--auto", help="Auto-resolve scan target (entrypoint or config-static)"),
    ] = False,
    auto_server: Annotated[
        str | None,
        typer.Option("--auto-server", help="Server name when --auto finds multiple MCP servers"),
    ] = None,
    machine_wide: Annotated[
        bool,
        typer.Option(
            "--machine-wide",
            help="Scan all MCP servers discovered in local client configs",
        ),
    ] = False,
    html: Annotated[
        Path | None,
        typer.Option(
            "--html",
            help=f"HTML report path (default: {ANALYSIS_DIR_NAME}/scan-report.html)",
        ),
    ] = None,
    no_save: Annotated[
        bool,
        typer.Option(
            "--no-save",
            help=f"Skip writing JSON/HTML artifacts to {ANALYSIS_DIR_NAME}/",
        ),
    ] = False,
    technique: Annotated[
        list[str] | None,
        typer.Option("--technique", help="Limit scan to MCTS-T technique id (repeatable)"),
    ] = None,
    ci: Annotated[
        bool,
        typer.Option("--ci", help="Apply CI gate preset (fail-on-critical, min-score 70)"),
    ] = False,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Governance policy YAML (default: .mcts/policy.yaml)"),
    ] = None,
) -> None:
    """Run a full security scan against an MCP server."""
    import json

    from mcts.cli.auto import AutoScanError, resolve_auto_scan
    from mcts.cli.machine_wide import run_machine_wide_cli
    from mcts.governance import evaluate_policy, load_policy
    from mcts.probe.consent import LiveProbeConsentError, live_consent_granted
    from mcts.probe.session import MCPProbeError
    from mcts.probe.startup_errors import MCPStartupError

    if machine_wide and (config or url or snapshot or auto):
        console.print(
            "[red]Error:[/red] --machine-wide cannot be combined with --config, --url, --snapshot, or --auto."
        )
        raise typer.Exit(code=2)

    if not machine_wide and target is None:
        console.print("[red]Error:[/red] TARGET is required unless --machine-wide is set.")
        raise typer.Exit(code=2)

    if target is None:
        target = Path(".")

    if (
        target == Path(".")
        and config is None
        and snapshot is None
        and not url
        and not auto
        and not machine_wide
    ):
        _print_discovery_hints(target)

    needs_live = live or bool(url)
    if needs_live and not live_consent_granted(flag=understand_live_risk):
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
    surface_list = (
        [part.strip() for part in surfaces.split(",") if part.strip()]
        if surfaces
        else ["tool", "prompt", "resource", "instruction"]
    )
    resource_mime_list = (
        [part.strip() for part in resource_mime.split(",") if part.strip()] if resource_mime else []
    )
    remote_headers = _parse_headers(header)
    tool_filters = [p.strip() for p in tool_filter.split(",") if p.strip()] if tool_filter else []
    analyzer_filters = [p.strip() for p in analyzer_filter.split(",") if p.strip()] if analyzer_filter else []
    severity_filters = [p.strip() for p in severity_filter.split(",") if p.strip()] if severity_filter else []
    analyzer_list = [p.strip() for p in analyzers.split(",") if p.strip()] if analyzers else []
    technique_filters: list[str] = []
    if technique:
        from mcts.taxonomy.technique_mode import resolve_technique_scan

        for item in technique:
            allowed, normalized = resolve_technique_scan(item)
            technique_filters.append(normalized)
            if allowed and not analyzer_list:
                analyzer_list.extend(allowed)

    if ci:
        fail_on_critical = True
        if min_score is None:
            min_score = 70

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
    if output_format not in ("json", "sarif", "raw"):
        console.print(f"[red]Error:[/red] Unknown format {format!r}. Use json, sarif, or raw.")
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
        terminal_format=terminal_format,
        fail_on_critical=fail_on_critical,
        min_score=min_score,
        max_critical=max_critical,
        fail_on_category=category_gates,
        theme=resolved_theme.name.value,
        no_progress=no_progress,
        live=needs_live,
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
        behavioral_probe=behavioral_probe or needs_live,
        surfaces=surface_list,
        resource_mime_allowlist=resource_mime_list,
        remote_url=url,
        remote_transport=transport,
        bearer_token=bearer_token,
        remote_headers=remote_headers,
        protocol_probe=protocol_probe,
        stderr_file=stderr_file,
        strict_live=strict_live,
        expand_vars=expand_vars,
        snapshot_path=snapshot,
        pip_audit=pip_audit,
        npm_audit=npm_audit,
        enable_yara=enable_yara,
        enable_llm_judge=enable_llm,
        enable_llm_triage=enable_llm_triage,
        enable_semgrep=enable_semgrep,
        semgrep_rules_path=semgrep_rules,
        enable_cloud_inspect=enable_cloud,
        enable_virustotal=enable_virustotal,
        tool_filter=tool_filters,
        analyzer_filter=analyzer_filters,
        severity_filter=severity_filters,
        analyzers=analyzer_list,
        hide_safe=hide_safe,
        auto=auto,
        auto_server=auto_server,
        auto_html=html,
        technique_filter=technique_filters,
        governance_policy=policy,
        ci_preset=ci,
    )

    if machine_wide:
        try:
            resolved_theme = get_theme(theme)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        renderer = ReportRenderer(resolved_theme, console=console)
        code = run_machine_wide_cli(
            config_obj,
            output=output,
            no_save=no_save,
            console=console,
            renderer=renderer,
        )
        raise typer.Exit(code=code)

    if auto:
        try:
            config_obj = resolve_auto_scan(target, config_obj, auto_server=auto_server)
        except AutoScanError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            if exc.multiple_servers:
                console.print("  Available servers:")
                for name in exc.multiple_servers:
                    console.print(f"    • {name}")
                console.print("  Pass --auto-server NAME to pick one.")
            raise typer.Exit(code=2) from exc
        resolved = config_obj.target
        if config_obj.config_path and config_obj.config_server:
            console.print(
                f"[dim]Auto resolved to config-static scan: "
                f"{config_obj.config_path} (server={config_obj.config_server})[/dim]"
            )
        else:
            console.print(f"[dim]Auto resolved to: {resolved}[/dim]")
    display_target = (
        config_obj.config_path if (config_obj.config_path and target == Path(".")) else config_obj.target
    )
    scanner = Scanner(config_obj)
    command_label = f"mcts scan {display_target}"
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
    except (LiveProbeConsentError, MCPStartupError, MCPProbeError, ValueError) as exc:
        if isinstance(exc, MCPStartupError):
            _print_startup_error(exc)
        else:
            console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    duration = time.perf_counter() - started

    if not no_progress:
        console.print()

    if terminal_format:
        from mcts.ui.alternate_formats import render_report

        try:
            render_report(
                report,
                terminal_format,
                console,
                tool_filter=set(tool_filters) if tool_filters else None,
                analyzer_filter=set(analyzer_filters) if analyzer_filters else None,
                severity_filter=set(severity_filters) if severity_filters else None,
                hide_safe=hide_safe,
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=2) from exc
    else:
        renderer.render(
            report,
            command=command_label,
            duration_seconds=duration,
            analyzers_run=scanner.analyzers_run_count(),
        )

    if not no_save:
        json_path, html_path, sarif_path = persist_scan_artifacts(
            report,
            json_path=resolve_output_path(output if output_format == "json" else None, "scan-report.json"),
            html_path=resolve_output_path(html, "scan-report.html"),
            sarif_path=resolve_output_path(output if output_format == "sarif" else None, "scan-report.sarif"),
        )
        if output_format == "raw":
            raw_path = resolve_output_path(output, "scan-report.raw.json")
            _write_report(report, raw_path, "raw", target=str(display_target), remote_url=url)
            renderer.render_saved_notice(str(raw_path))
        renderer.render_saved_notice(str(json_path))
        renderer.render_saved_notice(str(html_path))
        renderer.render_saved_notice(str(sarif_path))
        console.print(f"[dim]  mcts report {json_path}[/dim]  [dim](or open {html_path})[/dim]")

    _print_discovery_warnings(report.server, stderr_file)
    _check_strict_live(report, config_obj)
    _check_gates(report, config_obj)
    try:
        gov = load_policy(config_obj.governance_policy)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    if gov is not None:
        violations = evaluate_policy(
            policy=gov,
            score=report.score.overall,
            critical=report.summary.critical,
            high=report.summary.high,
            servers=[str(display_target)],
        )
        if violations:
            console.print("[red]Governance policy violations:[/red]")
            for item in violations:
                console.print(f"  • {item}")
            raise typer.Exit(code=1)


@app.command()
def inventory(
    scan: Annotated[
        bool,
        typer.Option("--scan", help="Static-scan each discovered server entrypoint for tools"),
    ] = False,
    skills: Annotated[
        bool,
        typer.Option("--skills", help="Discover and scan SKILL.md files in agent skill directories"),
    ] = False,
    scan_all: Annotated[
        bool,
        typer.Option("--scan-all", help="Run full security scan on each discovered MCP server"),
    ] = False,
    full_toxic_flows: Annotated[
        bool,
        typer.Option("--full-toxic-flows", help="Enable W015–W020 toxic flow analysis across servers"),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write inventory JSON report"),
    ] = None,
    theme: Annotated[
        str,
        typer.Option("--theme", help="Terminal theme: cyber, minimal, github"),
    ] = ThemeName.CYBER.value,
) -> None:
    """Discover MCP servers configured across 12+ agent clients."""
    from mcts.analyzers.cross_server import CrossServerAnalyzer
    from mcts.analyzers.skill_md import analyze_skills
    from mcts.analyzers.toxic_flows import analyze_inventory as analyze_toxic_flows
    from mcts.core.config import ScanConfig
    from mcts.inventory.runner import enrich_with_tool_names, run_inventory
    from mcts.inventory.scan_all import (
        default_output_path,
        run_inventory_scan_all,
        write_inventory_scan_all,
    )
    from mcts.taxonomy.mapper import enrich_findings

    try:
        resolved_theme = get_theme(theme)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if scan_all:
        inventory_report, scan_rows = run_inventory_scan_all(ScanConfig(target=Path(".")))
        console.print(
            f"[bold]Inventory scan-all[/bold] — {len(scan_rows)} server(s), "
            f"{inventory_report.config_files_found} config file(s)"
        )
        for row in scan_rows:
            label = f"[{row['client']}] {row['server_name']}"
            if row.get("score") is not None:
                console.print(f"  {label} — score {row['score']}/100, {row.get('findings', 0)} finding(s)")
            else:
                console.print(f"  {label} — [dim]{row.get('error', 'skipped')}[/dim]")
        output_path = default_output_path(output)
        write_inventory_scan_all(output_path, inventory_report, scan_rows)
        ReportRenderer(resolved_theme, console=console).render_saved_notice(str(output_path))
        if any((row.get("findings") or 0) > 0 for row in scan_rows):
            raise typer.Exit(code=1)
        return

    report = run_inventory(skills=skills)
    entries = enrich_with_tool_names(report.entries) if scan else report.entries

    shadow_findings = enrich_findings(CrossServerAnalyzer(entries).analyze_inventory(entries))
    skill_findings = enrich_findings(analyze_skills(report.skills)) if skills else []
    toxic_findings: list = []
    if full_toxic_flows or len(entries) >= 2:
        toxic_findings = enrich_findings(analyze_toxic_flows(entries))

    console.print(f"[bold]MCP inventory[/bold] — {report.config_files_found} config file(s)")
    for client in report.clients_scanned:
        console.print(f"  • {client}")
    for entry in entries:
        tools = f" ({len(entry.tools)} tools)" if entry.tools else ""
        console.print(f"  [{entry.client}] {entry.server_name}{tools} — {entry.config_path}")

    if skills:
        console.print(f"\n[bold]Skills[/bold] — {len(report.skills)} SKILL.md file(s)")
        for skill in report.skills:
            console.print(f"  [{skill.client}] {skill.skill_name} — {skill.skill_path}")
        if skill_findings:
            console.print(f"\n[yellow]Skill findings:[/yellow] {len(skill_findings)} issue(s)")
            for finding in skill_findings[:5]:
                console.print(f"  • {finding.title}")

    if toxic_findings:
        console.print(f"\n[yellow]Toxic flows:[/yellow] {len(toxic_findings)} finding(s)")
        for finding in toxic_findings[:5]:
            console.print(f"  • {finding.title}")

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
    if skills:
        payload["skills"] = [skill.model_dump() for skill in report.skills]
        payload["skill_findings"] = [f.model_dump() for f in skill_findings]
    if toxic_findings:
        payload["toxic_flow_findings"] = [f.model_dump() for f in toxic_findings]
    import json

    output_path = resolve_output_path(output, "inventory.json")
    output_path.write_text(json.dumps(payload, indent=2))
    ReportRenderer(resolved_theme, console=console).render_saved_notice(str(output_path))

    combined = shadow_findings + skill_findings + toxic_findings
    if combined and any(f.severity.value in ("critical", "high") for f in combined):
        raise typer.Exit(code=1)


@app.command()
def vet(
    package: Annotated[
        str,
        typer.Argument(help="Package spec: pypi:name, npm:pkg, or oci:registry/repo:tag"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write vet report JSON"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON to stdout"),
    ] = False,
) -> None:
    """Pre-install vetting for PyPI, npm, and OCI package references."""
    import json

    from mcts.reporting.models import Severity
    from mcts.vet import run_vet

    try:
        report = run_vet(package)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    payload = report.model_dump(mode="json")
    if json_output:
        console.print(json.dumps(payload, indent=2))
    else:
        console.print(f"[bold]mcts vet[/bold] {package}")
        console.print(f"Verdict: [bold]{report.verdict}[/bold]  Risk: {report.risk_score}/100")
        if report.findings:
            for finding in report.findings:
                console.print(f"  [{finding.severity.value}] {finding.title}")
        else:
            console.print("  No issues flagged by heuristics.")

    output_path = resolve_output_path(output, "vet-report.json")
    output_path.write_text(json.dumps(payload, indent=2))
    if not json_output:
        console.print(f"[green]Saved[/green] {output_path}")

    if any(f.severity in {Severity.CRITICAL, Severity.HIGH} for f in report.findings):
        raise typer.Exit(code=1)


@app.command()
def report(
    input_file: Annotated[
        Path,
        typer.Argument(help="JSON report from a previous scan"),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=f"HTML report path (default: {ANALYSIS_DIR_NAME}/report.html)",
        ),
    ] = None,
    theme: Annotated[
        str,
        typer.Option("--theme", help="Terminal theme: cyber, minimal, github"),
    ] = ThemeName.CYBER.value,
) -> None:
    """Generate an HTML security report from scan results."""
    from pydantic import ValidationError

    from mcts.reporting.models import ScanReport

    try:
        resolved_theme = get_theme(theme)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if input_file.is_dir():
        console.print("[red]Error:[/red] mcts report expects a JSON file from a prior scan, not a directory.")
        console.print(f"\n  mcts scan ./server.py   # writes {ANALYSIS_DIR_NAME}/scan-report.json")
        console.print(f"  mcts report {ANALYSIS_DIR_NAME}/scan-report.json")
        raise typer.Exit(code=2)

    if not input_file.exists():
        resolved = resolve_report_input_path(input_file)
        if resolved.is_file() and resolved != input_file.resolve():
            console.print(
                f"[dim]Resolved {input_file} → {resolved}[/dim] "
                f"(relative paths are saved under {ANALYSIS_DIR_NAME}/)"
            )
            input_file = resolved
        else:
            hint = analysis_path(input_file.name)
            console.print(f"[red]Error:[/red] File not found: {input_file}")
            if hint.is_file():
                console.print(f"[dim]Try:[/dim] mcts report {hint}")
            elif analysis_path("scan-report.json").is_file():
                console.print(f"[dim]Try:[/dim] mcts report {analysis_path('scan-report.json')}")
            raise typer.Exit(code=2)

    if input_file.suffix.lower() not in {".json"}:
        console.print("[yellow]Warning:[/yellow] Expected a .json scan report.")

    raw = input_file.read_text(encoding="utf-8")
    if raw.lstrip().startswith("<"):
        console.print(
            "[red]Error:[/red] Input looks like HTML. Pass the JSON scan report from "
            f"mcts scan ({ANALYSIS_DIR_NAME}/scan-report.json)"
        )
        raise typer.Exit(code=2)

    try:
        data = ScanReport.model_validate_json(raw)
    except ValidationError:
        console.print(
            "[red]Error:[/red] Invalid scan report JSON. Run mcts scan first "
            f"({ANALYSIS_DIR_NAME}/scan-report.json)."
        )
        raise typer.Exit(code=2) from None

    output_path = resolve_output_path(output, "report.html")
    _, html_path, sarif_path = persist_scan_artifacts(
        data,
        html_path=output_path,
        write_json=False,
        record_history=False,
    )
    renderer = ReportRenderer(resolved_theme, console=console)
    renderer.render_saved_notice(str(html_path))
    renderer.render_saved_notice(str(sarif_path))


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
        str | None,
        typer.Option("--command", help="Command to launch the MCP server"),
    ] = None,
    args: Annotated[
        str | None,
        typer.Option("--args", help="Comma-separated args for --command"),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="MCP client config JSON"),
    ] = None,
    server: Annotated[
        str | None,
        typer.Option("--server", help="Server name inside --config mcpServers"),
    ] = None,
    output: Annotated[
        Path | None,
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
    from mcts.probe.startup_errors import MCPStartupError
    from mcts.taxonomy.mapper import enrich_findings

    if target == Path(".") and config is None:
        _print_discovery_hints(target)

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
    except MCPStartupError as exc:
        _print_startup_error(exc)
        raise typer.Exit(code=2) from exc
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
    output_path = resolve_output_path(output, "fuzz-report.json")
    output_path.write_text(json.dumps(payload, indent=2))
    ReportRenderer(resolved_theme, console=console).render_saved_notice(str(output_path))

    if any(f.severity.value in ("critical", "high") for f in findings):
        raise typer.Exit(code=1)


def _parse_headers(header: list[str] | None) -> dict[str, str]:
    rows: dict[str, str] = {}
    for item in header or []:
        if ":" not in item:
            continue
        name, value = item.split(":", 1)
        rows[name.strip()] = value.strip()
    return rows


@app.command()
def readiness(
    target: Annotated[Path, typer.Argument(help="MCP server path or repo")],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    enable_opa: Annotated[
        bool,
        typer.Option("--opa", help="Enable optional OPA Rego policy checks"),
    ] = False,
    enable_llm: Annotated[
        bool,
        typer.Option("--llm-judge", help="Enable opt-in LLM readiness review"),
    ] = False,
) -> None:
    """Run production readiness checks (separate from security score)."""
    import json

    from mcts.readiness.runner import run_readiness

    config = ScanConfig(target=target, readiness_opa=enable_opa, readiness_llm=enable_llm)
    report = run_readiness(config)
    console.print(
        f"[bold]Readiness[/bold] — score {report.readiness_score}/100, "
        f"{report.tools_checked} tool(s), {len(report.findings)} note(s)"
    )
    for finding in report.findings[:20]:
        console.print(f"  [{finding.severity.value}] {finding.title}")
    output_path = resolve_output_path(output, "readiness-report.json")
    output_path.write_text(
        json.dumps(
            {
                "target": report.target,
                "tools_checked": report.tools_checked,
                "readiness_score": report.readiness_score,
                "production_ready": report.production_ready,
                "findings": [f.model_dump() for f in report.findings],
            },
            indent=2,
        )
    )
    console.print(f"[green]Saved[/green] {output_path}")


@app.command(name="serve")
def serve_api(
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8080,
    reload: Annotated[bool, typer.Option("--reload")] = False,
) -> None:
    """Start the MCTS REST API server."""
    try:
        import uvicorn
    except ImportError as exc:
        console.print("[red]REST API requires optional api extra: uv sync --extra api[/red]")
        raise typer.Exit(code=2) from exc
    from mcts.api.app import app as api_app

    uvicorn.run(api_app, host=host, port=port, reload=reload)


def _surface_scan(
    target: Path,
    surfaces: list[str],
    snapshot: Path | None = None,
    *,
    artifact_name: str,
) -> None:
    """Run a scan limited to specific MCP surfaces."""
    config = ScanConfig(
        target=target,
        surfaces=surfaces,
        snapshot_path=snapshot,
    )
    report = Scanner(config).run()
    console.print(f"[bold]MCTS[/bold] — {len(report.findings)} finding(s) on surfaces: {', '.join(surfaces)}")
    for finding in report.findings[:15]:
        console.print(f"  [{finding.severity.value}] {finding.title}")

    json_path, html_path, sarif_path = persist_scan_artifacts(
        report,
        json_path=resolve_output_path(None, artifact_name),
    )
    console.print(f"[green]Saved[/green] {json_path}, {html_path}, {sarif_path}")


@app.command("scan-prompts")
def scan_prompts(
    target: Annotated[Path, typer.Argument(help="MCP server path or repo")],
    snapshot: Annotated[
        Path | None,
        typer.Option("--snapshot", help="Static JSON snapshot with prompts"),
    ] = None,
) -> None:
    """Scan prompts and server instructions only."""
    _surface_scan(target, ["prompt", "instruction"], snapshot, artifact_name="scan-prompts-report.json")


@app.command("scan-resources")
def scan_resources(
    target: Annotated[Path, typer.Argument(help="MCP server path or repo")],
    snapshot: Annotated[
        Path | None,
        typer.Option("--snapshot", help="Static JSON snapshot with resources"),
    ] = None,
    resource_mime: Annotated[
        str | None,
        typer.Option("--resource-mime", help="Comma-separated MIME allowlist"),
    ] = None,
) -> None:
    """Scan MCP resources only."""
    mime_list = [p.strip() for p in resource_mime.split(",") if p.strip()] if resource_mime else []
    config = ScanConfig(
        target=target,
        surfaces=["resource"],
        snapshot_path=snapshot,
        resource_mime_allowlist=mime_list,
    )
    report = Scanner(config).run()
    console.print(f"[bold]MCTS[/bold] — {len(report.findings)} resource finding(s)")
    for finding in report.findings[:15]:
        console.print(f"  [{finding.severity.value}] {finding.title}")

    json_path, html_path, sarif_path = persist_scan_artifacts(
        report,
        json_path=resolve_output_path(None, "scan-resources-report.json"),
    )
    console.print(f"[green]Saved[/green] {json_path}, {html_path}, {sarif_path}")


@app.command("scan-instructions")
def scan_instructions(
    target: Annotated[Path, typer.Argument(help="MCP server path or repo")],
    snapshot: Annotated[
        Path | None,
        typer.Option("--snapshot", help="Static JSON snapshot with instructions"),
    ] = None,
) -> None:
    """Scan server instructions only."""
    _surface_scan(target, ["instruction"], snapshot, artifact_name="scan-instructions-report.json")


@app.command()
def doctor(
    path: Annotated[
        Path,
        typer.Argument(help="Project directory to check (default: .)"),
    ] = Path("."),
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Run optional import dry-run checks for config servers"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON"),
    ] = False,
) -> None:
    """Preflight checks before your first scan (no live probes)."""
    from mcts.cli.doctor import run_doctor

    code = run_doctor(path, deep=deep, json_output=json_output)
    if code:
        raise typer.Exit(code=code)


@app.command()
def snapshot(
    target: Annotated[
        Path,
        typer.Argument(help="Path to MCP server entrypoint or repo (use . with --config)"),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=f"Write snapshot JSON (default: {ANALYSIS_DIR_NAME}/snapshot.json)",
        ),
    ] = None,
    command: Annotated[
        str | None,
        typer.Option("--command", help="Command to launch the MCP server"),
    ] = None,
    args: Annotated[
        str | None,
        typer.Option("--args", help="Comma-separated args for --command"),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="MCP client config JSON"),
    ] = None,
    server: Annotated[
        str | None,
        typer.Option("--server", help="Server name inside --config mcpServers"),
    ] = None,
    understand_live_risk: Annotated[
        bool,
        typer.Option(
            "--i-understand-live-risk",
            help="Consent to connect to a live MCP server",
        ),
    ] = False,
    stderr_file: Annotated[
        str | None,
        typer.Option("--stderr-file", help="Capture live server stderr to file"),
    ] = None,
    expand_vars: Annotated[
        str,
        typer.Option("--expand-vars", help="Env expansion: auto, linux, mac, windows, off"),
    ] = "auto",
) -> None:
    """Export live tools/list metadata to JSON for offline mcts scan --snapshot."""
    import json

    from mcts.probe.consent import live_consent_granted
    from mcts.probe.startup_errors import MCPStartupError
    from mcts.snapshot.export import export_snapshot

    if not live_consent_granted(flag=understand_live_risk):
        console.print(
            "[red]Snapshot export requires live consent.[/red] Pass --i-understand-live-risk "
            "or set MCTS_LIVE_OK=1 in CI."
        )
        raise typer.Exit(code=2)

    if config and not server:
        console.print("[red]Error:[/red] --config requires --server.")
        raise typer.Exit(code=2)

    scan_target = config if (config and target == Path(".")) else target
    live_args = [part.strip() for part in args.split(",") if part.strip()] if args else []
    snap_config = ScanConfig(
        target=scan_target,
        live=True,
        live_command=command,
        live_args=live_args,
        config_path=config,
        config_server=server,
        live_consent=understand_live_risk,
        stderr_file=stderr_file,
        expand_vars=expand_vars,
    )
    try:
        payload = export_snapshot(snap_config)
    except MCPStartupError as exc:
        _print_startup_error(exc)
        raise typer.Exit(code=2) from exc
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    output_path = resolve_output_path(output, "snapshot.json")
    output_path.write_text(json.dumps(payload, indent=2))
    console.print(
        f"[green]✓[/green] Snapshot written to [bold]{output_path}[/bold] "
        f"({len(payload.get('tools', []))} tools)"
    )
    console.print(
        f"[dim]Scan offline: mcts scan {target} --snapshot {output_path}[/dim] "
        f"[dim](writes {ANALYSIS_DIR_NAME}/scan-report.json)[/dim]"
    )


@app.command("scan-mcp")
def scan_mcp(
    url: Annotated[str, typer.Argument(help="Remote MCP server URL")],
    transport: Annotated[
        str,
        typer.Option("--transport", help="Remote transport: streamable-http or sse"),
    ] = "streamable-http",
    bearer_token: Annotated[
        str | None,
        typer.Option("--bearer-token", help="Bearer token for remote MCP server"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write manifest probe JSON"),
    ] = None,
    understand_live_risk: Annotated[
        bool,
        typer.Option("--i-understand-live-risk", help="Consent to live remote probing"),
    ] = False,
) -> None:
    """Pre-connect remote MCP manifest probe (tools/list metadata)."""
    import json

    from mcts.probe.consent import live_consent_granted
    from mcts.probe.manifest import probe_remote_manifest

    if not live_consent_granted(flag=understand_live_risk):
        console.print(
            "[red]Remote manifest probe requires consent.[/red] Pass --i-understand-live-risk "
            "or set MCTS_LIVE_OK=1 in CI."
        )
        raise typer.Exit(code=2)

    config = ScanConfig(
        target=Path("."),
        remote_url=url,
        remote_transport=transport,
        bearer_token=bearer_token,
        live=True,
        live_consent=True,
    )
    try:
        result = probe_remote_manifest(config)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    payload = {
        "url": result.url,
        "transport": result.transport,
        "tool_count": result.tool_count,
        "prompt_count": result.prompt_count,
        "resource_count": result.resource_count,
        "tools": [tool.model_dump() for tool in result.server.tools],
    }
    output_path = resolve_output_path(output, "scan-mcp-manifest.json")
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print(
        f"[bold]scan-mcp[/bold] {url} — {result.tool_count} tools, "
        f"{result.prompt_count} prompts, {result.resource_count} resources"
    )
    console.print(f"[green]Saved[/green] {output_path}")


@app.command()
def pentest(
    target: Annotated[
        Path,
        typer.Argument(help="Path to MCP server entrypoint or repository"),
    ],
    live: Annotated[
        bool,
        typer.Option("--live", help="Include safe protocol fuzz after static recon"),
    ] = False,
    understand_live_risk: Annotated[
        bool,
        typer.Option(
            "--i-understand-live-risk",
            help="Consent to live MCP probing for protocol fuzz phase",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write pentest report JSON"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON to stdout"),
    ] = False,
    no_progress: Annotated[
        bool,
        typer.Option("--no-progress", help="Skip progress animation"),
    ] = False,
) -> None:
    """Run structured MCP red-team phases (static recon, attack chains, optional fuzz)."""
    import json

    from mcts.pentest import run_pentest
    from mcts.probe.consent import live_consent_granted
    from mcts.probe.session import MCPProbeError
    from mcts.probe.startup_errors import MCPStartupError
    from mcts.ui.progress import run_with_progress

    if live and not live_consent_granted(flag=understand_live_risk):
        console.print(
            "[red]Live pentest requires consent.[/red] Pass --i-understand-live-risk "
            "or set MCTS_LIVE_OK=1 in CI."
        )
        raise typer.Exit(code=2)

    config = ScanConfig(
        target=target,
        live=live,
        live_consent=understand_live_risk,
        no_progress=no_progress,
    )

    def _execute() -> object:
        return run_pentest(config, run_fuzz=live)

    try:
        report = run_with_progress(
            _execute,
            theme=get_theme("cyber"),
            console=console,
            enabled=not no_progress,
        )
    except (MCPStartupError, MCPProbeError, ValueError) as exc:
        if isinstance(exc, MCPStartupError):
            _print_startup_error(exc)
        else:
            console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    payload = report.model_dump(mode="json")
    output_path = resolve_output_path(output, "pentest-report.json")
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if json_output:
        console.print(json.dumps(payload, indent=2))
    else:
        console.print(f"[bold]mcts pentest[/bold] {target}")
        console.print(f"Verdict: [bold]{report.verdict}[/bold]  Score: {report.score}/100")
        for phase in report.phases:
            detail = f" ({phase.findings} finding(s))" if phase.findings else ""
            console.print(f"  • {phase.name}: {phase.status}{detail}")
        if report.recommendations:
            console.print("\n[bold]Recommendations[/bold]")
            for item in report.recommendations[:5]:
                console.print(f"  • {item}")
        console.print(f"\n[green]Saved[/green] {output_path}")

    if report.verdict in {"critical", "high"}:
        raise typer.Exit(code=1)


def run() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    run()
