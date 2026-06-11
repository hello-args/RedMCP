"""mcts doctor — preflight checks before first scan."""

from __future__ import annotations

import importlib.util as importlib_util
import os
import shutil
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from mcts import __version__
from mcts.discovery.config import (
    ConfigDiscoveryError,
    load_server_from_config,
    load_servers_dict,
    resolve_interpreter,
)
from mcts.discovery.onboarding import find_entrypoint_candidates, find_mcp_configs, format_discovery_hints

console = Console()

_OPTIONAL_EXTRA_CHECKS = (
    ("[mcp] extra", "mcp", "mcp-mcts[mcp]"),
    ("[api] extra", "fastapi", "mcp-mcts[api]"),
)
_OPTIONAL_CLI_CHECKS = (
    ("semgrep CLI", "semgrep"),
    ("pip-audit CLI", "pip-audit"),
    ("opa CLI", "opa"),
)


def run_doctor(
    path: Path,
    *,
    deep: bool = False,
    json_output: bool = False,
    output: Path | None = None,
) -> int:
    """Run read-only preflight checks. Returns exit code (0 ok, 1 failures, 2 user error)."""
    root = path.expanduser().resolve()
    if not root.exists():
        console.print(f"[red]Error:[/red] Path not found: {root}")
        return 2

    checks: list[tuple[str, str, str]] = []  # status, label, detail
    failures = 0
    warnings = 0

    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):  # noqa: UP036 — report for environments below requires-python
        checks.append(("pass", "Python", py_version))
    else:
        checks.append(("fail", "Python", f"{py_version} (requires >=3.11)"))
        failures += 1

    checks.append(("pass", "mcts", __version__))

    if root.is_dir():
        checks.append(("pass", "Target", str(root)))
    else:
        checks.append(("pass", "Target file", str(root)))

    configs = find_mcp_configs(root) if root.is_dir() else []
    if configs:
        for cfg in configs:
            try:
                servers = sorted(load_servers_dict(cfg))
            except ConfigDiscoveryError:
                servers = []
            rel = _rel(cfg, root)
            checks.append(("pass", "MCP config", f"{rel} ({len(servers)} server(s))"))
            for server_name in servers[:6]:
                _check_server_config(cfg, server_name, checks)
    elif root.is_dir():
        checks.append(("warn", "MCP config", "none found"))
        warnings += 1

    candidates = find_entrypoint_candidates(root) if root.is_dir() else []
    if candidates:
        rel = _rel(candidates[0], root)
        checks.append(("pass", "Entrypoint candidate", rel))
    elif root.is_dir():
        checks.append(("warn", "Entrypoint candidate", "none found"))
        warnings += 1

    if deep:
        if not configs:
            checks.append(("warn", "Deep checks", "skipped — no MCP config found"))
            warnings += 1
        else:
            for cfg in configs[:1]:
                try:
                    server_names = sorted(load_servers_dict(cfg))[:2]
                except ConfigDiscoveryError:
                    server_names = []
                if not server_names:
                    checks.append(("warn", "Deep checks", "skipped — no servers in config"))
                    warnings += 1
                    continue
                for server_name in server_names:
                    _deep_import_check(cfg, server_name, checks)

    if deep:
        warnings += _check_optional_toolchain(checks)

    payload = {
        "path": str(root),
        "checks": [{"status": s, "label": label, "detail": d} for s, label, d in checks],
        "failures": failures,
        "warnings": warnings,
    }

    if json_output or output is not None:
        import json

        from mcts.output.analysis_dir import resolve_output_path

        output_path = resolve_output_path(output, "doctor-report.json")
        text = json.dumps(payload, indent=2)
        output_path.write_text(text, encoding="utf-8")
        if json_output:
            console.print_json(text)
        console.print(f"[green]Saved[/green] {output_path}")

    if not json_output:
        console.print(f"[bold]mcts doctor[/bold] {path}\n")
        for status, label, detail in checks:
            icon = {"pass": "[green]✓[/green]", "warn": "[yellow]⚠[/yellow]", "fail": "[red]✗[/red]"}[status]
            console.print(f"{icon} {escape(label)}: {escape(detail)}")
        if root.is_dir():
            hints = format_discovery_hints(root)
            if hints:
                console.print("\n[dim]Suggested commands:[/dim]")
                for line in hints.splitlines():
                    console.print(f"  {line}")

    if failures:
        return 1
    return 0


def _check_server_config(config_path: Path, server_name: str, checks: list[tuple[str, str, str]]) -> None:
    try:
        entry = load_servers_dict(config_path)[server_name]
        command = str(entry.get("command") or "")
        config_dir = config_path.resolve().parent
        resolved, warn = resolve_interpreter(command, config_dir)
        if warn:
            checks.append(("warn", f"Server {server_name}", warn))
        venv_candidate = config_dir / ".venv" / "bin" / "python"
        if venv_candidate.exists():
            checks.append(("pass", "  .venv python", str(venv_candidate.name)))
        elif command in ("python", "python3"):
            checks.append(("warn", "  interpreter", f"bare {command!r}; .venv not found at {venv_candidate}"))
        _ = resolved
        _ = load_server_from_config(config_path, server_name)
    except ConfigDiscoveryError as exc:
        checks.append(("fail", f"Server {server_name}", str(exc)))


def _deep_import_check(config_path: Path, server_name: str, checks: list[tuple[str, str, str]]) -> None:
    import subprocess

    try:
        live = load_server_from_config(config_path, server_name)
    except ConfigDiscoveryError:
        return
    module = None
    for idx, arg in enumerate(live.args):
        if arg == "-m" and idx + 1 < len(live.args):
            module = live.args[idx + 1].split(":")[0]
            break
    if not module:
        checks.append(
            (
                "warn",
                "Deep checks",
                f"skipped for {server_name!r} — no -m module in launch args",
            )
        )
        return
    cwd = Path(live.cwd or ".")
    result = subprocess.run(
        [live.command, "-c", f"import {module}"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()
        line = tail[-1] if tail else "import failed"
        checks.append(("warn", f"Import {module}", line[:120]))


def _check_optional_toolchain(checks: list[tuple[str, str, str]]) -> int:
    warnings = 0
    for label, module, extra in _OPTIONAL_EXTRA_CHECKS:
        if importlib_util.find_spec(module):
            checks.append(("pass", label, f"module {module!r} importable"))
        else:
            checks.append(("warn", label, f"module {module!r} not found; install {extra} to enable"))
            warnings += 1

    for label, executable in _OPTIONAL_CLI_CHECKS:
        found = shutil.which(executable)
        if found:
            checks.append(("pass", label, f"found at {found}"))
        else:
            checks.append(("warn", label, "not found on PATH"))
            warnings += 1

    if os.environ.get("MCTS_LLM_API_KEY"):
        checks.append(("pass", "MCTS_LLM_API_KEY", "set"))
    else:
        checks.append(("warn", "MCTS_LLM_API_KEY", "not set"))
        warnings += 1
    return warnings


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)
