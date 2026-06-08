"""Resolve live stdio launch configuration."""

from __future__ import annotations

import sys

from mcts.core.config import ScanConfig
from mcts.discovery.config import load_server_from_config
from mcts.probe.models import LiveServerConfig


def resolve_live_config(config: ScanConfig) -> LiveServerConfig:
    if config.config_path and config.config_server:
        live = load_server_from_config(
            config.config_path,
            config.config_server,
            expand_vars=config.expand_vars,
        )
        if config.stderr_file:
            live = live.model_copy(update={"stderr_file": config.stderr_file})
        return live

    if config.live_command:
        return LiveServerConfig(
            command=config.live_command,
            args=config.live_args,
            env=config.live_env,
            cwd=str(config.target) if config.target.is_dir() else None,
            server_name=config.config_server or config.target.stem,
            stderr_file=config.stderr_file,
        )

    target = config.target
    if target.is_file() and target.suffix == ".py":
        return LiveServerConfig(
            command=sys.executable,
            args=[str(target.resolve())],
            env=config.live_env,
            server_name=target.stem,
            stderr_file=config.stderr_file,
        )

    raise ValueError(
        "Live scan requires --command and --args, --url for remote, or --config with --server, "
        "or a Python file target for auto-launch"
    )
