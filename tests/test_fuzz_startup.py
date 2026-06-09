"""Tests for fuzz abort on MCP startup failure."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from mcts.core.config import ScanConfig
from mcts.fuzz.runner import FuzzRunner
from mcts.probe.errors import MCPProbeError
from mcts.probe.models import LiveServerConfig
from mcts.probe.startup_errors import MCPStartupError, StartupCategory

_LIVE = LiveServerConfig(command="python", args=["server.py"])


@pytest.mark.asyncio
async def test_fuzz_safe_aborts_on_startup_error() -> None:
    config = ScanConfig(
        target="server.py",
        live_consent=True,
        fuzz_level="safe",
    )
    startup = MCPStartupError(
        "failed",
        category=StartupCategory.IMPORT_ERROR,
        detected_line="ModuleNotFoundError: No module named 'ifd'",
        suggestion="use venv python",
        stderr_tail=[],
    )
    with (
        patch("mcts.fuzz.runner.resolve_live_config", return_value=_LIVE),
        patch("mcts.fuzz.runner.probe_stdio", new_callable=AsyncMock) as mock_probe,
    ):
        mock_probe.side_effect = startup
        with pytest.raises(MCPStartupError):
            await FuzzRunner(config).run_async()


@pytest.mark.asyncio
async def test_fuzz_aborts_on_probe_error() -> None:
    config = ScanConfig(target="server.py", live_consent=True, fuzz_level="safe")
    with (
        patch("mcts.fuzz.runner.resolve_live_config", return_value=_LIVE),
        patch("mcts.fuzz.runner.probe_stdio", new_callable=AsyncMock) as mock_probe,
    ):
        mock_probe.side_effect = MCPProbeError("connection failed")
        with pytest.raises(MCPProbeError):
            await FuzzRunner(config).run_async()
