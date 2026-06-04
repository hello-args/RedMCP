"""Scan configuration."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    """Configuration for a MCPAudit security scan."""

    target: Path
    output: Path | None = None
    fail_on_critical: bool = False
    enable_jailbreak: bool = True
    enable_attack_chains: bool = True
    timeout_seconds: int = Field(default=120, ge=1)
    theme: str = "cyber"
    no_progress: bool = False
