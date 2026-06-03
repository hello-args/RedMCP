"""Base analyzer interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcpaudit.mcp.models import MCPServerInfo
from mcpaudit.reporting.models import Finding


class BaseAnalyzer(ABC):
    """Interface implemented by all MCPAudit security analyzers."""

    name: str = "base"

    @abstractmethod
    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        """Run analysis and return findings."""
