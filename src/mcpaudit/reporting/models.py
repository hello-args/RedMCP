"""Report data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from mcpaudit.mcp.models import MCPServerInfo


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange3",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
        }[self]


class Finding(BaseModel):
    id: str
    analyzer: str
    title: str
    description: str
    severity: Severity
    recommendation: str
    tool: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ScanSummary:
        counts = {s: 0 for s in Severity}
        for finding in findings:
            counts[finding.severity] += 1
        return cls(
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            total=len(findings),
        )


class RiskScore(BaseModel):
    overall: int = Field(ge=0, le=100)
    penalty: int = Field(ge=0)


class ScanReport(BaseModel):
    version: str
    target: str
    scanned_at: datetime
    server: MCPServerInfo
    findings: list[Finding]
    summary: ScanSummary
    score: RiskScore
