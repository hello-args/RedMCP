"""Node.js dependency CVE scanning via npm audit."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity


class NpmAuditAnalyzer(BaseAnalyzer):
    """Run npm audit --json when package-lock.json exists."""

    name = "npm_audit"

    def __init__(self, target: Path) -> None:
        self.target = target

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        del server
        if not shutil.which("npm"):
            return []
        root = self.target if self.target.is_dir() else self.target.parent
        if not (root / "package-lock.json").exists() and not (root / "package.json").exists():
            return []
        try:
            proc = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if not proc.stdout.strip():
            return []
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []
        return _findings_from_audit(payload, root)


def _findings_from_audit(payload: dict, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    advisories = payload.get("vulnerabilities") or payload.get("advisories") or {}
    if not isinstance(advisories, dict):
        return findings
    for name, meta in advisories.items():
        if not isinstance(meta, dict):
            continue
        severity = _map_severity(str(meta.get("severity") or "moderate"))
        via = meta.get("via")
        title = name
        if isinstance(via, list) and via:
            first = via[0]
            if isinstance(first, dict):
                title = str(first.get("title") or name)
        findings.append(
            Finding(
                id=f"npm-audit-{name}",
                analyzer="npm_audit",
                title=f"Vulnerable npm package: {title}",
                description=str(meta.get("range") or meta.get("severity") or name),
                severity=severity,
                recommendation=f"Run npm audit fix in {root}.",
                technique_id="MCTS-T-1014",
                confidence=0.9,
                evidence={"package": name, "severity": meta.get("severity")},
            )
        )
    return findings


def _map_severity(raw: str) -> Severity:
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
    }.get(raw.lower(), Severity.MEDIUM)
