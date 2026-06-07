"""Supply chain checks for MCP server repositories."""

from __future__ import annotations

import json
import re
from pathlib import Path

from mcts.analyzers.base import BaseAnalyzer
from mcts.core.config import DEFAULT_EXCLUDE_DIRS
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation

UNPINNED_PATTERN = re.compile(r"(\^|~|\*|latest|>=|<=|>|<)", re.I)
SUSPICIOUS_NPM_SCRIPT = re.compile(r"(postinstall|preinstall|prepare)", re.I)
DOCKER_FROM = re.compile(r"^\s*FROM\s+(\S+)", re.I | re.M)
NPM_EXEC = re.compile(r"\b(npx|npm)\s+(install|-g|exec)\b", re.I)


class SupplyChainAnalyzer(BaseAnalyzer):
    """Scan repo manifests and MCP launch commands for supply-chain risk."""

    name = "supply_chain"

    def __init__(self, target: Path) -> None:
        self.target = target

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        del server
        if not self.target.exists():
            return []

        root = self.target if self.target.is_dir() else self.target.parent
        findings: list[Finding] = []
        findings.extend(self._scan_package_json(root))
        findings.extend(self._scan_pyproject(root))
        findings.extend(self._scan_requirements(root))
        findings.extend(self._scan_dockerfile(root))
        return findings

    def _scan_package_json(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in _find_files(root, "package.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue

            for section in ("dependencies", "devDependencies"):
                deps = data.get(section) or {}
                if not isinstance(deps, dict):
                    continue
                for name, spec in deps.items():
                    if isinstance(spec, str) and UNPINNED_PATTERN.search(spec):
                        findings.append(
                            _finding(
                                path,
                                f"supply-unpinned-npm-{name}",
                                f"Unpinned npm dependency: {name}",
                                f"{section}.{name} uses floating version spec {spec!r}",
                                Severity.MEDIUM,
                                "MCTS-T-1014",
                            )
                        )

            scripts = data.get("scripts") or {}
            if isinstance(scripts, dict):
                for script_name, body in scripts.items():
                    if SUSPICIOUS_NPM_SCRIPT.search(script_name) and isinstance(body, str):
                        findings.append(
                            _finding(
                                path,
                                f"supply-npm-script-{script_name}",
                                f"Suspicious npm lifecycle script: {script_name}",
                                "Lifecycle scripts can execute code on install.",
                                Severity.HIGH,
                                "MCTS-T-1015",
                                evidence={"script": body[:200]},
                            )
                        )
        return findings

    def _scan_pyproject(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in _find_files(root, "pyproject.toml"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            for line_no, line in enumerate(text.splitlines(), start=1):
                if UNPINNED_PATTERN.search(line) and any(
                    token in line for token in ('"', "dependencies", "requires")
                ):
                    findings.append(
                        _finding(
                            path,
                            f"supply-unpinned-py-{line_no}",
                            "Unpinned Python dependency",
                            line.strip(),
                            Severity.MEDIUM,
                            "MCTS-T-1014",
                            line=line_no,
                        )
                    )
        return findings

    def _scan_requirements(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for filename in ("requirements.txt", "requirements-dev.txt"):
            for path in _find_files(root, filename):
                text = path.read_text(encoding="utf-8", errors="ignore")
                for line_no, line in enumerate(text.splitlines(), start=1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if UNPINNED_PATTERN.search(stripped) or "==" not in stripped:
                        findings.append(
                            _finding(
                                path,
                                f"supply-unpinned-req-{line_no}",
                                "Unpinned requirements entry",
                                stripped,
                                Severity.MEDIUM,
                                "MCTS-T-1014",
                                line=line_no,
                            )
                        )
        return findings

    def _scan_dockerfile(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in list(_find_files(root, "Dockerfile")) + list(root.glob("**/Dockerfile*"))[:10]:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for match in DOCKER_FROM.finditer(text):
                image = match.group(1)
                if "@sha256:" not in image and (":latest" in image.lower() or ":" not in image):
                    findings.append(
                        _finding(
                            path,
                            f"supply-docker-{hash(image) & 0xFFFF}",
                            "Docker base image not digest-pinned",
                            f"FROM {image}",
                            Severity.HIGH,
                            "MCTS-T-1015",
                        )
                    )
        return findings


def _find_files(root: Path, name: str) -> list[Path]:
    results: list[Path] = []
    if root.is_file() and root.name == name:
        return [root]
    for path in root.rglob(name):
        if any(part in DEFAULT_EXCLUDE_DIRS for part in path.parts):
            continue
        results.append(path)
    return results[:20]


def _finding(
    path: Path,
    finding_id: str,
    title: str,
    description: str,
    severity: Severity,
    technique_scenario: str,
    *,
    line: int | None = None,
    evidence: dict[str, str] | None = None,
) -> Finding:
    technique = "MCTS-T-1014" if technique_scenario == "MCTS-T-1014" else "MCTS-T-1015"
    return Finding(
        id=finding_id,
        analyzer="supply_chain",
        title=title,
        description=description,
        severity=severity,
        recommendation=(
            "Pin dependencies with exact versions or digests; "
            "verify package provenance (MCTS-M-008, MCTS-M-018)."
        ),
        technique_id=technique,
        confidence=0.75,
        location=SourceLocation(file=str(path), line=line),
        evidence=evidence or {},
    )
