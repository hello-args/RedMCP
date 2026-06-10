"""Behavioral static regression runner for example MCP servers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.client import MCPClient
from mcts.scoring.engine import RiskScoringEngine

_REPO_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_TARGETS: tuple[Path, ...] = (
    _REPO_ROOT / "examples/vulnerable-mcp-server/server.py",
    _REPO_ROOT / "examples/safe-mcp-server/server.py",
    _REPO_ROOT / "examples/medium-risk-mcp-server/server.py",
)

# Mirrors tests/test_scoring.py::test_real_server_scores_in_expected_bands
DEFAULT_SCORE_BANDS: dict[str, tuple[int, int, int, int]] = {
    "examples/safe-mcp-server/server.py": (95, 100, 0, 10),
    "examples/medium-risk-mcp-server/server.py": (60, 75, 15, 30),
    "examples/vulnerable-mcp-server/server.py": (0, 5, 180, 290),
}

# Behavioral-static finding count bands for the example servers
DEFAULT_FINDING_BANDS: dict[str, tuple[int, int]] = {
    "examples/safe-mcp-server/server.py": (0, 0),
    "examples/medium-risk-mcp-server/server.py": (0, 0),
    "examples/vulnerable-mcp-server/server.py": (4, 10),
}


@dataclass(frozen=True)
class ScoreBand:
    path: Path
    min_score: int
    max_score: int
    min_raw: int | None = None
    max_raw: int | None = None


@dataclass(frozen=True)
class FindingBand:
    path: Path
    min_findings: int
    max_findings: int


@dataclass
class TargetResult:
    path: str
    exists: bool
    behavioral_findings: int = 0
    finding_titles: list[str] = field(default_factory=list)
    score_overall: int | None = None
    score_raw: int | None = None
    passed: bool = True
    failures: list[str] = field(default_factory=list)


@dataclass
class RegressionReport:
    total: int
    passed: int
    failed: int
    results: list[TargetResult]


def resolve_target(path: Path, *, repo_root: Path = _REPO_ROOT) -> Path:
    if path.is_absolute():
        return path
    candidate = Path.cwd() / path
    if candidate.exists():
        return candidate
    return repo_root / path


def parse_score_band(spec: str, *, repo_root: Path = _REPO_ROOT) -> ScoreBand:
    parts = spec.split(":")
    if len(parts) not in (3, 5):
        raise ValueError(
            f"Invalid --expect-band {spec!r}; use PATH:MIN_SCORE:MAX_SCORE or "
            "PATH:MIN_SCORE:MAX_SCORE:MIN_RAW:MAX_RAW"
        )
    path = resolve_target(Path(parts[0]), repo_root=repo_root)
    min_score, max_score = int(parts[1]), int(parts[2])
    min_raw = int(parts[3]) if len(parts) > 3 else None
    max_raw = int(parts[4]) if len(parts) > 4 else None
    return ScoreBand(path=path, min_score=min_score, max_score=max_score, min_raw=min_raw, max_raw=max_raw)


def parse_finding_band(spec: str, *, repo_root: Path = _REPO_ROOT) -> FindingBand:
    parts = spec.split(":")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid --expect-findings {spec!r}; use PATH:MIN_FINDINGS:MAX_FINDINGS"
        )
    path = resolve_target(Path(parts[0]), repo_root=repo_root)
    return FindingBand(path=path, min_findings=int(parts[1]), max_findings=int(parts[2]))


def default_score_bands(targets: list[Path]) -> list[ScoreBand]:
    bands: list[ScoreBand] = []
    for target in targets:
        key = _relative_key(target)
        if key not in DEFAULT_SCORE_BANDS:
            continue
        min_score, max_score, min_raw, max_raw = DEFAULT_SCORE_BANDS[key]
        bands.append(
            ScoreBand(
                path=target,
                min_score=min_score,
                max_score=max_score,
                min_raw=min_raw,
                max_raw=max_raw,
            )
        )
    return bands


def default_finding_bands(targets: list[Path]) -> list[FindingBand]:
    bands: list[FindingBand] = []
    for target in targets:
        key = _relative_key(target)
        if key not in DEFAULT_FINDING_BANDS:
            continue
        min_findings, max_findings = DEFAULT_FINDING_BANDS[key]
        bands.append(
            FindingBand(path=target, min_findings=min_findings, max_findings=max_findings)
        )
    return bands


def _relative_key(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(_REPO_ROOT.resolve()))
    except ValueError:
        return str(path)


def _bands_for_target(
    path: Path,
    score_bands: list[ScoreBand],
    finding_bands: list[FindingBand],
) -> tuple[ScoreBand | None, FindingBand | None]:
    resolved = path.resolve()
    score_band = next((band for band in score_bands if band.path.resolve() == resolved), None)
    finding_band = next((band for band in finding_bands if band.path.resolve() == resolved), None)
    return score_band, finding_band


def _analyze_behavioral(path: Path) -> tuple[list[str], int]:
    server = MCPClient(path, ScanConfig(target=path)).discover()
    findings = BehavioralStaticAnalyzer().analyze(server)
    titles = [f.title for f in findings]
    return titles, len(findings)


def _analyze_scores(path: Path) -> tuple[int, int]:
    report = Scanner(ScanConfig(target=path)).run()
    if not RiskScoringEngine.verify(report.findings, report.score):
        raise RuntimeError(f"Score verification failed for {path}")
    return report.score.overall, report.score.raw_risk


def run_behavioral_regression(
    targets: list[Path] | None = None,
    *,
    score_bands: list[ScoreBand] | None = None,
    finding_bands: list[FindingBand] | None = None,
    gate_defaults: bool = False,
) -> RegressionReport:
    """Run behavioral static analysis (and optional score gates) on example servers."""
    rows = list(targets or DEFAULT_TARGETS)
    resolved_targets = [resolve_target(path) for path in rows]

    score_checks = list(score_bands or [])
    finding_checks = list(finding_bands or [])
    if gate_defaults:
        score_checks.extend(default_score_bands(resolved_targets))
        finding_checks.extend(default_finding_bands(resolved_targets))

    # Deduplicate bands by path (later explicit flags win if we dedupe by keeping first)
    score_checks = _dedupe_score_bands(score_checks)
    finding_checks = _dedupe_finding_bands(finding_checks)

    results: list[TargetResult] = []
    for target in resolved_targets:
        score_band, finding_band = _bands_for_target(target, score_checks, finding_checks)
        needs_scan = score_band is not None
        result = TargetResult(path=str(target), exists=target.exists())

        if not result.exists:
            result.passed = False
            result.failures.append("target path does not exist")
            results.append(result)
            continue

        titles, count = _analyze_behavioral(target)
        result.behavioral_findings = count
        result.finding_titles = titles

        if finding_band is not None:
            if not (finding_band.min_findings <= count <= finding_band.max_findings):
                result.passed = False
                result.failures.append(
                    "behavioral findings "
                    f"{count} outside expected band "
                    f"[{finding_band.min_findings}, {finding_band.max_findings}]"
                )

        if needs_scan:
            overall, raw = _analyze_scores(target)
            result.score_overall = overall
            result.score_raw = raw
            if score_band is not None:
                if not (score_band.min_score <= overall <= score_band.max_score):
                    result.passed = False
                    result.failures.append(
                        f"security score {overall} outside expected band "
                        f"[{score_band.min_score}, {score_band.max_score}]"
                    )
                if score_band.min_raw is not None and score_band.max_raw is not None:
                    if not (score_band.min_raw <= raw <= score_band.max_raw):
                        result.passed = False
                        result.failures.append(
                            f"raw risk {raw} outside expected band "
                            f"[{score_band.min_raw}, {score_band.max_raw}]"
                        )

        results.append(result)

    passed = sum(1 for row in results if row.passed)
    failed = len(results) - passed
    return RegressionReport(total=len(results), passed=passed, failed=failed, results=results)


def _dedupe_score_bands(bands: list[ScoreBand]) -> list[ScoreBand]:
    seen: dict[Path, ScoreBand] = {}
    for band in bands:
        seen[band.path.resolve()] = band
    return list(seen.values())


def _dedupe_finding_bands(bands: list[FindingBand]) -> list[FindingBand]:
    seen: dict[Path, FindingBand] = {}
    for band in bands:
        seen[band.path.resolve()] = band
    return list(seen.values())
