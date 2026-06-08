"""Behavioral SAST evaluation corpus runner."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding
from mcts.sast.extract_tool import extract_first_tool

_DEFAULT_CORPUS = Path(__file__).resolve().parents[3] / "eval" / "behavioral" / "cases.json"


@dataclass
class EvalCase:
    id: str
    language: str
    description: str
    handler: str
    source_file: str | None
    expect_taint: bool
    expect_mismatch: bool
    expect_clean: bool
    expect_detection: bool


@dataclass
class EvalResult:
    case_id: str
    passed: bool
    findings: list[str]
    reason: str


@dataclass
class EvalReport:
    total: int
    passed: int
    failed: int
    recall: float
    results: list[EvalResult]


def load_corpus(path: Path | None = None) -> list[EvalCase]:
    corpus_path = path or _DEFAULT_CORPUS
    corpus_dir = corpus_path.parent
    payload = json.loads(corpus_path.read_text(encoding="utf-8"))
    rows: list[EvalCase] = []
    for row in payload.get("cases", []):
        source_file = row.get("source_file")
        if source_file and not Path(source_file).is_absolute():
            source_file = str(corpus_dir / source_file)
        rows.append(
            EvalCase(
                id=str(row["id"]),
                language=str(row.get("language", "python")),
                description=str(row.get("description", "")),
                handler=str(row.get("handler", "")),
                source_file=source_file,
                expect_taint=bool(row.get("expect_taint", False)),
                expect_mismatch=bool(row.get("expect_mismatch", False)),
                expect_clean=bool(row.get("expect_clean", False)),
                expect_detection=bool(row.get("expect_detection", False)),
            )
        )
    return rows


def run_behavioral_eval(corpus_path: Path | None = None) -> EvalReport:
    cases = load_corpus(corpus_path)
    results: list[EvalResult] = []
    for case in cases:
        results.append(_evaluate_case(case))
    passed = sum(1 for row in results if row.passed)
    malicious = [c for c in cases if c.expect_taint or c.expect_mismatch or c.expect_detection]
    detected = sum(
        1
        for case, result in zip(cases, results, strict=True)
        if (case.expect_taint or case.expect_mismatch or case.expect_detection) and result.passed
    )
    recall = (detected / len(malicious)) if malicious else 1.0
    return EvalReport(
        total=len(cases),
        passed=passed,
        failed=len(cases) - passed,
        recall=recall,
        results=results,
    )


def _evaluate_case(case: EvalCase) -> EvalResult:
    tool = _build_tool(case)
    findings = BehavioralStaticAnalyzer().analyze(MCPServerInfo(tools=[tool]))
    has_taint = _has_prefix(findings, "behavioral-taint")
    has_mismatch = _has_prefix(findings, "behavioral-mismatch")
    has_any = bool(findings)

    if case.expect_clean and has_any:
        return EvalResult(case.id, False, _titles(findings), "expected clean handler")
    if case.expect_detection and not has_any:
        return EvalResult(case.id, False, _titles(findings), "expected behavioral detection")
    if case.expect_taint and not has_taint:
        return EvalResult(case.id, False, _titles(findings), "expected taint finding")
    if case.expect_mismatch and not has_mismatch:
        return EvalResult(case.id, False, _titles(findings), "expected mismatch finding")
    if (
        not case.expect_clean
        and not case.expect_taint
        and not case.expect_mismatch
        and not case.expect_detection
        and has_any
    ):
        return EvalResult(case.id, False, _titles(findings), "unexpected findings")
    return EvalResult(case.id, True, _titles(findings), "ok")


def _build_tool(case: EvalCase) -> MCPTool:
    if case.source_file and not case.handler:
        try:
            source = Path(case.source_file).read_text(encoding="utf-8")
        except OSError:
            source = ""
        extracted = extract_first_tool(source)
        if extracted:
            return MCPTool(
                name=extracted.name,
                description=extracted.description or case.description,
                handler_snippet=extracted.handler_snippet,
                source_file=case.source_file,
                source_line=extracted.source_line,
            )
    return MCPTool(
        name=case.id,
        description=case.description,
        handler_snippet=case.handler,
        source_file=case.source_file,
    )


def _has_prefix(findings: list[Finding], prefix: str) -> bool:
    return any(f.id.startswith(prefix) for f in findings)


def _titles(findings: list[Finding]) -> list[str]:
    return [f.title for f in findings]
