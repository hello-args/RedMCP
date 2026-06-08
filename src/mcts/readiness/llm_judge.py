"""Optional LLM semantic readiness checks (opt-in)."""

from __future__ import annotations

import json
import os
from typing import Any

from mcts.reporting.models import Finding, Severity

_PROMPT = (
    "Review this MCP tool definition for production readiness. "
    'Reply JSON only: {"issues": [{"id": "actionable_errors|failure_modes|scope_clarity", '
    '"severity": "low|medium|high", "summary": "..."}]}\n\n'
    "Evaluate: actionable error handling, documented failure modes, focused scope.\n\n"
    "Tool JSON:\n"
)


class ReadinessLlmJudge:
    """Semantic readiness review via LiteLLM (requires MCTS_LLM_API_KEY)."""

    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.environ.get("MCTS_LLM_MODEL", "gpt-4o-mini")

    def is_available(self) -> bool:
        if not os.environ.get("MCTS_LLM_API_KEY"):
            return False
        try:
            import litellm  # noqa: F401
        except ImportError:
            return False
        return True

    def analyze_tool(self, tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
        if not self.is_available():
            return []
        import litellm

        try:
            resp = litellm.completion(
                model=self.model,
                messages=[{"role": "user", "content": _PROMPT + json.dumps(tool_def)[:6000]}],
                timeout=30,
                api_key=os.environ.get("MCTS_LLM_API_KEY"),
            )
            content = resp.choices[0].message.content or "{}"
            payload = json.loads(content)
        except (json.JSONDecodeError, KeyError, IndexError, Exception):
            return []

        findings: list[Finding] = []
        for issue in payload.get("issues", []):
            if not isinstance(issue, dict):
                continue
            issue_id = str(issue.get("id", "readiness_llm"))
            severity = _map_severity(str(issue.get("severity", "medium")))
            findings.append(
                Finding(
                    id=f"readiness-llm-{issue_id}-{tool_name}",
                    analyzer="readiness",
                    title=f"LLM readiness: {issue.get('summary', issue_id)} ({tool_name})",
                    description=str(issue.get("summary", "LLM readiness concern")),
                    severity=severity,
                    tool=tool_name,
                    recommendation="Improve tool operational documentation per LLM readiness review.",
                    technique_id=None,
                    confidence=0.65,
                    evidence={"readiness_rule": f"LLM-{issue_id}", "source": "llm_judge"},
                )
            )
        return findings


def _map_severity(raw: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(raw.lower(), Severity.MEDIUM)
