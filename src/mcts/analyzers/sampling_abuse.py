"""Sampling API abuse detection (MCTS-T-1016)."""

from __future__ import annotations

from typing import Any

SENSITIVE_FOLLOW_ON_MARKERS = (
    "credentials",
    ".aws/",
    ".ssh/",
    "id_rsa",
    "prompt_state_mutation",
    "state_mutation",
)


def detect_sampling_abuse(event: dict[str, Any]) -> bool:
    """Detect MCTS-T-1016 quota drain / unapproved nested tool abuse."""
    if event.get("method") != "sampling/createMessage":
        return False

    burst = int(event.get("burst_count", 1))
    max_tokens = int(event.get("max_tokens", 0))
    approval = str(event.get("approval_state", ""))
    follow_on = str(event.get("follow_on_action", "")).lower()

    if burst >= 5 and max_tokens >= 8000:
        return True

    if approval in {"missing", "auto_approved"} and any(
        marker in follow_on for marker in SENSITIVE_FOLLOW_ON_MARKERS
    ):
        return True

    if approval == "auto_approved" and burst >= 2 and "mutation" in follow_on:
        return True

    requested = event.get("requested_tools") or []
    return bool(
        approval == "missing"
        and requested
        and any(marker in follow_on for marker in SENSITIVE_FOLLOW_ON_MARKERS)
    )
