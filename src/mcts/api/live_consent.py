"""Live MCP probing consent checks for REST API requests."""

from __future__ import annotations

from fastapi import HTTPException, Request

from mcts.probe.consent import CONSENT_MESSAGE, live_consent_granted

LIVE_CONSENT_HEADER = "X-MCTS-Live-Consent"


def api_live_consent_granted(*, understand_live_risk: bool, request: Request | None) -> bool:
    """Mirror CLI consent: body flag, consent header, or server MCTS_LIVE_OK env."""
    header_ok = False
    if request is not None:
        header_value = request.headers.get(LIVE_CONSENT_HEADER, "").strip().lower()
        header_ok = header_value in {"1", "true", "yes"}
    return live_consent_granted(flag=understand_live_risk or header_ok)


def require_api_live_consent(
    *,
    live: bool,
    remote_url: str | None,
    understand_live_risk: bool,
    request: Request | None,
) -> None:
    """Reject live/remote scans unless explicit consent was granted."""
    if not live and not remote_url:
        return
    if api_live_consent_granted(understand_live_risk=understand_live_risk, request=request):
        return
    raise HTTPException(status_code=403, detail=CONSENT_MESSAGE.strip())
