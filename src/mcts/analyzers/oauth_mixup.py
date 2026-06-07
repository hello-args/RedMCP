"""OAuth Authorization Server mix-up detection (MCTS-T-1012)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from mcts.analyzers.oauth_config import LEGITIMATE_OAUTH_HOSTS, TYPOSQUAT_MARKERS

_ISSUER_MISMATCH = re.compile(r"failed|mismatch", re.I)


def detect_oauth_mixup_event(event: dict[str, Any]) -> bool:
    """Detect MCTS-T-1012 indicators in OAuth telemetry events."""
    payload = event.get("event", event)
    oauth = payload.get("oauth") if isinstance(payload.get("oauth"), dict) else {}

    if oauth.get("issuer_validation") and _ISSUER_MISMATCH.search(str(oauth["issuer_validation"])):
        return True

    expected = oauth.get("expected_issuer")
    issuer = oauth.get("iss")
    if expected and issuer and expected.rstrip("/") != str(issuer).rstrip("/"):
        return True

    action = str(payload.get("action", ""))
    if action == "oauth.authorization.response.received" and oauth.get("provider_name") and not issuer:
        return True

    for key in ("authorization_endpoint", "token_endpoint", "new_value", "old_value"):
        url = oauth.get(key)
        if isinstance(url, str) and _suspicious_oauth_url(url):
            return True

    tls = payload.get("tls") if isinstance(payload.get("tls"), dict) else {}
    cert_domain = str((tls.get("server") or {}).get("domain", ""))
    if cert_domain:
        if _suspicious_oauth_url(f"https://{cert_domain}"):
            return True
        if any(marker in cert_domain.lower() for marker in ("accounts-google", "googie", "-google")):
            return True

    return bool(oauth.get("configuration_count", 0) > 1 and oauth.get("as_domain_first_seen"))


def _suspicious_oauth_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if "xn--" in host or re.search(r"[\u0400-\u04FF\u03bf]", host):
        return True
    lowered = url.lower()
    if any(marker in lowered for marker in TYPOSQUAT_MARKERS) and not any(
        legit in lowered for legit in LEGITIMATE_OAUTH_HOSTS
    ):
        return True
    if any(
        marker in lowered
        for marker in ("signin-aws", "accounts-google", "accounts-goog", "login-microsoft", "guthub.com")
    ):
        return True
    brands = ("google", "github", "microsoft", "amazon", "apple")
    return (
        host.endswith((".co", ".net"))
        and not host.endswith(".co.uk")
        and any(brand in host for brand in brands)
    )
