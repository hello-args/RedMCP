"""OAuth authorization phishing detection (MCTS-T-1011)."""

from __future__ import annotations

from urllib.parse import urlparse

TRUSTED_OAUTH_SUFFIXES: tuple[str, ...] = (
    ".google.com",
    ".amazonaws.com",
    ".microsoft.com",
    ".github.com",
    "accounts.google.com",
    "login.microsoftonline.com",
    "github.com",
)

SUSPICIOUS_REDIRECT_PATHS: tuple[str, ...] = (
    "/oauth/callback",
    "/auth/return",
    "/oauth2/callback",
)


def detect_oauth_phishing_config(config: dict) -> bool:
    """Detect suspicious OAuth redirect/provider configuration (MCTS-T-1011)."""
    redirect = _first_str(
        config,
        ("oauth_redirect_uri", "redirect_uri", "redirectUri", "callback_url"),
    )
    if redirect and _is_suspicious_redirect(redirect):
        return True

    auth_url = _first_str(
        config,
        ("authorization_endpoint", "authorizationEndpoint", "authorization_url", "auth_url"),
    )
    if auth_url and _is_typosquat_auth_url(auth_url):
        return True

    providers = config.get("oauth_providers") or config.get("providers")
    return bool(isinstance(providers, list) and len(providers) > 2)


def _first_str(config: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = config.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _is_suspicious_redirect(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if not host:
        return False
    if not any(marker in path for marker in SUSPICIOUS_REDIRECT_PATHS):
        return False
    if any(host.endswith(suffix) or host == suffix.lstrip(".") for suffix in TRUSTED_OAUTH_SUFFIXES):
        return False
    if any(marker in host for marker in ("evil", "phish", "attacker", "fake", "malicious")):
        return True
    if host in {"localhost", "127.0.0.1"}:
        return False
    return not _host_is_trusted(host)


def _is_typosquat_auth_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    typos = ("accounts-google", "gogle.com", "microsft.com", "guthub.com", "evil-oauth")
    return any(marker in host for marker in typos)


def _host_is_trusted(host: str) -> bool:
    return any(host == suffix.lstrip(".") or host.endswith(suffix) for suffix in TRUSTED_OAUTH_SUFFIXES)
