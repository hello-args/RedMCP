"""Live MCP discovery via stdio or remote HTTP probe."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.discovery.config import load_remote_from_config
from mcts.discovery.live_config import resolve_live_config
from mcts.mcp.models import MCPServerInfo
from mcts.probe.auth import RemoteAuth
from mcts.probe.consent import require_live_consent
from mcts.probe.http_session import probe_remote_sync, remote_config_from_scan
from mcts.probe.models import RemoteServerConfig
from mcts.probe.session import probe_stdio_sync


class LiveDiscovery:
    """Discover MCP capabilities by connecting to a live server."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def discover(self) -> MCPServerInfo:
        require_live_consent(flag=self.config.live_consent)
        if self.config.remote_url:
            remote = self._remote_config()
            return probe_remote_sync(remote, timeout_seconds=self.config.timeout_seconds)
        live_config = resolve_live_config(self.config)
        return probe_stdio_sync(live_config, timeout_seconds=self.config.timeout_seconds)

    def _remote_config(self) -> RemoteServerConfig:
        if self.config.config_path and self.config.config_server and not self.config.remote_url:
            return load_remote_from_config(
                self.config.config_path,
                self.config.config_server,
                expand_vars=self.config.expand_vars,
            )
        auth = RemoteAuth(
            bearer_token=self.config.bearer_token,
            headers=self.config.remote_headers,
            oauth_token_url=self.config.oauth_token_url,
            oauth_client_id=self.config.oauth_client_id,
            oauth_client_secret=self.config.oauth_client_secret,
            oauth_scopes=self.config.oauth_scopes,
        )
        return remote_config_from_scan(
            url=self.config.remote_url or "",
            transport=self.config.remote_transport,
            auth=auth,
            server_name=self.config.config_server or "remote-server",
        )
