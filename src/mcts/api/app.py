"""FastAPI REST server for MCTS scanning."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

from mcts.api import limits
from mcts.api.auth import require_api_key
from mcts.api.limits import (
    RequestLimitsMiddleware,
    cap_fanout,
    run_scan_with_limits,
)
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.client import MCPClient
from mcts.mcp.models import MCPServerInfo
from mcts.readiness.runner import run_readiness
from mcts.reporting.models import ScanReport

app = FastAPI(title="MCTS API", version="0.1.0")
app.add_middleware(RequestLimitsMiddleware)
_auth = [Depends(require_api_key)]


class ScanRequest(BaseModel):
    target: str = "."
    live: bool = False
    url: str | None = None
    transport: str = "streamable-http"
    bearer_token: str | None = None
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = None
    oauth_token_url: str | None = None
    oauth_scopes: str | None = None
    surfaces: list[str] = Field(default_factory=lambda: ["tool", "prompt", "resource", "instruction"])
    resource_mime_allowlist: list[str] = Field(default_factory=list)
    pip_audit: bool = False
    protocol_probe: bool = False
    hide_safe: bool = False
    tool_filter: list[str] = Field(default_factory=list)
    analyzer_filter: list[str] = Field(default_factory=list)
    severity_filter: list[str] = Field(default_factory=list)
    analyzers: list[str] = Field(default_factory=list)
    technique_filter: list[str] = Field(default_factory=list)
    semantic_secrets: bool = False
    runtime_events: list[dict[str, Any]] = Field(default_factory=list)
    fail_on_critical: bool = False
    min_score: int | None = Field(default=None, ge=0, le=100)

    @field_validator("runtime_events")
    @classmethod
    def _limit_runtime_events(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        limit = limits.max_runtime_events()
        if len(value) > limit:
            raise ValueError(f"runtime_events exceeds maximum length of {limit}")
        return value


class ToolScanRequest(ScanRequest):
    tool_name: str


class PromptScanRequest(ScanRequest):
    prompt_name: str


class ResourceScanRequest(ScanRequest):
    resource_uri: str
    resource_mime_allowlist: list[str] = Field(default_factory=lambda: ["text/plain", "text/html"])


class ReadinessRequest(BaseModel):
    target: str = "."
    url: str | None = None
    live: bool = False
    enable_opa: bool = False


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _build_config(req: ScanRequest, *, live_consent: bool | None = None) -> ScanConfig:
    return ScanConfig(
        target=Path(req.target),
        live=req.live or bool(req.url),
        remote_url=req.url,
        remote_transport=req.transport,
        bearer_token=req.bearer_token,
        surfaces=req.surfaces,
        resource_mime_allowlist=req.resource_mime_allowlist,
        pip_audit=req.pip_audit,
        protocol_probe=req.protocol_probe,
        live_consent=live_consent if live_consent is not None else (req.live or bool(req.url)),
        hide_safe=req.hide_safe,
        tool_filter=req.tool_filter,
        analyzer_filter=req.analyzer_filter,
        severity_filter=req.severity_filter,
        analyzers=req.analyzers,
        technique_filter=req.technique_filter,
        semantic_secrets=req.semantic_secrets,
        runtime_events=req.runtime_events,
        fail_on_critical=req.fail_on_critical,
        min_score=req.min_score,
        oauth_client_id=req.oauth_client_id,
        oauth_client_secret=req.oauth_client_secret,
        oauth_token_url=req.oauth_token_url,
        oauth_scopes=req.oauth_scopes,
    )


def _discover(req: ScanRequest) -> MCPServerInfo:
    config = _build_config(req)
    try:
        return MCPClient(config.target, config).discover()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _scan_server(req: ScanRequest, server: MCPServerInfo) -> dict[str, Any]:
    config = _build_config(req)
    try:
        report: ScanReport = Scanner(config).analyze_server(server)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return report.model_dump()


async def _discover_async(req: ScanRequest) -> MCPServerInfo:
    return await run_scan_with_limits(lambda: _discover(req))


async def _scan_server_async(req: ScanRequest, server: MCPServerInfo) -> dict[str, Any]:
    return await run_scan_with_limits(lambda: _scan_server(req, server))


def _filter_server(
    server: MCPServerInfo,
    *,
    tool_name: str | None = None,
    prompt_name: str | None = None,
    resource_uri: str | None = None,
    instructions_only: bool = False,
) -> MCPServerInfo:
    if tool_name:
        tools = [tool for tool in server.tools if tool.name == tool_name]
        if not tools:
            raise HTTPException(status_code=404, detail=f"Tool not found: {tool_name}")
        return server.model_copy(
            update={"tools": tools, "prompts": [], "resources": [], "instructions": None}
        )
    if prompt_name:
        prompts = [prompt for prompt in server.prompts if prompt.name == prompt_name]
        if not prompts:
            raise HTTPException(status_code=404, detail=f"Prompt not found: {prompt_name}")
        return server.model_copy(
            update={"tools": [], "prompts": prompts, "resources": [], "instructions": None}
        )
    if resource_uri:
        resources = [resource for resource in server.resources if resource.uri == resource_uri]
        if not resources:
            raise HTTPException(status_code=404, detail=f"Resource not found: {resource_uri}")
        return server.model_copy(
            update={"tools": [], "prompts": [], "resources": resources, "instructions": None}
        )
    if instructions_only:
        if not server.instructions:
            raise HTTPException(status_code=404, detail="Server instructions not available")
        return server.model_copy(update={"tools": [], "prompts": [], "resources": []})
    return server


@app.post("/scan", dependencies=_auth)
async def scan_all(req: ScanRequest) -> dict[str, Any]:
    server = await _discover_async(req)
    return await _scan_server_async(req, server)


@app.post("/scan-tool", dependencies=_auth)
async def scan_tool(req: ToolScanRequest) -> dict[str, Any]:
    server = _filter_server(await _discover_async(req), tool_name=req.tool_name)
    return await _scan_server_async(req, server)


@app.post("/scan-all-tools", dependencies=_auth)
async def scan_all_tools(req: ScanRequest) -> dict[str, Any]:
    server = await _discover_async(req)
    tools = cap_fanout(server.tools, label="tools")
    reports = []
    for tool in tools:
        filtered = _filter_server(server, tool_name=tool.name)
        reports.append(await _scan_server_async(req, filtered))
    return {
        "server_url": req.url or req.target,
        "tool_count": len(tools),
        "reports": reports,
    }


@app.post("/scan-prompt", dependencies=_auth)
async def scan_prompt(req: PromptScanRequest) -> dict[str, Any]:
    server = _filter_server(await _discover_async(req), prompt_name=req.prompt_name)
    payload = await _scan_server_async(req, server)
    return {
        "server_url": req.url or req.target,
        "prompt_name": req.prompt_name,
        "report": payload,
    }


@app.post("/scan-all-prompts", dependencies=_auth)
async def scan_all_prompts(req: ScanRequest) -> dict[str, Any]:
    server = await _discover_async(req)
    prompts = cap_fanout(server.prompts, label="prompts")
    reports = [
        await _scan_server_async(req, _filter_server(server, prompt_name=prompt.name))
        for prompt in prompts
    ]
    return {
        "server_url": req.url or req.target,
        "total_prompts": len(prompts),
        "reports": reports,
    }


@app.post("/scan-resource", dependencies=_auth)
async def scan_resource(req: ResourceScanRequest) -> dict[str, Any]:
    server = _filter_server(await _discover_async(req), resource_uri=req.resource_uri)
    payload = await _scan_server_async(req, server)
    return {
        "server_url": req.url or req.target,
        "resource_uri": req.resource_uri,
        "report": payload,
    }


@app.post("/scan-all-resources", dependencies=_auth)
async def scan_all_resources(req: ScanRequest) -> dict[str, Any]:
    server = await _discover_async(req)
    resources = cap_fanout(server.resources, label="resources")
    reports = [
        await _scan_server_async(req, _filter_server(server, resource_uri=resource.uri))
        for resource in resources
    ]
    return {
        "server_url": req.url or req.target,
        "total_resources": len(resources),
        "reports": reports,
    }


@app.post("/scan-instructions", dependencies=_auth)
async def scan_instructions(req: ScanRequest) -> dict[str, Any]:
    server = _filter_server(await _discover_async(req), instructions_only=True)
    payload = await _scan_server_async(req, server)
    return {
        "server_url": req.url or req.target,
        "instructions": server.instructions,
        "report": payload,
    }


@app.post("/readiness", dependencies=_auth)
async def readiness(req: ReadinessRequest) -> dict[str, Any]:
    config = ScanConfig(
        target=Path(req.target),
        live=req.live or bool(req.url),
        remote_url=req.url,
        live_consent=req.live or bool(req.url),
        readiness_opa=req.enable_opa,
    )

    def _run() -> dict[str, Any]:
        try:
            report = run_readiness(config)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "target": report.target,
            "tools_checked": report.tools_checked,
            "readiness_score": report.readiness_score,
            "production_ready": report.production_ready,
            "findings": [finding.model_dump() for finding in report.findings],
        }

    return await run_scan_with_limits(_run)


def create_app() -> FastAPI:
    return app
