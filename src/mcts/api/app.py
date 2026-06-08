"""FastAPI REST server for MCTS scanning."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from mcts.api.auth import require_api_key
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.client import MCPClient
from mcts.mcp.models import MCPServerInfo
from mcts.readiness.runner import run_readiness
from mcts.reporting.models import ScanReport

app = FastAPI(title="MCTS API", version="0.1.0")
_auth = [Depends(require_api_key)]


class ScanRequest(BaseModel):
    target: str = "."
    live: bool = False
    url: str | None = None
    transport: str = "streamable-http"
    bearer_token: str | None = None
    surfaces: list[str] = Field(default_factory=lambda: ["tool", "prompt", "resource", "instruction"])
    resource_mime_allowlist: list[str] = Field(default_factory=list)
    pip_audit: bool = False
    protocol_probe: bool = False
    hide_safe: bool = False
    tool_filter: list[str] = Field(default_factory=list)
    analyzer_filter: list[str] = Field(default_factory=list)


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
def scan_all(req: ScanRequest) -> dict[str, Any]:
    return _scan_server(req, _discover(req))


@app.post("/scan-tool", dependencies=_auth)
def scan_tool(req: ToolScanRequest) -> dict[str, Any]:
    server = _filter_server(_discover(req), tool_name=req.tool_name)
    return _scan_server(req, server)


@app.post("/scan-all-tools", dependencies=_auth)
def scan_all_tools(req: ScanRequest) -> dict[str, Any]:
    server = _discover(req)
    return {
        "server_url": req.url or req.target,
        "tool_count": len(server.tools),
        "reports": [_scan_server(req, _filter_server(server, tool_name=tool.name)) for tool in server.tools],
    }


@app.post("/scan-prompt", dependencies=_auth)
def scan_prompt(req: PromptScanRequest) -> dict[str, Any]:
    server = _filter_server(_discover(req), prompt_name=req.prompt_name)
    payload = _scan_server(req, server)
    return {
        "server_url": req.url or req.target,
        "prompt_name": req.prompt_name,
        "report": payload,
    }


@app.post("/scan-all-prompts", dependencies=_auth)
def scan_all_prompts(req: ScanRequest) -> dict[str, Any]:
    server = _discover(req)
    return {
        "server_url": req.url or req.target,
        "total_prompts": len(server.prompts),
        "reports": [
            _scan_server(req, _filter_server(server, prompt_name=prompt.name)) for prompt in server.prompts
        ],
    }


@app.post("/scan-resource", dependencies=_auth)
def scan_resource(req: ResourceScanRequest) -> dict[str, Any]:
    server = _filter_server(_discover(req), resource_uri=req.resource_uri)
    payload = _scan_server(req, server)
    return {
        "server_url": req.url or req.target,
        "resource_uri": req.resource_uri,
        "report": payload,
    }


@app.post("/scan-all-resources", dependencies=_auth)
def scan_all_resources(req: ScanRequest) -> dict[str, Any]:
    server = _discover(req)
    return {
        "server_url": req.url or req.target,
        "total_resources": len(server.resources),
        "reports": [
            _scan_server(req, _filter_server(server, resource_uri=resource.uri))
            for resource in server.resources
        ],
    }


@app.post("/scan-instructions", dependencies=_auth)
def scan_instructions(req: ScanRequest) -> dict[str, Any]:
    server = _filter_server(_discover(req), instructions_only=True)
    payload = _scan_server(req, server)
    return {
        "server_url": req.url or req.target,
        "instructions": server.instructions,
        "report": payload,
    }


@app.post("/readiness", dependencies=_auth)
def readiness(req: ReadinessRequest) -> dict[str, Any]:
    config = ScanConfig(
        target=Path(req.target),
        live=req.live or bool(req.url),
        remote_url=req.url,
        live_consent=req.live or bool(req.url),
        readiness_opa=req.enable_opa,
    )
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


def create_app() -> FastAPI:
    return app
