"""MCP artifact surface abstraction for multi-surface scanning."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from mcts.mcp.models import MCPServerInfo


class ScanSurfaceKind(StrEnum):
    TOOL = "tool"
    PROMPT = "prompt"
    RESOURCE = "resource"
    INSTRUCTION = "instruction"


DEFAULT_SURFACES: frozenset[ScanSurfaceKind] = frozenset(ScanSurfaceKind)


@dataclass(frozen=True)
class ScanSurface:
    """A scannable MCP artifact with normalized text fields."""

    kind: ScanSurfaceKind
    name: str
    description: str
    extra_text: str = ""
    uri: str | None = None
    mime_type: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    discovered_via: str = "static"

    @property
    def label(self) -> str:
        return f"{self.kind.value}:{self.name}"

    def all_text(self) -> str:
        parts = [self.name, self.description]
        if self.extra_text:
            parts.append(self.extra_text)
        if self.uri:
            parts.append(self.uri)
        return "\n".join(p for p in parts if p)

    def is_intentional_context_file(self) -> bool:
        """Return True for repo markdown meant to be loaded as agent context.

        Prompt templates and SKILL.md files are usually long and imperative by
        design. Keep hard scanners for secrets/exfil/shell/Unicode, but suppress
        generic length/imperative-language heuristics for these context files.
        """
        if self.kind not in {ScanSurfaceKind.PROMPT, ScanSurfaceKind.INSTRUCTION}:
            return False
        if not self.source_file:
            return self.discovered_via == "skill-md"
        path = Path(self.source_file)
        name = path.name.lower()
        if self.discovered_via == "skill-md" or name == "skill.md":
            return True
        return "prompt" in name and name.endswith((".md", ".markdown", ".mdx"))


def parse_surfaces(raw: list[str] | None) -> frozenset[ScanSurfaceKind]:
    if not raw:
        return DEFAULT_SURFACES
    mapping = {k.value: k for k in ScanSurfaceKind}
    selected: set[ScanSurfaceKind] = set()
    for item in raw:
        key = item.strip().lower()
        if key not in mapping:
            raise ValueError(f"Unknown surface {item!r}. Use: tool, prompt, resource, instruction")
        selected.add(mapping[key])
    return frozenset(selected)


def iter_surfaces(
    server: MCPServerInfo,
    surfaces: frozenset[ScanSurfaceKind] | None = None,
    mime_allowlist: frozenset[str] | None = None,
) -> list[ScanSurface]:
    """Yield scannable surfaces from server info."""
    active = surfaces or DEFAULT_SURFACES
    rows: list[ScanSurface] = []

    if ScanSurfaceKind.TOOL in active:
        for tool in server.tools:
            schema_text = str(tool.input_schema) if tool.input_schema else ""
            rows.append(
                ScanSurface(
                    kind=ScanSurfaceKind.TOOL,
                    name=tool.name,
                    description=tool.description or "",
                    extra_text=schema_text,
                    source_file=tool.source_file,
                    source_line=tool.source_line,
                    discovered_via=tool.discovered_via,
                )
            )

    if ScanSurfaceKind.PROMPT in active:
        for prompt in server.prompts:
            arg_text = " ".join(f"{a.get('name', '')} {a.get('description', '')}" for a in prompt.arguments)
            rows.append(
                ScanSurface(
                    kind=ScanSurfaceKind.PROMPT,
                    name=prompt.name,
                    description=prompt.description or "",
                    extra_text=arg_text,
                    source_file=prompt.source_file,
                    source_line=prompt.source_line,
                    discovered_via=prompt.discovered_via,
                )
            )

    if ScanSurfaceKind.RESOURCE in active:
        for resource in server.resources:
            if mime_allowlist and resource.mime_type and resource.mime_type not in mime_allowlist:
                continue
            extra = ""
            if resource.content:
                extra = resource.content
            rows.append(
                ScanSurface(
                    kind=ScanSurfaceKind.RESOURCE,
                    name=resource.name or resource.uri,
                    description=resource.description or "",
                    extra_text=extra,
                    uri=resource.uri,
                    mime_type=resource.mime_type,
                    discovered_via="resource",
                )
            )

    if ScanSurfaceKind.INSTRUCTION in active and server.instructions:
        source_file = server.instruction_sources[0] if server.instruction_sources else None
        rows.append(
            ScanSurface(
                kind=ScanSurfaceKind.INSTRUCTION,
                name="server-instructions",
                description=server.instructions,
                source_file=source_file,
                source_line=1,
                discovered_via="instruction-file" if source_file else "static",
            )
        )

    return rows
