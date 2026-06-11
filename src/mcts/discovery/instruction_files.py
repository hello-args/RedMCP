"""Discover agent instruction and prompt content from markdown files in a repo."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.target import ScanTarget, TargetKind
from mcts.mcp.models import AgentSkillFile, MCPPrompt, MCPServerInfo

MARKDOWN_SUFFIXES = frozenset({".md", ".markdown", ".mdx"})

DEFAULT_INSTRUCTION_GLOBS: tuple[str, ...] = (
    "**/SKILL.md",
    "**/*prompt*.md",
    "**/system_prompt.md",
    "**/instructions.md",
    "**/INSTRUCTIONS.md",
)

DEFAULT_INSTRUCTION_SKIP_PREFIXES: tuple[str, ...] = (
    "docs/prompts/",
    "doc/prompts/",
    "design/",
)

DEFAULT_SKILLS_DIR_NAMES: tuple[str, ...] = (
    "skills",
    "agent/skills",
    ".agents/skills",
)

INSTRUCTION_BASENAMES = frozenset(
    {
        "system_prompt.md",
        "instructions.md",
        "instructions.markdown",
    }
)


def discover_instruction_surfaces(config: ScanConfig) -> MCPServerInfo:
    """Walk the scan target for markdown prompts, instructions, and SKILL.md files."""
    if not _should_discover(config):
        return _empty_info(config)

    target = ScanTarget(config.target)
    paths = _collect_paths(config, target)
    if not paths:
        return _empty_info(config)

    prompts: list[MCPPrompt] = []
    agent_skills: list[AgentSkillFile] = []
    instruction_blocks: list[tuple[str, str]] = []
    source_files: dict[str, str] = {}

    for path in sorted(paths, key=lambda p: str(p).lower()):
        text = _read_markdown(config, path)
        if not text.strip():
            continue
        source_files[str(path.resolve())] = text
        classification = _classify_path(path)
        if classification == "skill":
            skill_name = path.parent.name
            agent_skills.append(
                AgentSkillFile(
                    name=skill_name,
                    path=str(path.resolve()),
                    content=text,
                    origin="repo",
                )
            )
            prompts.append(
                MCPPrompt(
                    name=skill_name,
                    description=text,
                    source_file=str(path.resolve()),
                    source_line=1,
                    discovered_via="skill-md",
                )
            )
        elif classification == "system":
            instruction_blocks.append((str(path.resolve()), text))
            prompts.append(
                MCPPrompt(
                    name=path.stem,
                    description=text,
                    source_file=str(path.resolve()),
                    source_line=1,
                    discovered_via="instruction-file",
                )
            )
        else:
            prompts.append(
                MCPPrompt(
                    name=path.stem,
                    description=text,
                    source_file=str(path.resolve()),
                    source_line=1,
                    discovered_via="instruction-file",
                )
            )

    instructions: str | None = None
    instruction_sources: list[str] = []
    if instruction_blocks:
        instruction_sources = [path for path, _ in instruction_blocks]
        instructions = "\n\n---\n\n".join(text for _, text in instruction_blocks)

    name = target.path.name if target.kind == TargetKind.DIRECTORY else target.path.stem
    return MCPServerInfo(
        name=name,
        prompts=prompts,
        instructions=instructions,
        instruction_sources=instruction_sources,
        agent_skills=agent_skills,
        transport="static",
        discovery_mode="instruction-files",
        source_files=source_files,
    )


def _should_discover(config: ScanConfig) -> bool:
    if config.instruction_files or config.skills_dirs:
        return True
    if not config.discover_instructions:
        return False
    if config.snapshot_path or any(
        [
            config.snapshot_tools,
            config.snapshot_prompts,
            config.snapshot_resources,
            config.snapshot_instructions,
        ]
    ):
        return False
    return not (config.live or config.remote_url)


def _empty_info(config: ScanConfig) -> MCPServerInfo:
    target = ScanTarget(config.target)
    name = target.path.name if target.path.exists() and target.path.is_dir() else target.path.stem
    return MCPServerInfo(name=name, discovery_mode="empty")


def _collect_paths(config: ScanConfig, target: ScanTarget) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        resolved = path.resolve()
        if resolved in seen or not path.is_file():
            return
        if path.suffix.lower() not in MARKDOWN_SUFFIXES:
            return
        seen.add(resolved)
        paths.append(path)

    for raw in config.instruction_files:
        add(Path(raw).expanduser())

    for raw in config.skills_dirs:
        root = Path(raw).expanduser()
        if root.is_file() and root.name == "SKILL.md":
            add(root)
        elif root.is_dir():
            for skill_md in sorted(root.rglob("SKILL.md")):
                if _path_allowed(config, skill_md, target):
                    add(skill_md)

    if target.kind == TargetKind.FILE:
        if target.path.suffix.lower() in MARKDOWN_SUFFIXES:
            add(target.path)
        return paths

    if not target.path.is_dir():
        return paths

    if _is_skills_directory(target.path):
        for skill_md in sorted(target.path.rglob("SKILL.md")):
            if _path_allowed(config, skill_md, target):
                add(skill_md)
        return paths

    globs = config.instruction_globs or list(DEFAULT_INSTRUCTION_GLOBS)
    for pattern in globs:
        for match in target.path.glob(pattern):
            if match.is_file() and _path_allowed(config, match, target):
                add(match)

    for rel in DEFAULT_SKILLS_DIR_NAMES:
        skills_root = target.path / rel
        if skills_root.is_dir():
            for skill_md in sorted(skills_root.rglob("SKILL.md")):
                if _path_allowed(config, skill_md, target):
                    add(skill_md)

    return paths


def _is_skills_directory(path: Path) -> bool:
    if path.name.lower() == "skills":
        return True
    return any(path.glob("*/SKILL.md"))


def _path_allowed(config: ScanConfig, path: Path, target: ScanTarget) -> bool:
    try:
        rel = path.relative_to(target.path if target.kind == TargetKind.DIRECTORY else path.parent)
        rel_str = str(rel)
    except ValueError:
        rel_str = str(path)

    if any(part in config.exclude_dirs for part in path.parts):
        return False
    rel_normalized = rel_str.replace("\\", "/").lower()
    if any(rel_normalized.startswith(prefix) for prefix in DEFAULT_INSTRUCTION_SKIP_PREFIXES):
        return False
    return not (config.exclude_globs and any(fnmatch(rel_str, g) for g in config.exclude_globs))


def _read_markdown(config: ScanConfig, path: Path) -> str:
    try:
        if path.stat().st_size > config.max_file_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _classify_path(path: Path) -> str:
    name_lower = path.name.lower()
    if name_lower == "skill.md":
        return "skill"
    if name_lower in INSTRUCTION_BASENAMES or "system_prompt" in name_lower:
        return "system"
    if "prompt" in name_lower:
        return "prompt"
    return "prompt"
