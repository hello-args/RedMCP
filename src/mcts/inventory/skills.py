"""Discover agent skill directories and SKILL.md files."""

from __future__ import annotations

from pathlib import Path

from mcts.inventory.client_registry import SKILL_DIR_CANDIDATES
from mcts.inventory.models import SkillEntry


def discover_skills(*, project_root: Path | None = None) -> list[SkillEntry]:
    """Return SKILL.md files from well-known agent skill directories."""
    seen: set[Path] = set()
    entries: list[SkillEntry] = []

    for client, candidates in SKILL_DIR_CANDIDATES.items():
        for raw in candidates:
            root = Path(raw).expanduser()
            if raw.startswith("."):
                if project_root is None:
                    continue
                root = (project_root / raw).resolve()
            if not root.is_dir():
                continue
            for skill_md in sorted(root.rglob("SKILL.md")):
                if not skill_md.is_file():
                    continue
                resolved = skill_md.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                entries.append(_entry_from_path(client, resolved))

    return entries


def _entry_from_path(client: str, path: Path) -> SkillEntry:
    skill_name = path.parent.name
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        content = ""
    return SkillEntry(
        client=client,
        skill_name=skill_name,
        skill_path=str(path),
        content_length=len(content),
        content=content,
    )
