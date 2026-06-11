from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from skillgate.models import ScannedFile

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
}
SCRIPT_EXTENSIONS = {".sh", ".bash", ".py", ".js", ".ts", ".mjs", ".cjs", ".ps1"}
RELEVANT_NAMES = {
    "SKILL.md",
    "AGENTS.md",
    "CLAUDE.md",
    "mcp.json",
    ".mcp.json",
    "package.json",
    "pyproject.toml",
}
REFERENCE_RE = re.compile(
    r"""(?P<path>(?:\.{1,2}/)?[A-Za-z0-9_./\\-]+\.(?:sh|bash|py|js|ts|mjs|cjs|ps1))"""
)


def normalize_path(path: Path) -> str:
    return path.as_posix()


def relative_path(root: Path, path: Path) -> str:
    return normalize_path(path.resolve().relative_to(root.resolve()))


def is_excluded(path: Path) -> bool:
    return any(part in EXCLUDED_DIRS for part in path.parts)


def is_relevant_path(rel_path: Path) -> bool:
    rel = normalize_path(rel_path)
    if rel_path.name in RELEVANT_NAMES:
        return True
    return (
        rel == ".github/copilot-instructions.md"
        or rel.startswith(".claude/skills/")
        or rel.startswith(".agents/skills/")
        or (rel.startswith("skills/") and rel_path.name == "SKILL.md")
        or rel.startswith("agents/")
        or rel.startswith(".claude/commands/")
        or rel.startswith(".gemini/commands/")
        or rel.startswith("hooks/")
    )


def classify_file(path: Path) -> str:
    name = path.name
    suffix = path.suffix.lower()
    if name in {"mcp.json", ".mcp.json"}:
        return "mcp_config"
    if name == "package.json":
        return "package_config"
    if name == "pyproject.toml":
        return "python_config"
    if suffix == ".md":
        return "markdown"
    if suffix in SCRIPT_EXTENSIONS:
        return "script"
    if suffix == ".json":
        return "json_config"
    return "agent_file"


def iter_candidate_files(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = sorted(name for name in dirnames if name not in EXCLUDED_DIRS)
        for filename in sorted(filenames):
            path = current / filename
            rel = path.relative_to(root)
            if not is_excluded(rel) and is_relevant_path(rel):
                candidates.append(path)
    return sorted(candidates, key=lambda item: relative_path(root, item))


def referenced_scripts(root: Path, source: Path, content: str) -> list[Path]:
    scripts: list[Path] = []
    for match in REFERENCE_RE.finditer(content):
        raw = match.group("path").replace("\\", "/")
        if "://" in raw or raw.startswith("/"):
            continue
        target = (source.parent / raw).resolve()
        try:
            rel = target.relative_to(root.resolve())
        except ValueError:
            continue
        if target.exists() and target.is_file() and target.suffix.lower() in SCRIPT_EXTENSIONS:
            if not is_excluded(rel):
                scripts.append(target)
    return sorted(set(scripts), key=lambda item: relative_path(root, item))


def discover_paths(root: Path) -> list[Path]:
    root = root.resolve()
    discovered = set(iter_candidate_files(root))
    changed = True
    while changed:
        changed = False
        for path in sorted(discovered, key=lambda item: relative_path(root, item)):
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for script in referenced_scripts(root, path, content):
                if script not in discovered:
                    discovered.add(script)
                    changed = True
    return sorted(discovered, key=lambda item: relative_path(root, item))


def scan_file_metadata(root: Path, path: Path) -> ScannedFile:
    data = path.read_bytes()
    return ScannedFile(
        path=relative_path(root, path),
        file_type=classify_file(path),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )
