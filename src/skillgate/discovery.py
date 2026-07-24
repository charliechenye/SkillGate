from __future__ import annotations

import hashlib
import json
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
    "mcp-registry.json",
    "mcp-server.json",
    "package.json",
    "pyproject.toml",
}
SEMANTIC_CONFIG_NAMES = {
    ".agent.yaml",
    ".agent.yml",
    "agent-config.toml",
    "agent-config.yaml",
    "agent-config.yml",
    "agent.toml",
    "agent.yaml",
    "agent.yml",
    "agents.toml",
    "agents.yaml",
    "agents.yml",
    "mcp.toml",
    "mcp.yaml",
    "mcp.yml",
    "prompts.toml",
    "prompts.yaml",
    "prompts.yml",
}
MCP_REGISTRY_NAMES = {"mcp-registry.json", "mcp-server.json", "server.json"}
REFERENCE_RE = re.compile(
    r"""(?P<path>(?:\.{1,2}/)?[A-Za-z0-9_./\\-]+\.(?:sh|bash|py|js|ts|mjs|cjs|ps1))"""
)
WRAPPED_REFERENCE_RE = re.compile(r"(?P<separator>[\\/])(?:[ \t]*\\)?[ \t]*\r?\n[ \t]*")
REFERENCE_DIRS = ("scripts", "references", "assets")


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


def looks_like_mcp_registry(path: Path) -> bool:
    if path.name not in MCP_REGISTRY_NAMES:
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("servers"), list):
        return True
    server = data.get("server")
    if isinstance(server, dict) and isinstance(server.get("name"), str):
        return True
    return isinstance(data.get("name"), str) and any(
        key in data for key in ["repository", "remotes", "packages", "tools", "_meta"]
    )


def classify_file(path: Path) -> str:
    name = path.name
    suffix = path.suffix.lower()
    if name in {"mcp.json", ".mcp.json"}:
        return "mcp_config"
    if name in MCP_REGISTRY_NAMES:
        return "mcp_registry"
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
            if not is_excluded(rel) and (is_relevant_path(rel) or looks_like_mcp_registry(path)):
                candidates.append(path)
    return sorted(candidates, key=lambda item: relative_path(root, item))


def _wrapped_reference_text(content: str) -> str:
    return WRAPPED_REFERENCE_RE.sub(r"\g<separator>", content)


def _reference_candidates(root: Path, source: Path, raw: str) -> list[Path]:
    normalized = raw.replace("\\", "/")
    candidates = [source.parent / normalized]
    if "/" not in normalized:
        candidates.extend(root / directory / normalized for directory in REFERENCE_DIRS)
    safe: list[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve()
        try:
            rel = resolved.relative_to(root.resolve())
        except ValueError:
            continue
        if resolved.is_file() and resolved.suffix.lower() in SCRIPT_EXTENSIONS:
            if not is_excluded(rel):
                safe.append(resolved)
    return safe


def referenced_scripts(root: Path, source: Path, content: str) -> list[Path]:
    scripts: list[Path] = []
    variants = (content, _wrapped_reference_text(content))
    for variant in variants:
        for match in REFERENCE_RE.finditer(variant):
            raw = match.group("path").replace("\\", "/")
            if "://" in raw or raw.startswith("/"):
                continue
            scripts.extend(_reference_candidates(root, source, raw))
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


def discover_semantic_paths(root: Path) -> list[Path]:
    """Return normal discovery plus the narrow structured semantic allowlist.

    The default scanner keeps its existing discovery behavior. Semantic
    inventory extends that shared boundary only for explicitly named YAML and
    TOML agent configuration files.
    """

    root = root.resolve()
    discovered = set(discover_paths(root))
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = sorted(name for name in dirnames if name not in EXCLUDED_DIRS)
        for filename in sorted(filenames):
            if filename in SEMANTIC_CONFIG_NAMES:
                discovered.add(current / filename)
    return sorted(discovered, key=lambda item: relative_path(root, item))


def scan_file_metadata(root: Path, path: Path) -> ScannedFile:
    data = path.read_bytes()
    return ScannedFile(
        path=relative_path(root, path),
        file_type=classify_file(path),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )
