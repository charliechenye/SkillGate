"""Bounded semantic text inventory for statically shipped agent artifacts.

This module deliberately inventories source-selected text only. It does not
emit findings, infer a source role from suspicious wording, execute content,
or change the existing scan and review-packet contracts.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from skillgate import __version__
from skillgate.discovery import classify_file, discover_semantic_paths, relative_path
from skillgate.models import (
    SemanticInventorySkip,
    SemanticTextBlock,
    SemanticTextInventory,
    stable_json,
)
from skillgate.rules.base import FileContent, redact_evidence

SEMANTIC_INVENTORY_SCHEMA_VERSION = "1"

_DIRECT_MARKDOWN_NAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "SKILL.md",
}
_DIRECT_MARKDOWN_PREFIXES = (
    ".claude/commands/",
    ".gemini/commands/",
    ".github/copilot-instructions.md",
    "agents/",
    "skills/",
)
_STRUCTURED_SEMANTIC_NAMES = {
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
    "manifest.json",
    "mcp.toml",
    "mcp.yaml",
    "mcp.yml",
    "prompts.toml",
    "prompts.yaml",
    "prompts.yml",
}
_MCP_FILE_TYPES = {"mcp_config", "mcp_registry"}
_TEXT_FIELD_ROLES = {
    "description": ("tool_description", "direct"),
    "instruction": ("agent_instruction", "direct"),
    "instructions": ("agent_instruction", "direct"),
    "prompt": ("prompt_template", "direct"),
    "system_prompt": ("prompt_template", "direct"),
    "template": ("prompt_template", "direct"),
}
_MANIFEST_FIELD_ROLES = {
    "description": ("manifest_metadata", "possible"),
    "instruction": ("agent_instruction", "possible"),
    "instructions": ("agent_instruction", "possible"),
    "prompt": ("prompt_template", "possible"),
    "system_prompt": ("prompt_template", "possible"),
    "template": ("prompt_template", "possible"),
}
_FRONTMATTER_DESCRIPTION_RE = re.compile(r"^(?P<indent>[ \t]*)description:\s*(?P<value>.+?)\s*$")
_SECRET_VALUE_RE = re.compile(
    r"""(?ix)
    (?P<name>[\"']?[a-z0-9_-]*(?:token|secret|password|credential|api[_-]?key|access[_-]?key)[a-z0-9_-]*[\"']?)
    (?P<separator>\s*[:=]\s*)
    (?P<value>\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|[^\s,;]+)
    """
)


@dataclass(frozen=True)
class SemanticInventoryLimits:
    """Read and output bounds for the semantic inventory."""

    max_file_bytes: int = 256 * 1024
    max_block_bytes: int = 64 * 1024
    max_total_bytes: int = 1024 * 1024
    max_blocks: int = 200


DEFAULT_SEMANTIC_INVENTORY_LIMITS = SemanticInventoryLimits()


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def _line_end(text: str, offset: int, value: str) -> int:
    return _line_number(text, offset + len(value))


def _redacted_text(value: str) -> str:
    """Preserve secret names while avoiding literal assignment values in inventory JSON."""

    value = _SECRET_VALUE_RE.sub(r"\g<name>\g<separator>[REDACTED]", value)
    return redact_evidence(value)


def _path_is_direct_markdown(path: str) -> bool:
    normalized = path.replace("\\", "/")
    name = PurePosixPath(normalized).name
    if name not in _DIRECT_MARKDOWN_NAMES:
        return normalized == ".github/copilot-instructions.md"
    return (
        name == "SKILL.md"
        or normalized.startswith(_DIRECT_MARKDOWN_PREFIXES)
        or name
        in {
            "AGENTS.md",
            "CLAUDE.md",
            "GEMINI.md",
        }
    )


def _is_semantic_source(file: FileContent) -> bool:
    path = file.path.replace("\\", "/")
    name = PurePosixPath(path).name
    if file.file_type == "markdown":
        return _path_is_direct_markdown(path)
    return file.file_type in _MCP_FILE_TYPES or name in _STRUCTURED_SEMANTIC_NAMES


def _frontmatter_end(lines: list[str]) -> int:
    if not lines or lines[0].strip() != "---":
        return 0
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return index + 1
    return 0


def _markdown_blocks(file: FileContent) -> list[SemanticTextBlock]:
    lines = file.text.splitlines(keepends=True)
    frontmatter_end = _frontmatter_end(lines) if PurePosixPath(file.path).name == "SKILL.md" else 0
    blocks: list[SemanticTextBlock] = []
    if frontmatter_end:
        for index, line in enumerate(lines[1 : frontmatter_end - 1], start=2):
            match = _FRONTMATTER_DESCRIPTION_RE.match(line.rstrip("\r\n"))
            if not match:
                continue
            value = match.group("value").strip().strip("\"'")
            if value:
                blocks.append(
                    SemanticTextBlock(
                        file_path=file.path,
                        line_number=index,
                        end_line=index,
                        text=_redacted_text(value),
                        source_role="tool_description",
                        structured_field="frontmatter.description",
                        agent_consumption="direct",
                    )
                )
            break

    body_source = "".join(lines[frontmatter_end:])
    body = body_source.strip()
    if not body:
        return blocks
    start_offset = sum(len(line) for line in lines[:frontmatter_end]) + (
        len(body_source) - len(body_source.lstrip())
    )
    blocks.append(
        SemanticTextBlock(
            file_path=file.path,
            line_number=_line_number(file.text, start_offset),
            end_line=_line_end(file.text, start_offset, body),
            text=_redacted_text(body),
            source_role="agent_instruction",
            structured_field="body" if PurePosixPath(file.path).name == "SKILL.md" else None,
            agent_consumption="direct",
        )
    )
    return blocks


def _structured_field_name(parts: tuple[str, ...]) -> str:
    output = ""
    for part in parts:
        output += f"[{part}]" if part.isdigit() else ("." if output else "") + part
    return output


def _iter_selected_text_fields(
    value: Any, parts: tuple[str, ...] = ()
) -> Iterable[tuple[tuple[str, ...], str, str]]:
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            item = value[key]
            name = str(key)
            child_parts = (*parts, name)
            if name in _TEXT_FIELD_ROLES and isinstance(item, str) and item.strip():
                yield child_parts, name, item.strip()
            yield from _iter_selected_text_fields(item, child_parts)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_selected_text_fields(item, (*parts, str(index)))


def _structured_value_offset(text: str, field: str, value: str, used_offsets: set[int]) -> int:
    """Find a source span conservatively; fall back to the field key when needed."""

    value_patterns = [json.dumps(value), re.escape(value)]
    key_pattern = re.escape(field)
    for value_pattern in value_patterns:
        for match in re.finditer(
            rf"(?s)(?:[\"']{key_pattern}[\"']|{key_pattern})\s*[:=]\s*{value_pattern}",
            text,
        ):
            if match.start() not in used_offsets:
                used_offsets.add(match.start())
                return match.start()
    for key_match in re.finditer(
        rf"(?m)^.*?(?:[\"']{key_pattern}[\"']|{key_pattern})\s*[:=]",
        text,
    ):
        if key_match.start() not in used_offsets:
            used_offsets.add(key_match.start())
            return key_match.start()
    return 0


def _parse_structured_text(file: FileContent) -> tuple[Any, bool]:
    suffix = PurePosixPath(file.path).suffix.lower()
    try:
        if suffix == ".json":
            return json.loads(file.text), False
        if suffix in {".yaml", ".yml"}:
            return yaml.safe_load(file.text), False
        if suffix == ".toml":
            return tomllib.loads(file.text), False
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, yaml.YAMLError):
        return None, True
    return None, False


def _structured_blocks(file: FileContent) -> list[SemanticTextBlock]:
    data, _parse_failed = _parse_structured_text(file)
    if not isinstance(data, dict):
        return []
    is_manifest = PurePosixPath(file.path).name == "manifest.json"
    roles = _MANIFEST_FIELD_ROLES if is_manifest else _TEXT_FIELD_ROLES
    blocks = []
    used_offsets: set[int] = set()
    for parts, field, value in _iter_selected_text_fields(data):
        role, consumption = roles[field]
        offset = _structured_value_offset(file.text, field, value, used_offsets)
        line_number = _line_number(file.text, offset)
        blocks.append(
            SemanticTextBlock(
                file_path=file.path,
                line_number=line_number,
                end_line=line_number + value.count("\n"),
                text=_redacted_text(value),
                source_role=role,
                structured_field=_structured_field_name(parts),
                agent_consumption=consumption,
            )
        )
    return blocks


def extract_semantic_text_blocks(file: FileContent) -> list[SemanticTextBlock]:
    """Extract explicit semantic inputs from one already-loaded file.

    Files without an allowlisted source adapter intentionally return no blocks.
    """

    if not _is_semantic_source(file):
        return []
    if file.file_type == "markdown":
        return _markdown_blocks(file)
    return _structured_blocks(file)


def _block_bytes(block: SemanticTextBlock) -> int:
    return len(block.text.encode("utf-8"))


def semantic_text_inventory(
    files: Iterable[FileContent],
    *,
    limits: SemanticInventoryLimits = DEFAULT_SEMANTIC_INVENTORY_LIMITS,
) -> SemanticTextInventory:
    """Build a stable, bounded inventory without deriving semantic findings."""

    blocks: list[SemanticTextBlock] = []
    skipped: list[SemanticInventorySkip] = []
    source_files = 0
    total_bytes = 0
    for file in sorted(files, key=lambda item: item.path):
        if not _is_semantic_source(file):
            continue
        source_files += 1
        if len(file.text.encode("utf-8")) > limits.max_file_bytes:
            skipped.append(SemanticInventorySkip(file_path=file.path, reason="file_size_limit"))
            continue
        if file.file_type != "markdown" and _parse_structured_text(file)[1]:
            skipped.append(SemanticInventorySkip(file_path=file.path, reason="parse_error"))
            continue
        file_blocks = extract_semantic_text_blocks(file)
        if any(_block_bytes(block) > limits.max_block_bytes for block in file_blocks):
            skipped.append(SemanticInventorySkip(file_path=file.path, reason="block_size_limit"))
            continue
        file_bytes = sum(_block_bytes(block) for block in file_blocks)
        if len(blocks) + len(file_blocks) > limits.max_blocks:
            skipped.append(SemanticInventorySkip(file_path=file.path, reason="block_count_limit"))
            continue
        if total_bytes + file_bytes > limits.max_total_bytes:
            skipped.append(SemanticInventorySkip(file_path=file.path, reason="total_size_limit"))
            continue
        blocks.extend(file_blocks)
        total_bytes += file_bytes
    blocks.sort(
        key=lambda block: (
            block.file_path,
            block.line_number,
            block.end_line,
            block.structured_field or "",
        )
    )
    skipped.sort(key=lambda item: (item.file_path, item.reason))
    return SemanticTextInventory(
        schema_version=SEMANTIC_INVENTORY_SCHEMA_VERSION,
        tool_version=__version__,
        blocks=blocks,
        skipped_files=skipped,
        summary={
            "blocks": len(blocks),
            "source_files": source_files,
            "skipped_files": len(skipped),
            "text_bytes": total_bytes,
        },
    )


def semantic_text_inventory_json(inventory: SemanticTextInventory) -> str:
    return stable_json(inventory)


def semantic_text_inventory_repository(
    root: Path,
    *,
    limits: SemanticInventoryLimits = DEFAULT_SEMANTIC_INVENTORY_LIMITS,
) -> SemanticTextInventory:
    """Inventory discovery-selected local files without changing scan behavior.

    Archive callers should supply the safety-selected ``FileContent`` values to
    ``semantic_text_inventory`` instead of rewalking an extracted archive.
    """

    root = root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError("semantic inventory root must be an existing directory")
    files = []
    for path in discover_semantic_paths(root):
        relative = relative_path(root, path)
        file_type = classify_file(path)
        probe = FileContent(path=relative, file_type=file_type, text="")
        if not _is_semantic_source(probe):
            continue
        if path.stat().st_size > limits.max_file_bytes:
            files.append(
                FileContent(
                    path=relative,
                    file_type=file_type,
                    text="x" * (limits.max_file_bytes + 1),
                )
            )
            continue
        files.append(
            FileContent(
                path=relative,
                file_type=file_type,
                text=path.read_text(encoding="utf-8", errors="replace"),
            )
        )
    return semantic_text_inventory(files, limits=limits)
