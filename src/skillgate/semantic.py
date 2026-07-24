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
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from skillgate import __version__
from skillgate.discovery import classify_file, discover_semantic_paths, relative_path
from skillgate.models import (
    Finding,
    SemanticAnalysis,
    SemanticFinding,
    SemanticInventorySkip,
    SemanticTextBlock,
    SemanticTextInventory,
    stable_json,
)
from skillgate.rules.base import FileContent, redact_evidence
from skillgate.scan import scan_repository

SEMANTIC_INVENTORY_SCHEMA_VERSION = "1"
SEMANTIC_ANALYSIS_SCHEMA_VERSION = "1"

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
_SA001_ACTION_RE = re.compile(r"(?i)\b(?:read|inspect|open|collect|retrieve)\b")
_SA001_TARGET_RE = re.compile(
    r"(?i)(?:\.(?:env)(?:\b|/)|\.ssh/|\b(?:private[ -]?key|credential store|"
    r"access[ -]?token)\b|\b(?:TOKEN|SECRET|API_KEY|ACCESS_KEY)\b|"
    r"\b(?!PUBLIC_)[A-Z][A-Z0-9_]*_(?:TOKEN|SECRET|KEY)\b)"
)
_SA002_ACTION_RE = re.compile(r"(?i)\b(?:send|forward|upload|append|post|share|transmit)\b")
_SA002_SENSITIVE_RE = re.compile(r"(?i)\b(?:private|secret|token|credential|confidential)\b")
_DESTINATION_RE = re.compile(
    r"(?i)(?:https?://[^\s'\"<>`]+|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)"
)
_NEGATION_RE = re.compile(r"(?i)\b(?:do not|don't|never|must not|avoid)\b")
_SENTENCE_BOUNDARY_RE = re.compile(r"(?:[!?]|(?<=[A-Za-z])\.)(?:\s+|$)")


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


def _sentence_prefix(value: str, offset: int) -> str:
    """Return the current sentence prefix without treating file-name dots as boundaries."""

    prefix = value[:offset]
    boundaries = list(_SENTENCE_BOUNDARY_RE.finditer(prefix))
    return prefix[boundaries[-1].end() :] if boundaries else prefix


def _has_non_negated_action(value: str, pattern: re.Pattern[str]) -> bool:
    return any(
        not _NEGATION_RE.search(_sentence_prefix(value, match.start()))
        for match in pattern.finditer(value)
    )


def _sentences(value: str) -> Iterable[str]:
    start = 0
    for boundary in _SENTENCE_BOUNDARY_RE.finditer(value):
        yield value[start : boundary.start()]
        start = boundary.end()
    if start < len(value):
        yield value[start:]


def _semantic_finding_id(rule_id: str, block: SemanticTextBlock, evidence: str) -> str:
    seed = "|".join(
        [
            rule_id,
            block.file_path,
            str(block.line_number),
            str(block.end_line),
            block.structured_field or "",
            evidence,
        ]
    ).encode("utf-8")
    return f"{rule_id}-{sha256(seed).hexdigest()[:12]}"


def _related_rule_ids(
    findings: Iterable[Finding], block: SemanticTextBlock, capability: str
) -> list[str]:
    return sorted(
        {
            finding.rule_id
            for finding in findings
            if finding.file_path == block.file_path and finding.capability == capability
        }
    )


def _make_semantic_finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    block: SemanticTextBlock,
    related_rule_ids: list[str],
    review_guidance: str,
) -> SemanticFinding:
    evidence = _redacted_text(block.text)
    return SemanticFinding(
        id=_semantic_finding_id(rule_id, block, evidence),
        rule_id=rule_id,
        title=title,
        potential_impact="high",
        confidence="high",
        applicability=block.agent_consumption,
        file_path=block.file_path,
        line_number=block.line_number,
        end_line=block.end_line,
        evidence=evidence,
        category=category,
        source_role=block.source_role,
        structured_field=block.structured_field,
        related_rule_ids=related_rule_ids,
        review_guidance=review_guidance,
    )


def _matches_sa001(block: SemanticTextBlock) -> bool:
    return any(
        _has_non_negated_action(sentence, _SA001_ACTION_RE)
        and _SA001_TARGET_RE.search(sentence) is not None
        for sentence in _sentences(block.text)
    )


def _matches_sa002(block: SemanticTextBlock) -> bool:
    return any(
        _has_non_negated_action(sentence, _SA002_ACTION_RE)
        and _SA002_SENSITIVE_RE.search(sentence) is not None
        and _DESTINATION_RE.search(sentence) is not None
        for sentence in _sentences(block.text)
    )


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


def analyze_semantic_inventory(
    inventory: SemanticTextInventory,
    static_findings: Iterable[Finding] = (),
) -> SemanticAnalysis:
    """Produce narrow advisory findings from direct, source-selected text blocks.

    This separate result family deliberately does not alter ScanReport, policy,
    baseline, SARIF, or CLI behavior.
    """

    findings = list(static_findings)
    semantic_findings: list[SemanticFinding] = []
    for block in inventory.blocks:
        if block.agent_consumption != "direct":
            continue
        if _matches_sa001(block):
            semantic_findings.append(
                _make_semantic_finding(
                    rule_id="SA001",
                    title="Agent-directed sensitive-data access instruction",
                    category="sensitive_data_access",
                    block=block,
                    related_rule_ids=_related_rule_ids(findings, block, "secret_access"),
                    review_guidance=(
                        "Confirm whether this access is necessary, declared, and bounded "
                        "for the artifact's purpose."
                    ),
                )
            )
        if _matches_sa002(block):
            semantic_findings.append(
                _make_semantic_finding(
                    rule_id="SA002",
                    title="Agent-directed private-data transmission instruction",
                    category="data_transmission",
                    block=block,
                    related_rule_ids=_related_rule_ids(findings, block, "network_egress"),
                    review_guidance=(
                        "Confirm that the requested data and named destination are expected, "
                        "necessary, and approved."
                    ),
                )
            )
    semantic_findings.sort(
        key=lambda item: (item.rule_id, item.file_path, item.line_number, item.id)
    )
    return SemanticAnalysis(
        schema_version=SEMANTIC_ANALYSIS_SCHEMA_VERSION,
        tool_version=__version__,
        findings=semantic_findings,
        summary={
            "findings": len(semantic_findings),
            "sa001": sum(item.rule_id == "SA001" for item in semantic_findings),
            "sa002": sum(item.rule_id == "SA002" for item in semantic_findings),
        },
    )


def analyze_semantic_repository(root: Path) -> SemanticAnalysis:
    """Analyze a local inventory with related static findings, without a CLI surface."""

    inventory = semantic_text_inventory_repository(root)
    static_report = scan_repository(root, format_aware=True)
    return analyze_semantic_inventory(inventory, static_report.findings)


def semantic_analysis_json(analysis: SemanticAnalysis) -> str:
    return stable_json(analysis)


def render_semantic_analysis_markdown(analysis: SemanticAnalysis) -> str:
    """Render an internal, advisory-only Markdown view of semantic findings."""

    lines = [
        "# SkillGate Semantic Analysis",
        "",
        "Advisory only: these findings identify explicit shipped instructions for review.",
        "They do not prove exploitability or replace runtime trust boundaries.",
        "",
        f"- Findings: {analysis.summary['findings']}",
        f"- SA001 sensitive-data access instructions: {analysis.summary['sa001']}",
        f"- SA002 private-data transmission instructions: {analysis.summary['sa002']}",
        "",
        "## Findings",
        "",
    ]
    if not analysis.findings:
        lines.append("None.")
    for finding in analysis.findings:
        related = ", ".join(finding.related_rule_ids) or "-"
        lines.extend(
            [
                f"### {finding.rule_id}: {finding.title}",
                "",
                f"- Source: `{finding.file_path}:{finding.line_number}-{finding.end_line}`",
                f"- Category: `{finding.category}`",
                f"- Impact / confidence / applicability: `{finding.potential_impact}` / "
                f"`{finding.confidence}` / `{finding.applicability}`",
                f"- Source role: `{finding.source_role}`",
                f"- Structured field: `{finding.structured_field or '-'}`",
                f"- Related static rules: `{related}`",
                f"- Evidence: {finding.evidence}",
                f"- Review: {finding.review_guidance}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


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
