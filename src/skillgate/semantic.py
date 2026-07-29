"""Bounded semantic inventory and advisory helpers for shipped agent artifacts.

It processes only source-selected text, never executes content, and keeps its
inventory, analysis, and drift results outside existing scan and review-packet
contracts.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from pydantic import ValidationError

from skillgate import __version__
from skillgate.discovery import classify_file, discover_semantic_paths, relative_path
from skillgate.identity import normalized_path
from skillgate.models import (
    AgentConsumption,
    Finding,
    SemanticAnalysis,
    SemanticBaseline,
    SemanticBlockSnapshot,
    SemanticDriftReport,
    SemanticFinding,
    SemanticInstructionDrift,
    SemanticInventorySkip,
    SemanticSourceRole,
    SemanticTextBlock,
    SemanticTextInventory,
    stable_json,
)
from skillgate.rules.base import FileContent, redact_evidence
from skillgate.scan import scan_repository

SEMANTIC_INVENTORY_SCHEMA_VERSION = "1"
SEMANTIC_ANALYSIS_SCHEMA_VERSION = "1"
SEMANTIC_BASELINE_SCHEMA_VERSION = "1"
SEMANTIC_DRIFT_SCHEMA_VERSION = "1"

_DIRECT_MARKDOWN_NAMES = frozenset(
    {
        "AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        "SKILL.md",
    }
)
_DIRECT_MARKDOWN_PREFIXES = (
    ".claude/commands/",
    ".gemini/commands/",
    ".github/copilot-instructions.md",
    "agents/",
    "skills/",
)
_STRUCTURED_SEMANTIC_NAMES = frozenset(
    {
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
)
_MCP_FILE_TYPES = frozenset({"mcp_config", "mcp_registry"})
SemanticFieldRole = tuple[SemanticSourceRole, AgentConsumption]
_TEXT_FIELD_ROLES: dict[str, SemanticFieldRole] = {
    "description": ("tool_description", "direct"),
    "instruction": ("agent_instruction", "direct"),
    "instructions": ("agent_instruction", "direct"),
    "prompt": ("prompt_template", "direct"),
    "system_prompt": ("prompt_template", "direct"),
    "template": ("prompt_template", "direct"),
}
_MANIFEST_FIELD_ROLES: dict[str, SemanticFieldRole] = {
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


def normalized_semantic_text(value: str) -> str:
    """Normalize layout whitespace in already redacted instruction text."""

    normalized_lines = _redacted_text(value).replace("\r\n", "\n").replace("\r", "\n")
    return " ".join(normalized_lines.split())


def semantic_block_fingerprint(block: SemanticTextBlock) -> str:
    """Return a line-movement-stable identity for one source-selected text block."""

    payload = {
        "agent_consumption": block.agent_consumption,
        "file_path": normalized_path(block.file_path),
        "source_role": block.source_role,
        "structured_field": block.structured_field,
        "text": normalized_semantic_text(block.text),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{sha256(encoded).hexdigest()}"


def _semantic_block_snapshot(block: SemanticTextBlock) -> SemanticBlockSnapshot:
    return SemanticBlockSnapshot(
        fingerprint=semantic_block_fingerprint(block),
        file_path=normalized_path(block.file_path),
        line_number=block.line_number,
        end_line=block.end_line,
        text=_redacted_text(block.text),
        source_role=block.source_role,
        structured_field=block.structured_field,
        agent_consumption=block.agent_consumption,
    )


def _snapshot_context(block: SemanticBlockSnapshot) -> tuple[str, str, str, str | None]:
    """Return the context used to pair changed text after exact matches are removed."""

    return (
        block.file_path,
        block.source_role,
        block.agent_consumption,
        block.structured_field,
    )


def _context_sort_key(context: tuple[str, str, str, str | None]) -> tuple[str, str, str, str]:
    return (context[0], context[1], context[2], context[3] or "")


def _snapshot_sort_key(block: SemanticBlockSnapshot) -> tuple[str, str, str, str, int, int]:
    return (
        block.fingerprint,
        block.file_path,
        block.source_role,
        block.structured_field or "",
        block.line_number,
        block.end_line,
    )


def _semantic_skip_sort_key(skip: SemanticInventorySkip) -> tuple[str, str]:
    return (skip.file_path, skip.reason)


def _semantic_drift_sort_key(
    change: SemanticInstructionDrift,
) -> tuple[int, str, str, str, str, int, int]:
    block = change.after or change.before
    assert block is not None
    change_order = {"added": 0, "removed": 1, "modified": 2}
    return (change_order[change.change_type], *_snapshot_sort_key(block))


def create_semantic_baseline(inventory: SemanticTextInventory) -> SemanticBaseline:
    """Create a redacted, internal semantic approval baseline from an inventory."""

    return SemanticBaseline(
        schema_version=SEMANTIC_BASELINE_SCHEMA_VERSION,
        tool_version=__version__,
        created_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        blocks=sorted(
            (_semantic_block_snapshot(block) for block in inventory.blocks),
            key=_snapshot_sort_key,
        ),
        skipped_files=sorted(inventory.skipped_files, key=_semantic_skip_sort_key),
    )


def create_semantic_baseline_repository(
    root: Path,
    *,
    limits: SemanticInventoryLimits = DEFAULT_SEMANTIC_INVENTORY_LIMITS,
) -> SemanticBaseline:
    """Create an internal semantic baseline from one local repository without a CLI."""

    return create_semantic_baseline(semantic_text_inventory_repository(root, limits=limits))


def save_semantic_baseline(baseline: SemanticBaseline, output: Path) -> None:
    """Persist an internal baseline using the repository's stable JSON convention."""

    output.write_text(stable_json(baseline), encoding="utf-8")


def load_semantic_baseline(path: Path) -> SemanticBaseline:
    """Load a persisted internal semantic baseline without affecting BaselineLock."""

    try:
        return SemanticBaseline.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise ValueError(f"Unable to load semantic baseline file: {path}") from exc


def diff_semantic_baseline(
    baseline: SemanticBaseline, inventory: SemanticTextInventory
) -> SemanticDriftReport:
    """Compare a semantic inventory without treating line movement as drift.

    Exact fingerprints include source role, selected field, applicability, and
    normalized redacted text. Remaining blocks with the same context are
    modifications; a context move is intentionally removal plus addition so
    review does not lose the source-field change.
    """

    before_by_fingerprint: dict[str, list[SemanticBlockSnapshot]] = {}
    after_by_fingerprint: dict[str, list[SemanticBlockSnapshot]] = {}
    for block in baseline.blocks:
        before_by_fingerprint.setdefault(block.fingerprint, []).append(block)
    for block in (_semantic_block_snapshot(item) for item in inventory.blocks):
        after_by_fingerprint.setdefault(block.fingerprint, []).append(block)
    for blocks in (*before_by_fingerprint.values(), *after_by_fingerprint.values()):
        blocks.sort(key=_snapshot_sort_key)

    unchanged = 0
    before_remaining: list[SemanticBlockSnapshot] = []
    after_remaining: list[SemanticBlockSnapshot] = []
    for fingerprint in sorted(set(before_by_fingerprint) | set(after_by_fingerprint)):
        before_blocks = before_by_fingerprint.get(fingerprint, [])
        after_blocks = after_by_fingerprint.get(fingerprint, [])
        matched = min(len(before_blocks), len(after_blocks))
        unchanged += matched
        before_remaining.extend(before_blocks[matched:])
        after_remaining.extend(after_blocks[matched:])

    before_by_context: dict[tuple[str, str, str, str | None], list[SemanticBlockSnapshot]] = {}
    after_by_context: dict[tuple[str, str, str, str | None], list[SemanticBlockSnapshot]] = {}
    for block in before_remaining:
        before_by_context.setdefault(_snapshot_context(block), []).append(block)
    for block in after_remaining:
        after_by_context.setdefault(_snapshot_context(block), []).append(block)

    changes: list[SemanticInstructionDrift] = []
    for context in sorted(set(before_by_context) | set(after_by_context), key=_context_sort_key):
        before_blocks = sorted(before_by_context.get(context, []), key=_snapshot_sort_key)
        after_blocks = sorted(after_by_context.get(context, []), key=_snapshot_sort_key)
        paired = min(len(before_blocks), len(after_blocks))
        changes.extend(
            SemanticInstructionDrift(
                change_type="modified",
                before=before_blocks[index],
                after=after_blocks[index],
            )
            for index in range(paired)
        )
        changes.extend(
            SemanticInstructionDrift(change_type="removed", before=block)
            for block in before_blocks[paired:]
        )
        changes.extend(
            SemanticInstructionDrift(change_type="added", after=block)
            for block in after_blocks[paired:]
        )

    changes.sort(key=_semantic_drift_sort_key)
    baseline_skipped_files = sorted(baseline.skipped_files, key=_semantic_skip_sort_key)
    current_skipped_files = sorted(inventory.skipped_files, key=_semantic_skip_sort_key)
    return SemanticDriftReport(
        schema_version=SEMANTIC_DRIFT_SCHEMA_VERSION,
        tool_version=__version__,
        baseline_created_at=baseline.created_at,
        baseline_skipped_files=baseline_skipped_files,
        current_skipped_files=current_skipped_files,
        coverage_changed=baseline_skipped_files != current_skipped_files,
        incomplete=bool(baseline_skipped_files or current_skipped_files),
        changes=changes,
        summary={
            "added": sum(change.change_type == "added" for change in changes),
            "removed": sum(change.change_type == "removed" for change in changes),
            "modified": sum(change.change_type == "modified" for change in changes),
            "unchanged": unchanged,
        },
    )


def diff_semantic_repository(
    baseline: SemanticBaseline,
    root: Path,
    *,
    limits: SemanticInventoryLimits = DEFAULT_SEMANTIC_INVENTORY_LIMITS,
) -> SemanticDriftReport:
    """Compare an internal semantic baseline to one local repository without a CLI."""

    return diff_semantic_baseline(
        baseline,
        semantic_text_inventory_repository(root, limits=limits),
    )


def semantic_baseline_json(baseline: SemanticBaseline) -> str:
    """Serialize an internal semantic baseline using stable JSON."""

    return stable_json(baseline)


def semantic_drift_json(report: SemanticDriftReport) -> str:
    """Serialize an internal semantic drift report using stable JSON."""

    return stable_json(report)


def _one_line_semantic_text(value: str) -> str:
    return normalized_semantic_text(value)


def _markdown_code(value: str) -> str:
    """Wrap untrusted single-line text in a code span without allowing backtick breaks."""

    longest_run = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * (longest_run + 1)
    return f"{fence}{value}{fence}"


def _render_drift_context(block: SemanticBlockSnapshot) -> list[str]:
    return [
        f"- Source: {_markdown_code(f'{block.file_path}:{block.line_number}-{block.end_line}')}",
        f"- Context: {_markdown_code(block.source_role)} / "
        f"{_markdown_code(block.structured_field or '-')} / "
        f"{_markdown_code(block.agent_consumption)}",
    ]


def render_semantic_drift_markdown(report: SemanticDriftReport) -> str:
    """Render an internal, redacted advisory view of semantic instruction drift."""

    lines = [
        "# SkillGate Semantic Instruction Drift",
        "",
        "Advisory only: this report compares shipped, source-selected text blocks.",
        "It does not change capability-baseline, policy, SARIF, or review-packet behavior.",
        "",
        f"- Added: {report.summary['added']}",
        f"- Removed: {report.summary['removed']}",
        f"- Modified: {report.summary['modified']}",
        f"- Unchanged: {report.summary['unchanged']}",
        f"- Coverage complete: `{not report.incomplete}`",
        "",
        "## Changes",
        "",
    ]
    if report.incomplete:
        baseline_skips = (
            ", ".join(
                f"{_markdown_code(skip.file_path)} ({_markdown_code(skip.reason)})"
                for skip in report.baseline_skipped_files
            )
            or "none"
        )
        current_skips = (
            ", ".join(
                f"{_markdown_code(skip.file_path)} ({_markdown_code(skip.reason)})"
                for skip in report.current_skipped_files
            )
            or "none"
        )
        lines.extend(
            [
                "Coverage is incomplete because one or more semantic source files were skipped.",
                f"Baseline skipped files: {len(report.baseline_skipped_files)}; "
                f"current skipped files: {len(report.current_skipped_files)}.",
                f"- Baseline skips: {baseline_skips}",
                f"- Current skips: {current_skips}",
                "",
            ]
        )
    if not report.changes:
        lines.append("None.")
    for change in report.changes:
        if change.change_type == "added":
            assert change.after is not None
            lines.extend(
                [
                    "### Added instruction",
                    "",
                    *_render_drift_context(change.after),
                    f"- Fingerprint: {_markdown_code(change.after.fingerprint)}",
                    f"- Instruction: {_markdown_code(_one_line_semantic_text(change.after.text))}",
                    "",
                ]
            )
        elif change.change_type == "removed":
            assert change.before is not None
            lines.extend(
                [
                    "### Removed instruction",
                    "",
                    *_render_drift_context(change.before),
                    f"- Fingerprint: {_markdown_code(change.before.fingerprint)}",
                    f"- Instruction: {_markdown_code(_one_line_semantic_text(change.before.text))}",
                    "",
                ]
            )
        else:
            assert change.before is not None and change.after is not None
            lines.extend(
                [
                    "### Modified instruction",
                    "",
                    *_render_drift_context(change.after),
                    f"- Before fingerprint: {_markdown_code(change.before.fingerprint)}",
                    f"- After fingerprint: {_markdown_code(change.after.fingerprint)}",
                    f"- Before: {_markdown_code(_one_line_semantic_text(change.before.text))}",
                    f"- After: {_markdown_code(_one_line_semantic_text(change.after.text))}",
                    "",
                ]
            )
    return "\n".join(lines) + "\n"


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
