"""Aggregate static capability evidence for Agent Plugins 1.0 packages.

This module composes the existing SkillGate scanner with the structural Agent
Plugin inventory. It deliberately does not add scanner rules, policy, drift,
approval, or client-extension semantics.

The result is always an observed static capability lower bound. A reviewed
component with no capabilities is different from a component that could not
be reviewed, and uninterpreted package surfaces remain explicit blind spots.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from skillgate.agent_plugins import (
    DEFAULT_AGENT_PLUGIN_LIMITS,
    AgentPluginCoverage,
    AgentPluginDiagnostic,
    AgentPluginInventory,
    AgentPluginLimits,
    AgentPluginMcpServer,
    AgentPluginSkill,
    load_agent_plugin,
)
from skillgate.discovery import EXCLUDED_DIRS, SCRIPT_EXTENSIONS, classify_file
from skillgate.mcp_app_assets import (
    inventory_local_mcp_app_assets,
    mcp_app_asset_capabilities,
)
from skillgate.mcp_apps import (
    MCP_APP_UI_MIME_PREFIX,
    MCP_APP_UI_MIME_VALUES,
    inventory_from_json_text,
)
from skillgate.models import Capability
from skillgate.rules import DEFAULT_RULES
from skillgate.rules.base import FileContent
from skillgate.scan import unique_capabilities

_ROOT_COMPONENT_ID = "mcp.json"
_REVIEWED = "reviewed"
_INCOMPLETE = "incomplete"
_INVALID = "invalid"
_SKIPPED = "skipped"
_FILE_SCANNED = "scanned"
_FILE_NOT_APPLICABLE = "not_applicable"
_FILE_UNSUPPORTED = "unsupported"
_FILE_LIMIT_EXCEEDED = "limit_exceeded"
_FILE_UNREADABLE = "unreadable"
_FILE_SCAN_FAILED = "scan_failed"
_CAPABILITY_TEXT_EXTENSIONS = frozenset(
    {
        ".css",
        ".html",
        ".htm",
        ".json",
        ".markdown",
        ".md",
        ".rst",
        ".toml",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
_CAPABILITY_TEXT_NAMES = frozenset(
    {
        "AGENTS.md",
        "CLAUDE.md",
        "SKILL.md",
        ".agent.yaml",
        ".agent.yml",
        ".env",
        ".env.local",
        "agent-config.toml",
        "agent-config.yaml",
        "agent-config.yml",
        "agent.toml",
        "agent.yaml",
        "agent.yml",
        "agents.toml",
        "agents.yaml",
        "agents.yml",
        "mcp-registry.json",
        "mcp-server.json",
        "mcp.json",
        "package.json",
        "prompts.toml",
        "prompts.yaml",
        "prompts.yml",
        "pyproject.toml",
    }
)


@dataclass(frozen=True)
class AgentPluginCapabilityLimits:
    """Bounded file-analysis limits for one Agent Plugin component."""

    max_files_per_component: int = 256
    max_file_bytes: int = 1_048_576
    max_total_bytes_per_component: int = 8_388_608
    max_directories_per_component: int = 256
    max_entries_per_component: int = 1_024


DEFAULT_AGENT_PLUGIN_CAPABILITY_LIMITS = AgentPluginCapabilityLimits()


@dataclass(frozen=True)
class AgentPluginCapabilityFileReview:
    """Accounting for one file in a component capability review."""

    path: str
    status: str
    reason: str | None = None
    size_bytes: int | None = None

    def to_data(self) -> dict[str, object]:
        return {
            "path": self.path,
            "status": self.status,
            "reason": self.reason,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class _CapabilityFileCandidate:
    path: str
    read_path: Path


@dataclass
class _CapabilityFileInventory:
    candidates: list[_CapabilityFileCandidate]
    file_reviews: list[AgentPluginCapabilityFileReview]
    diagnostics: list[AgentPluginDiagnostic]
    complete: bool = True


@dataclass(frozen=True)
class _BoundedScanResult:
    status: str
    scanned_files: tuple[str, ...]
    file_reviews: tuple[AgentPluginCapabilityFileReview, ...]
    capabilities: tuple[Capability, ...]
    diagnostics: tuple[AgentPluginDiagnostic, ...]
    bytes_read: int = 0
    text_by_path: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class _SkillAssociatedResource:
    source_file: str
    declaration_path: str
    uri: str


@dataclass(frozen=True)
class _SkillAssociatedResourceResolution:
    label: str
    reason: str | None
    target_path: str | None = None


@dataclass(frozen=True)
class AgentPluginCapabilityEvidence:
    """One original scanner capability with Agent Plugin ownership context."""

    component_kind: str
    component_id: str
    component_path: str
    source_file: str
    source_line: int | None
    original_capability: Capability

    def to_data(self) -> dict[str, object]:
        return {
            "component_kind": self.component_kind,
            "component_id": self.component_id,
            "component_path": self.component_path,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "original_capability": self.original_capability.model_dump(mode="json"),
        }


@dataclass(frozen=True)
class AgentPluginObservedCapability:
    """One aggregate semantic capability retaining every evidence source."""

    type: str
    resource: str | None
    details: dict[str, Any]
    evidence: tuple[AgentPluginCapabilityEvidence, ...]

    def to_data(self) -> dict[str, object]:
        return {
            "type": self.type,
            "resource": self.resource,
            "details": dict(self.details),
            "evidence": [item.to_data() for item in self.evidence],
        }


@dataclass(frozen=True)
class AgentPluginComponentCapabilityReview:
    """Capability-review result for one portable or fixed component."""

    component_kind: str
    component_id: str
    component_path: str
    structural_status: str
    capability_scan_status: str
    scanned_files: tuple[str, ...] = ()
    capabilities: tuple[Capability, ...] = ()
    diagnostics: tuple[AgentPluginDiagnostic, ...] = ()
    file_reviews: tuple[AgentPluginCapabilityFileReview, ...] = ()

    def to_data(self) -> dict[str, object]:
        return {
            "component_kind": self.component_kind,
            "component_id": self.component_id,
            "component_path": self.component_path,
            "structural_status": self.structural_status,
            "capability_scan_status": self.capability_scan_status,
            "scanned_files": list(self.scanned_files),
            "file_reviews": [item.to_data() for item in self.file_reviews],
            "capabilities": [item.model_dump(mode="json") for item in self.capabilities],
            "diagnostics": [item.to_data() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class AgentPluginCapabilityBlindSpot:
    """A surface or component that prevents complete capability coverage."""

    component_kind: str
    component_id: str
    component_path: str
    reason: str

    def to_data(self) -> dict[str, str]:
        return {
            "component_kind": self.component_kind,
            "component_id": self.component_id,
            "component_path": self.component_path,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AgentPluginCapabilityCoverage:
    """Capability-review coverage, separate from structural coverage."""

    portable_core: str
    overall_artifact: str

    def to_data(self) -> dict[str, str]:
        return {
            "portable_core": self.portable_core,
            "overall_artifact": self.overall_artifact,
        }


@dataclass(frozen=True)
class AgentPluginCapabilityReview:
    """Internal aggregate observed-capability review for one Agent Plugin."""

    plugin_identity: dict[str, object]
    status: str
    structural_coverage: AgentPluginCoverage
    capability_coverage: AgentPluginCapabilityCoverage
    components: tuple[AgentPluginComponentCapabilityReview, ...]
    observed_capabilities: tuple[AgentPluginObservedCapability, ...]
    unknown_surfaces: tuple[str, ...]
    blind_spots: tuple[AgentPluginCapabilityBlindSpot, ...]
    diagnostics: tuple[AgentPluginDiagnostic, ...]
    claim_scope: str = "observed_static_capabilities"
    lower_bound: bool = True

    @property
    def coverage(self) -> AgentPluginCapabilityCoverage:
        """Convenience alias for callers focused on capability coverage."""
        return self.capability_coverage

    def to_data(self) -> dict[str, object]:
        return {
            "plugin_identity": dict(self.plugin_identity),
            "status": self.status,
            "structural_coverage": self.structural_coverage.to_data(),
            "capability_coverage": self.capability_coverage.to_data(),
            "components": [item.to_data() for item in self.components],
            "observed_capabilities": [item.to_data() for item in self.observed_capabilities],
            "unknown_surfaces": list(self.unknown_surfaces),
            "blind_spots": [item.to_data() for item in self.blind_spots],
            "diagnostics": [item.to_data() for item in self.diagnostics],
            "claim_scope": self.claim_scope,
            "lower_bound": self.lower_bound,
        }


def _diagnostic(code: str, message: str, path: str | None = None) -> AgentPluginDiagnostic:
    return AgentPluginDiagnostic(code=code, message=message, path=path)


def _sorted_diagnostics(
    diagnostics: list[AgentPluginDiagnostic],
) -> tuple[AgentPluginDiagnostic, ...]:
    return tuple(sorted(diagnostics, key=lambda item: (item.path or "", item.code, item.message)))


def _dedupe_diagnostics(
    diagnostics: list[AgentPluginDiagnostic],
) -> tuple[AgentPluginDiagnostic, ...]:
    return _sorted_diagnostics(
        list({(item.code, item.message, item.path): item for item in diagnostics}.values())
    )


def _capability_key(capability: Capability) -> tuple[str, str, str]:
    data = capability.model_dump(mode="json")
    return (
        str(data["type"]),
        json.dumps(data.get("resource"), sort_keys=True, separators=(",", ":")),
        json.dumps(data.get("details", {}), sort_keys=True, separators=(",", ":")),
    )


def _evidence_key(evidence: AgentPluginCapabilityEvidence) -> tuple[object, ...]:
    return (
        evidence.component_kind,
        evidence.component_id,
        evidence.component_path,
        evidence.source_file,
        -1 if evidence.source_line is None else evidence.source_line,
        _capability_key(evidence.original_capability),
    )


def _component_key(component: AgentPluginComponentCapabilityReview) -> tuple[str, str, str]:
    return (component.component_kind, component.component_id, component.component_path)


def _skill_component_id(skill: AgentPluginSkill) -> str:
    return Path(skill.path).parent.name


def _skill_component_path(skill: AgentPluginSkill) -> str:
    return Path(skill.path).parent.as_posix()


def _relative_plugin_path(root: Path, path: Path) -> str | None:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, RuntimeError, ValueError):
            return None


def _safe_file_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _is_capability_text_file(path: Path) -> bool:
    return path.name in _CAPABILITY_TEXT_NAMES or path.suffix.lower() in (
        SCRIPT_EXTENSIONS | _CAPABILITY_TEXT_EXTENSIONS
    )


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _inventory_marker(
    inventory: _CapabilityFileInventory,
    component_path: str,
    reason: str,
    message: str,
) -> None:
    marker = f"{component_path}/<unaccounted>"
    status = (
        _FILE_LIMIT_EXCEEDED
        if "limit_exceeded" in reason
        else _FILE_UNREADABLE
        if "unavailable" in reason
        else _FILE_UNSUPPORTED
    )
    if not any(item.path == marker for item in inventory.file_reviews):
        inventory.file_reviews.append(
            AgentPluginCapabilityFileReview(
                path=marker,
                status=status,
                reason=reason,
            )
        )
    inventory.diagnostics.append(_diagnostic(reason, message, marker))
    inventory.complete = False


def _inventory_skill_files(
    root: Path,
    component_root: Path,
    component_path: str,
    limits: AgentPluginCapabilityLimits,
) -> _CapabilityFileInventory:
    """Boundedly account for every inspectable file under one Skill root."""
    inventory = _CapabilityFileInventory([], [], [])
    root_resolved = root.resolve()
    component_resolved = component_root.resolve()
    pending = [component_root]
    visited_directories: set[Path] = set()
    file_count = 0
    directory_count = 0
    entry_count = 0
    max_files = max(limits.max_files_per_component, 0)
    max_directories = max(limits.max_directories_per_component, 0)
    max_entries = max(limits.max_entries_per_component, 0)

    while pending:
        current = pending.pop(0)
        try:
            current_resolved = current.resolve()
        except (OSError, RuntimeError):
            _inventory_marker(
                inventory,
                component_path,
                "capability_directory_unavailable",
                "a Skill directory could not be resolved safely",
            )
            continue
        if current_resolved in visited_directories:
            continue
        if directory_count >= max_directories:
            _inventory_marker(
                inventory,
                component_path,
                "capability_directory_limit_exceeded",
                "the Skill component exceeded its bounded directory inventory limit",
            )
            break
        directory_count += 1
        visited_directories.add(current_resolved)
        directory_entry_limit_reached = False
        try:
            with os.scandir(current) as iterator:
                entries = []
                for entry in iterator:
                    if entry_count + len(entries) >= max_entries:
                        directory_entry_limit_reached = True
                        break
                    entries.append(entry)
        except OSError:
            current_path = _relative_plugin_path(root, current) or component_path
            marker = f"{current_path}/<unreadable>"
            inventory.file_reviews.append(
                AgentPluginCapabilityFileReview(
                    path=marker,
                    status=_FILE_UNREADABLE,
                    reason="directory_unreadable",
                )
            )
            inventory.diagnostics.append(
                _diagnostic(
                    "capability_directory_unreadable",
                    "a Skill directory could not be listed safely",
                    current_path,
                )
            )
            inventory.complete = False
            continue

        for entry in entries:
            entry_count += 1
            candidate_path = Path(entry.path)
            relative = _relative_plugin_path(root, candidate_path)
            if relative is None:
                _inventory_marker(
                    inventory,
                    component_path,
                    "capability_path_unavailable",
                    "a Skill file path could not be represented relative to the plugin",
                )
                pending.clear()
                break

            if entry.name in EXCLUDED_DIRS:
                inventory.file_reviews.append(
                    AgentPluginCapabilityFileReview(
                        path=f"{relative}/<excluded>",
                        status=_FILE_UNSUPPORTED,
                        reason="excluded_directory_not_analyzed",
                    )
                )
                inventory.diagnostics.append(
                    _diagnostic(
                        "capability_surface_unsupported",
                        "an excluded Skill directory was not capability-analyzed",
                        relative,
                    )
                )
                inventory.complete = False
                continue

            try:
                is_directory = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
                is_symlink = entry.is_symlink()
            except OSError:
                inventory.file_reviews.append(
                    AgentPluginCapabilityFileReview(
                        path=relative,
                        status=_FILE_UNREADABLE,
                        reason="file_type_unreadable",
                    )
                )
                inventory.diagnostics.append(
                    _diagnostic(
                        "capability_file_unreadable",
                        "a Skill file could not be inspected safely",
                        relative,
                    )
                )
                inventory.complete = False
                continue

            if is_directory:
                pending.append(candidate_path)
                pending.sort(key=lambda item: _relative_plugin_path(root, item) or "")
                continue

            read_path = candidate_path
            if is_symlink:
                try:
                    read_path = candidate_path.resolve()
                except (OSError, RuntimeError):
                    read_path = candidate_path
                if read_path.is_dir():
                    inventory.file_reviews.append(
                        AgentPluginCapabilityFileReview(
                            path=relative,
                            status=_FILE_UNSUPPORTED,
                            reason="symlink_directory_not_followed",
                        )
                    )
                    inventory.diagnostics.append(
                        _diagnostic(
                            "capability_surface_unsupported",
                            "a symlinked Skill directory was not followed during bounded review",
                            relative,
                        )
                    )
                    inventory.complete = False
                    continue
                is_file = read_path.is_file()

            if not is_file:
                inventory.file_reviews.append(
                    AgentPluginCapabilityFileReview(
                        path=relative,
                        status=_FILE_UNSUPPORTED,
                        reason="non_regular_file",
                        size_bytes=_safe_file_size(read_path),
                    )
                )
                inventory.diagnostics.append(
                    _diagnostic(
                        "capability_surface_unsupported",
                        "a non-regular Skill surface was not capability-analyzed",
                        relative,
                    )
                )
                inventory.complete = False
                continue

            file_count += 1
            if file_count > max_files:
                inventory.file_reviews.append(
                    AgentPluginCapabilityFileReview(
                        path=relative,
                        status=_FILE_LIMIT_EXCEEDED,
                        reason="max_files_per_component",
                        size_bytes=_safe_file_size(read_path),
                    )
                )
                inventory.diagnostics.append(
                    _diagnostic(
                        "capability_file_limit_exceeded",
                        "the Skill component exceeded its bounded file-count limit",
                        relative,
                    )
                )
                inventory.complete = False
                pending.clear()
                break

            if not _path_is_within(read_path, component_resolved) or not _path_is_within(
                read_path, root_resolved
            ):
                inventory.file_reviews.append(
                    AgentPluginCapabilityFileReview(
                        path=relative,
                        status=_FILE_UNSUPPORTED,
                        reason="outside_component_boundary",
                        size_bytes=_safe_file_size(read_path),
                    )
                )
                inventory.diagnostics.append(
                    _diagnostic(
                        "capability_surface_outside_component",
                        "a Skill file resolves outside its component boundary",
                        relative,
                    )
                )
                inventory.complete = False
                continue

            if _is_capability_text_file(candidate_path):
                inventory.candidates.append(
                    _CapabilityFileCandidate(path=relative, read_path=read_path)
                )
            else:
                inventory.file_reviews.append(
                    AgentPluginCapabilityFileReview(
                        path=relative,
                        status=_FILE_UNSUPPORTED,
                        reason="unsupported_file_type",
                        size_bytes=_safe_file_size(read_path),
                    )
                )
                inventory.diagnostics.append(
                    _diagnostic(
                        "capability_surface_unsupported",
                        "the Skill file type is outside the bounded capability analyzer",
                        relative,
                    )
                )
                inventory.complete = False

        if directory_entry_limit_reached:
            _inventory_marker(
                inventory,
                component_path,
                "capability_entry_limit_exceeded",
                "the Skill component exceeded its bounded entry inventory limit",
            )
            pending.clear()

    inventory.candidates.sort(key=lambda item: item.path)
    inventory.file_reviews.sort(key=lambda item: item.path)
    return inventory


def _analyze_file_content(file: FileContent) -> list[Capability]:
    """Apply the existing static rules without performing any file I/O."""
    capabilities: list[Capability] = []
    for rule in DEFAULT_RULES:
        capabilities.extend(rule.analyze(file).capabilities)
    return unique_capabilities(capabilities)


def _read_and_analyze_candidate(
    candidate: _CapabilityFileCandidate,
    *,
    bytes_read: int,
    limits: AgentPluginCapabilityLimits,
) -> tuple[
    AgentPluginCapabilityFileReview,
    int,
    tuple[Capability, ...],
    AgentPluginDiagnostic | None,
    str | None,
]:
    size_bytes = _safe_file_size(candidate.read_path)
    if size_bytes is None:
        return (
            AgentPluginCapabilityFileReview(
                candidate.path,
                _FILE_UNREADABLE,
                "file_unreadable",
            ),
            bytes_read,
            (),
            _diagnostic(
                "capability_file_unreadable",
                "a Skill capability file could not be read safely",
                candidate.path,
            ),
            None,
        )

    max_file_bytes = max(limits.max_file_bytes, 0)
    max_total_bytes = max(limits.max_total_bytes_per_component, 0)
    remaining_bytes = max_total_bytes - bytes_read
    if size_bytes > max_file_bytes:
        return (
            AgentPluginCapabilityFileReview(
                candidate.path,
                _FILE_LIMIT_EXCEEDED,
                "max_file_bytes",
                size_bytes,
            ),
            bytes_read,
            (),
            _diagnostic(
                "capability_file_limit_exceeded",
                "a Skill capability file exceeds the bounded per-file byte limit",
                candidate.path,
            ),
            None,
        )
    if size_bytes > remaining_bytes:
        return (
            AgentPluginCapabilityFileReview(
                candidate.path,
                _FILE_LIMIT_EXCEEDED,
                "max_total_bytes_per_component",
                size_bytes,
            ),
            bytes_read,
            (),
            _diagnostic(
                "capability_total_bytes_limit_exceeded",
                "the Skill component exceeded its bounded cumulative byte limit",
                candidate.path,
            ),
            None,
        )

    read_limit = min(size_bytes + 1, max_file_bytes + 1, max(remaining_bytes, 0))
    try:
        with candidate.read_path.open("rb", buffering=0) as stream:
            data = stream.read(read_limit)
    except OSError:
        return (
            AgentPluginCapabilityFileReview(
                candidate.path,
                _FILE_UNREADABLE,
                "file_unreadable",
                size_bytes,
            ),
            bytes_read,
            (),
            _diagnostic(
                "capability_file_unreadable",
                "a Skill capability file could not be read safely",
                candidate.path,
            ),
            None,
        )

    consumed = len(data)
    next_bytes_read = bytes_read + consumed
    if len(data) != size_bytes:
        return (
            AgentPluginCapabilityFileReview(
                candidate.path,
                _FILE_UNREADABLE,
                "file_changed_during_read",
                size_bytes,
            ),
            next_bytes_read,
            (),
            _diagnostic(
                "capability_file_changed_during_read",
                "a capability file changed while it was being boundedly read",
                candidate.path,
            ),
            None,
        )

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return (
            AgentPluginCapabilityFileReview(
                candidate.path,
                _FILE_UNSUPPORTED,
                "binary_not_utf8",
                size_bytes,
            ),
            next_bytes_read,
            (),
            _diagnostic(
                "capability_surface_unsupported",
                "a binary or non-UTF-8 capability surface was not decoded",
                candidate.path,
            ),
            None,
        )

    file = FileContent(
        path=candidate.path,
        file_type=classify_file(Path(candidate.path)),
        text=text,
    )
    try:
        capabilities = tuple(_analyze_file_content(file))
    except Exception:
        return (
            AgentPluginCapabilityFileReview(
                candidate.path,
                _FILE_SCAN_FAILED,
                "rule_analysis_failed",
                size_bytes,
            ),
            next_bytes_read,
            (),
            _diagnostic(
                "capability_scan_failed",
                "existing capability rules failed for a component file",
                candidate.path,
            ),
            None,
        )
    return (
        AgentPluginCapabilityFileReview(candidate.path, _FILE_SCANNED, size_bytes=size_bytes),
        next_bytes_read,
        capabilities,
        None,
        text,
    )


def _source_within_component(source_file: str, component_path: str) -> bool:
    if not source_file or source_file.startswith("/") or source_file.startswith("<"):
        return False
    source_parts = PurePosixPath(source_file).parts
    component_parts = PurePosixPath(component_path).parts
    if ".." in source_parts:
        return False
    return source_parts[: len(component_parts)] == component_parts


def _scan_bounded_candidates(
    candidates: Iterable[_CapabilityFileCandidate],
    *,
    component_path: str,
    limits: AgentPluginCapabilityLimits,
    initial_file_reviews: Iterable[AgentPluginCapabilityFileReview] = (),
    initial_diagnostics: Iterable[AgentPluginDiagnostic] = (),
    initial_complete: bool = True,
    enforce_source_containment: bool = False,
) -> _BoundedScanResult:
    file_reviews = list(initial_file_reviews)
    diagnostics = list(initial_diagnostics)
    capabilities: list[Capability] = []
    scanned_files: set[str] = set()
    text_by_path: list[tuple[str, str]] = []
    bytes_read = 0

    for candidate in candidates:
        file_review, bytes_read, file_capabilities, diagnostic, text = _read_and_analyze_candidate(
            candidate,
            bytes_read=bytes_read,
            limits=limits,
        )
        file_reviews.append(file_review)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
        if file_review.status == _FILE_SCANNED:
            scanned_files.add(candidate.path)
            if text is not None:
                text_by_path.append((candidate.path, text))
            capabilities.extend(file_capabilities)

    filtered_capabilities: list[Capability] = []
    for capability in unique_capabilities(capabilities):
        if enforce_source_containment:
            if not _source_within_component(capability.source_file, component_path):
                diagnostics.append(
                    _diagnostic(
                        "capability_source_outside_component",
                        "capability evidence was excluded because its source is outside "
                        "the Skill component",
                        capability.source_file,
                    )
                )
                continue
            if capability.source_file not in scanned_files:
                diagnostics.append(
                    _diagnostic(
                        "capability_source_not_scanned",
                        "capability evidence was excluded because its source file was not scanned",
                        capability.source_file,
                    )
                )
                continue
        filtered_capabilities.append(capability)

    file_reviews.sort(key=lambda item: item.path)
    complete = (
        initial_complete
        and not diagnostics
        and all(item.status in {_FILE_SCANNED, _FILE_NOT_APPLICABLE} for item in file_reviews)
    )
    return _BoundedScanResult(
        status=_REVIEWED if complete else _INCOMPLETE,
        scanned_files=tuple(sorted(scanned_files)),
        file_reviews=tuple(file_reviews),
        capabilities=tuple(sorted(filtered_capabilities, key=_capability_key)),
        diagnostics=_dedupe_diagnostics(diagnostics),
        bytes_read=bytes_read,
        text_by_path=tuple(sorted(text_by_path)),
    )


def _is_mcp_app_mime(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    return normalized in {item.lower() for item in MCP_APP_UI_MIME_VALUES} or normalized.startswith(
        MCP_APP_UI_MIME_PREFIX.lower()
    )


def _associated_resource_uri(value: object, mime_type: object, key: str) -> str | None:
    if not isinstance(value, str):
        return None
    uri = value.strip()
    if not uri:
        return None
    if _is_mcp_app_mime(mime_type):
        return uri
    if key in {"resourceUri", "resource_uri"} and uri.startswith(
        ("ui://", "file://", "./", "../", "/")
    ):
        return uri
    if key == "uri" and uri.startswith("ui://"):
        return uri
    return None


def _skill_associated_resources(
    source_file: str,
    text: str,
) -> tuple[_SkillAssociatedResource, ...]:
    declarations: list[_SkillAssociatedResource] = []
    seen_uris: set[str] = set()

    try:
        inventory = inventory_from_json_text(text, declaration_path=source_file, scope="skill")
    except Exception:
        inventory = None
    if inventory is not None:
        for resource in inventory.resources:
            if resource.resource_uri in seen_uris:
                continue
            seen_uris.add(resource.resource_uri)
            declarations.append(
                _SkillAssociatedResource(
                    source_file=source_file,
                    declaration_path=resource.declaration_path,
                    uri=resource.resource_uri,
                )
            )

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return tuple(declarations)

    def walk(value: object, path: str) -> None:
        if isinstance(value, dict):
            mime_type = value.get("mimeType") or value.get("mime_type")
            for key in ("uri", "resourceUri", "resource_uri"):
                uri = _associated_resource_uri(value.get(key), mime_type, key)
                if uri is None or uri in seen_uris:
                    continue
                seen_uris.add(uri)
                declaration_path = f"{path}.{key}" if path else key
                declarations.append(
                    _SkillAssociatedResource(
                        source_file=source_file,
                        declaration_path=f"{source_file}.{declaration_path}",
                        uri=uri,
                    )
                )
            for key in sorted(value, key=str):
                child_path = f"{path}.{key}" if path else str(key)
                walk(value[key], child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                child_path = f"{path}.{index}" if path else str(index)
                walk(child, child_path)

    walk(data, "")
    return tuple(
        sorted(
            declarations,
            key=lambda item: (item.source_file, item.declaration_path, item.uri),
        )
    )


def _associated_resource_label(
    root: Path,
    candidate: Path | None,
    raw_uri: str,
    marker: str,
) -> str:
    if candidate is not None:
        try:
            relative = candidate.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, RuntimeError, ValueError):
            relative = None
        if relative:
            return relative
    clean_uri = raw_uri.split("#", 1)[0].split("?", 1)[0].replace("\\", "/")
    name = PurePosixPath(clean_uri).name or "resource"
    return f"<{marker}>/{name}"


def _resolve_skill_associated_resource(
    root: Path,
    component_root: Path,
    source_file: str,
    raw_uri: str,
) -> _SkillAssociatedResourceResolution:
    uri = raw_uri.strip()
    parsed = urlparse(uri)
    if parsed.scheme in {"http", "https"}:
        return _SkillAssociatedResourceResolution(
            label="<external_resource>",
            reason="associated_resource_external",
        )
    if parsed.scheme == "file":
        return _SkillAssociatedResourceResolution(
            label="<outside_plugin>/resource",
            reason="associated_resource_outside_plugin",
        )
    if parsed.scheme and parsed.scheme != "ui":
        return _SkillAssociatedResourceResolution(
            label="<unsupported_resource>",
            reason="associated_resource_unsupported",
        )
    if uri.startswith("/"):
        return _SkillAssociatedResourceResolution(
            label="<outside_plugin>/resource",
            reason="associated_resource_outside_plugin",
        )

    source_path = root / source_file
    candidates: list[Path]
    is_ui_uri = parsed.scheme == "ui"
    if is_ui_uri:
        combined = "/".join(part for part in [parsed.netloc, parsed.path.lstrip("/")] if part)
        if not combined:
            return _SkillAssociatedResourceResolution(
                label="<unsupported_resource>",
                reason="associated_resource_unsupported",
            )
        candidates = [root / combined]
        component_candidate = component_root / combined
        if component_candidate != candidates[0]:
            candidates.append(component_candidate)
    else:
        clean_uri = uri.split("#", 1)[0].split("?", 1)[0].replace("\\", "/")
        if not clean_uri:
            return _SkillAssociatedResourceResolution(
                label="<unsupported_resource>",
                reason="associated_resource_unsupported",
            )
        candidates = [source_path.parent / clean_uri, root / clean_uri]

    selected: Path | None = None
    for candidate in candidates:
        try:
            if candidate.exists():
                selected = candidate
                break
        except OSError:
            continue
    if selected is None:
        selected = candidates[0]
        try:
            resolved = selected.resolve()
        except (OSError, RuntimeError):
            return _SkillAssociatedResourceResolution(
                label="<unsupported_resource>",
                reason="associated_resource_unsupported",
            )
        if not _path_is_within(resolved, root):
            reason = "associated_resource_outside_plugin"
            marker = "outside_plugin"
        elif not is_ui_uri and not _path_is_within(resolved, component_root):
            reason = "associated_resource_outside_component"
            marker = "outside_component"
        else:
            reason = "associated_resource_missing"
            marker = "missing_resource"
        return _SkillAssociatedResourceResolution(
            label=_associated_resource_label(root, selected, uri, marker),
            reason=reason,
        )

    try:
        resolved = selected.resolve()
    except (OSError, RuntimeError):
        return _SkillAssociatedResourceResolution(
            label="<unsupported_resource>",
            reason="associated_resource_unsupported",
        )
    label = _associated_resource_label(root, selected, uri, "outside_plugin")
    if not _path_is_within(resolved, root):
        return _SkillAssociatedResourceResolution(
            label=label,
            reason="associated_resource_outside_plugin",
        )
    if not _path_is_within(resolved, component_root):
        return _SkillAssociatedResourceResolution(
            label=label,
            reason="associated_resource_outside_component",
        )
    relative = _associated_resource_label(root, selected, uri, "unsupported_resource")
    try:
        supported = selected.is_file() and _is_capability_text_file(selected)
    except OSError:
        supported = False
    if any(part in EXCLUDED_DIRS for part in PurePosixPath(relative).parts) or not supported:
        return _SkillAssociatedResourceResolution(
            label=relative,
            reason="associated_resource_unsupported",
            target_path=relative,
        )
    return _SkillAssociatedResourceResolution(label=relative, reason=None, target_path=relative)


def _associated_reason_for_file_review(status: str) -> str:
    return {
        _FILE_LIMIT_EXCEEDED: "associated_resource_limit_exceeded",
        _FILE_UNREADABLE: "associated_resource_unreadable",
        _FILE_SCAN_FAILED: "associated_resource_scan_failed",
    }.get(status, "associated_resource_unsupported")


def _account_skill_associated_resources(
    root: Path,
    component_root: Path,
    result: _BoundedScanResult,
) -> _BoundedScanResult:
    declarations = [
        declaration
        for source_file, text in result.text_by_path
        if Path(source_file).suffix.lower() == ".json"
        for declaration in _skill_associated_resources(source_file, text)
    ]
    if not declarations:
        return result

    file_reviews = {item.path: item for item in result.file_reviews}
    diagnostics = list(result.diagnostics)
    changed = False
    for declaration in declarations:
        resolution = _resolve_skill_associated_resource(
            root,
            component_root,
            declaration.source_file,
            declaration.uri,
        )
        if resolution.reason is None and resolution.target_path in result.scanned_files:
            continue

        path = resolution.target_path or resolution.label
        existing = file_reviews.get(path)
        if existing is not None and existing.status == _FILE_SCANNED:
            continue
        if existing is not None:
            reason = _associated_reason_for_file_review(existing.status)
            file_reviews[path] = AgentPluginCapabilityFileReview(
                path=existing.path,
                status=existing.status,
                reason=reason,
                size_bytes=existing.size_bytes,
            )
        else:
            reason = resolution.reason or "associated_resource_unreviewed"
            file_reviews[path] = AgentPluginCapabilityFileReview(
                path=path,
                status=_FILE_UNSUPPORTED,
                reason=reason,
            )
        diagnostics.append(
            _diagnostic(
                reason,
                f"{declaration.declaration_path} declares associated resource {path}; "
                "the resource was not analyzed within the Skill capability boundary",
                declaration.source_file,
            )
        )
        changed = True

    if not changed:
        return result
    return _BoundedScanResult(
        status=_INCOMPLETE,
        scanned_files=result.scanned_files,
        file_reviews=tuple(sorted(file_reviews.values(), key=lambda item: item.path)),
        capabilities=result.capabilities,
        diagnostics=_dedupe_diagnostics(diagnostics),
        bytes_read=result.bytes_read,
        text_by_path=result.text_by_path,
    )


def _structural_diagnostics_for_path(
    diagnostics: tuple[AgentPluginDiagnostic, ...], path: str
) -> list[AgentPluginDiagnostic]:
    return [item for item in diagnostics if item.path == path]


def _not_reviewed_component(
    *,
    component_kind: str,
    component_id: str,
    component_path: str,
    structural_status: str,
    structural_diagnostics: list[AgentPluginDiagnostic],
) -> AgentPluginComponentCapabilityReview:
    scan_status = {
        "invalid": _INVALID,
        "skipped": _SKIPPED,
    }.get(structural_status, _INCOMPLETE)
    diagnostics = [*structural_diagnostics]
    diagnostics.append(
        _diagnostic(
            "capability_scan_not_attempted",
            "capability scanning was not attempted for this structurally unavailable component",
            component_path,
        )
    )
    return AgentPluginComponentCapabilityReview(
        component_kind=component_kind,
        component_id=component_id,
        component_path=component_path,
        structural_status=structural_status,
        capability_scan_status=scan_status,
        diagnostics=_sorted_diagnostics(diagnostics),
    )


def _scan_skill(
    root: Path,
    skill: AgentPluginSkill,
    limits: AgentPluginCapabilityLimits,
) -> AgentPluginComponentCapabilityReview:
    component_id = _skill_component_id(skill)
    component_path = _skill_component_path(skill)
    component_root = root / Path(skill.path).parent
    try:
        resolved_component_root = component_root.resolve()
        resolved_component_root.relative_to(root.resolve())
    except Exception:
        return AgentPluginComponentCapabilityReview(
            component_kind="skill",
            component_id=component_id,
            component_path=component_path,
            structural_status=skill.status,
            capability_scan_status=_INCOMPLETE,
            diagnostics=(
                _diagnostic(
                    "capability_discovery_failed",
                    "skill capability file discovery failed",
                    component_path,
                ),
            ),
        )

    inventory = _inventory_skill_files(
        root,
        component_root,
        component_path,
        limits,
    )
    result = _scan_bounded_candidates(
        inventory.candidates,
        component_path=component_path,
        limits=limits,
        initial_file_reviews=inventory.file_reviews,
        initial_diagnostics=inventory.diagnostics,
        initial_complete=inventory.complete,
        enforce_source_containment=True,
    )
    result = _account_skill_associated_resources(root, resolved_component_root, result)
    return AgentPluginComponentCapabilityReview(
        component_kind="skill",
        component_id=component_id,
        component_path=component_path,
        structural_status=skill.status,
        capability_scan_status=result.status,
        scanned_files=result.scanned_files,
        file_reviews=result.file_reviews,
        capabilities=result.capabilities,
        diagnostics=result.diagnostics,
    )


def _skill_reviews(
    root: Path,
    inventory: AgentPluginInventory,
    limits: AgentPluginCapabilityLimits,
) -> list[AgentPluginComponentCapabilityReview]:
    reviews: list[AgentPluginComponentCapabilityReview] = []
    if inventory.skills_status != "absent" and inventory.skills_status != "valid":
        reviews.append(
            _not_reviewed_component(
                component_kind="skills",
                component_id="skills",
                component_path="skills",
                structural_status=inventory.skills_status,
                structural_diagnostics=_structural_diagnostics_for_path(
                    inventory.diagnostics, "skills"
                ),
            )
        )
    for skill in inventory.skills:
        if skill.status == "valid" and skill.conformant:
            reviews.append(_scan_skill(root, skill, limits))
        else:
            reviews.append(
                _not_reviewed_component(
                    component_kind="skill",
                    component_id=_skill_component_id(skill),
                    component_path=_skill_component_path(skill),
                    structural_status=skill.status,
                    structural_diagnostics=list(skill.diagnostics),
                )
            )
    return reviews


def _mcp_server_maps(
    servers: tuple[AgentPluginMcpServer, ...],
) -> tuple[
    dict[str, AgentPluginMcpServer],
    dict[str, AgentPluginMcpServer],
    dict[str, AgentPluginMcpServer],
]:
    by_config_path = {
        item.path.removeprefix("mcp.json."): item
        for item in servers
        if item.path.startswith("mcp.json.")
    }
    by_name = {item.name: item for item in servers}
    valid_by_config_path = {
        path: item for path, item in by_config_path.items() if item.status == "valid"
    }
    return by_config_path, by_name, valid_by_config_path


def _mcp_capability_owner(
    capability: Capability,
    *,
    by_config_path: dict[str, AgentPluginMcpServer],
    by_name: dict[str, AgentPluginMcpServer],
    valid_by_config_path: dict[str, AgentPluginMcpServer],
    invalid_server_present: bool,
) -> tuple[str | None, AgentPluginDiagnostic | None]:
    details = capability.details
    config_path = details.get("config_path")
    if isinstance(config_path, str):
        server = by_config_path.get(config_path)
        if server is None:
            return None, _diagnostic(
                "mcp_capability_unattributed",
                "MCP capability declaration path did not match a structural server",
                "mcp.json",
            )
        if config_path not in valid_by_config_path:
            return None, _diagnostic(
                "mcp_capability_excluded_invalid_server",
                "capability from an invalid MCP server was excluded",
                server.path,
            )
        return server.name, None

    scope = details.get("scope")
    if isinstance(scope, str) and scope.startswith("server:"):
        server = by_name.get(scope.removeprefix("server:"))
        if server is None:
            return None, _diagnostic(
                "mcp_capability_unattributed",
                "MCP capability server scope did not match a structural server",
                "mcp.json",
            )
        if server.status != "valid":
            return None, _diagnostic(
                "mcp_capability_excluded_invalid_server",
                "capability from an invalid MCP server was excluded",
                server.path,
            )
        return server.name, None

    if invalid_server_present and capability.type in {
        "mcp_app_asset",
        "mcp_app_host_bridge",
        "mcp_app_unknown_declaration",
    }:
        return None, _diagnostic(
            "mcp_capability_unattributed",
            "MCP asset capability could not be attributed while a server was invalid",
            "mcp.json",
        )
    return _ROOT_COMPONENT_ID, None


def _scan_mcp_component(
    root: Path,
    root_path: str,
    limits: AgentPluginCapabilityLimits,
) -> _BoundedScanResult:
    candidate = _CapabilityFileCandidate(path=root_path, read_path=root / root_path)
    result = _scan_bounded_candidates(
        [candidate],
        component_path=root_path,
        limits=limits,
    )
    text_by_path = dict(result.text_by_path)
    mcp_text = text_by_path.get(root_path)
    if mcp_text is None:
        return result

    diagnostics = list(result.diagnostics)
    file_reviews = {item.path: item for item in result.file_reviews}
    scanned_files = set(result.scanned_files)
    capabilities = list(result.capabilities)
    bytes_read = result.bytes_read
    try:
        asset_inventory = inventory_local_mcp_app_assets(
            root,
            {root / root_path},
            seed_texts={(root / root_path).resolve(): mcp_text},
            max_assets=max(limits.max_files_per_component - 1, 0),
            max_asset_bytes=max(limits.max_file_bytes, 0),
            max_total_asset_bytes=max(limits.max_total_bytes_per_component - bytes_read, 0),
        )
    except Exception:
        diagnostics.append(
            _diagnostic(
                "capability_asset_scan_failed",
                "MCP App asset capability inspection failed for the bounded MCP component",
                root_path,
            )
        )
        file_reviews[f"{root_path}/<mcp-app-assets>"] = AgentPluginCapabilityFileReview(
            path=f"{root_path}/<mcp-app-assets>",
            status=_FILE_SCAN_FAILED,
            reason="asset_inventory_failed",
        )
        return _BoundedScanResult(
            status=_INCOMPLETE,
            scanned_files=tuple(sorted(scanned_files)),
            file_reviews=tuple(sorted(file_reviews.values(), key=lambda item: item.path)),
            capabilities=tuple(sorted(unique_capabilities(capabilities), key=_capability_key)),
            diagnostics=_dedupe_diagnostics(diagnostics),
            bytes_read=bytes_read,
            text_by_path=result.text_by_path,
        )

    asset_status_rank = {
        _FILE_SCAN_FAILED: 4,
        _FILE_UNREADABLE: 3,
        _FILE_LIMIT_EXCEEDED: 2,
        _FILE_UNSUPPORTED: 1,
        _FILE_SCANNED: 0,
    }
    for asset in asset_inventory.assets:
        if asset.skipped_reason is None and asset.size_bytes is not None:
            status = _FILE_SCANNED
            scanned_files.add(asset.path)
            bytes_read += asset.size_bytes
            reason = None
        elif asset.skipped_reason in {
            "asset_too_large",
            "asset_total_limit_exceeded",
        }:
            status = _FILE_LIMIT_EXCEEDED
            reason = asset.skipped_reason
        elif asset.skipped_reason == "asset_not_utf8":
            status = _FILE_UNSUPPORTED
            reason = asset.skipped_reason
            if asset.size_bytes is not None:
                bytes_read += asset.size_bytes
        else:
            status = _FILE_UNREADABLE
            reason = asset.skipped_reason or "asset_unreviewed"
        candidate_review = AgentPluginCapabilityFileReview(
            path=asset.path,
            status=status,
            reason=reason,
            size_bytes=asset.size_bytes,
        )
        existing = file_reviews.get(asset.path)
        if existing is None or asset_status_rank[status] > asset_status_rank[existing.status]:
            file_reviews[asset.path] = candidate_review
        if status != _FILE_SCANNED:
            code = (
                "capability_file_limit_exceeded"
                if status == _FILE_LIMIT_EXCEEDED
                else "capability_surface_unsupported"
                if status == _FILE_UNSUPPORTED
                else "capability_asset_unreviewed"
            )
            diagnostics.append(
                _diagnostic(
                    code,
                    "an MCP App asset was not completely capability-analyzed",
                    asset.path,
                )
            )

    if asset_inventory.limit_reached:
        marker = f"{root_path}/<mcp-app-assets>"
        file_reviews[marker] = AgentPluginCapabilityFileReview(
            path=marker,
            status=_FILE_LIMIT_EXCEEDED,
            reason="max_files_per_component",
        )
        diagnostics.append(
            _diagnostic(
                "capability_file_limit_exceeded",
                "the MCP component exceeded its bounded asset-count limit",
                marker,
            )
        )

    capabilities.extend(mcp_app_asset_capabilities(asset_inventory))
    complete = not diagnostics and all(
        item.status in {_FILE_SCANNED, _FILE_NOT_APPLICABLE} for item in file_reviews.values()
    )
    return _BoundedScanResult(
        status=_REVIEWED if complete else _INCOMPLETE,
        scanned_files=tuple(sorted(scanned_files)),
        file_reviews=tuple(sorted(file_reviews.values(), key=lambda item: item.path)),
        capabilities=tuple(sorted(unique_capabilities(capabilities), key=_capability_key)),
        diagnostics=_dedupe_diagnostics(diagnostics),
        bytes_read=bytes_read,
        text_by_path=result.text_by_path,
    )


def _mcp_reviews(
    root: Path,
    inventory: AgentPluginInventory,
    limits: AgentPluginCapabilityLimits,
) -> list[AgentPluginComponentCapabilityReview]:
    mcp = inventory.mcp
    if mcp.status == "absent":
        return []
    root_path = mcp.path
    if mcp.status != "valid":
        return [
            _not_reviewed_component(
                component_kind="mcp",
                component_id=_ROOT_COMPONENT_ID,
                component_path=root_path,
                structural_status=mcp.status,
                structural_diagnostics=list(mcp.diagnostics),
            )
        ]

    scan = _scan_mcp_component(root, root_path, limits)
    status = scan.status
    scanned_files = scan.scanned_files
    capabilities = scan.capabilities
    scan_diagnostics = scan.diagnostics
    by_config_path, by_name, valid_by_config_path = _mcp_server_maps(mcp.servers)
    invalid_server_present = any(item.status != "valid" for item in mcp.servers)
    root_capabilities: list[Capability] = []
    server_capabilities: dict[str, list[Capability]] = {item.name: [] for item in mcp.servers}
    root_attribution_diagnostics: list[AgentPluginDiagnostic] = []
    server_attribution_diagnostics: dict[str, list[AgentPluginDiagnostic]] = {
        item.name: [] for item in mcp.servers
    }
    for capability in capabilities:
        owner, diagnostic = _mcp_capability_owner(
            capability,
            by_config_path=by_config_path,
            by_name=by_name,
            valid_by_config_path=valid_by_config_path,
            invalid_server_present=invalid_server_present,
        )
        if diagnostic is not None:
            matching_server = next(
                (item for item in mcp.servers if item.path == diagnostic.path),
                None,
            )
            if matching_server is None:
                root_attribution_diagnostics.append(diagnostic)
            else:
                server_attribution_diagnostics[matching_server.name].append(diagnostic)
        if owner == _ROOT_COMPONENT_ID:
            root_capabilities.append(capability)
        elif owner in server_capabilities:
            server_capabilities[owner].append(capability)

    root_status = (
        _REVIEWED if status == _REVIEWED and not root_attribution_diagnostics else _INCOMPLETE
    )
    reviews = [
        AgentPluginComponentCapabilityReview(
            component_kind="mcp",
            component_id=_ROOT_COMPONENT_ID,
            component_path=root_path,
            structural_status=mcp.status,
            capability_scan_status=root_status,
            scanned_files=scanned_files,
            file_reviews=scan.file_reviews,
            capabilities=tuple(sorted(root_capabilities, key=_capability_key)),
            diagnostics=_dedupe_diagnostics([*scan_diagnostics, *root_attribution_diagnostics]),
        )
    ]
    for server in mcp.servers:
        if server.status != "valid":
            server_diagnostics = [
                *server.diagnostics,
                *server_attribution_diagnostics[server.name],
            ]
            reviews.append(
                _not_reviewed_component(
                    component_kind="mcp_server",
                    component_id=server.name,
                    component_path=server.path,
                    structural_status=server.status,
                    structural_diagnostics=server_diagnostics,
                )
            )
            continue
        server_diagnostics = [
            *scan_diagnostics,
            *server_attribution_diagnostics[server.name],
        ]
        reviews.append(
            AgentPluginComponentCapabilityReview(
                component_kind="mcp_server",
                component_id=server.name,
                component_path=server.path,
                structural_status=server.status,
                capability_scan_status=status if not server_diagnostics else _INCOMPLETE,
                scanned_files=scanned_files,
                file_reviews=scan.file_reviews,
                capabilities=tuple(sorted(server_capabilities[server.name], key=_capability_key)),
                diagnostics=_dedupe_diagnostics(server_diagnostics),
            )
        )
    return reviews


def _package_blind_spots(
    inventory: AgentPluginInventory,
) -> list[AgentPluginCapabilityBlindSpot]:
    spots: list[AgentPluginCapabilityBlindSpot] = []
    for extension in inventory.extensions:
        spots.append(
            AgentPluginCapabilityBlindSpot(
                component_kind="client_extension",
                component_id=extension.namespace,
                component_path=extension.namespace,
                reason="client_extension_unimplemented",
            )
        )

    represented_paths = {item.path for item in inventory.package_surfaces}
    represented_paths.update(item.namespace for item in inventory.extensions)
    for surface in inventory.package_surfaces:
        if surface.kind == "client_extension":
            reason = "client_extension_unimplemented"
            kind = "client_extension"
        elif surface.kind == "discovery_limit":
            reason = "package_discovery_incomplete"
            kind = "package_surface"
        elif surface.kind in {"unknown_package_file", "unknown_package_directory"}:
            reason = "unknown_package_surface"
            kind = "package_surface"
        else:
            continue
        spots.append(
            AgentPluginCapabilityBlindSpot(
                component_kind=kind,
                component_id=surface.path,
                component_path=surface.path,
                reason=reason,
            )
        )
    for path in inventory.unknown_surfaces:
        if path in represented_paths:
            continue
        spots.append(
            AgentPluginCapabilityBlindSpot(
                component_kind="package_surface",
                component_id=path,
                component_path=path,
                reason="unknown_package_surface",
            )
        )
    return spots


def _component_blind_spots(
    components: list[AgentPluginComponentCapabilityReview],
) -> list[AgentPluginCapabilityBlindSpot]:
    spots: list[AgentPluginCapabilityBlindSpot] = []
    for component in components:
        if component.capability_scan_status == _REVIEWED:
            continue
        if component.capability_scan_status in {_INVALID, _SKIPPED}:
            reason = "structural_component_not_reviewed"
        else:
            reason = "capability_scan_incomplete"
        spots.append(
            AgentPluginCapabilityBlindSpot(
                component_kind=component.component_kind,
                component_id=component.component_id,
                component_path=component.component_path,
                reason=reason,
            )
        )
    return spots


def _file_blind_spots(
    components: list[AgentPluginComponentCapabilityReview],
) -> list[AgentPluginCapabilityBlindSpot]:
    reason_by_status = {
        _FILE_UNSUPPORTED: "capability_surface_unsupported",
        _FILE_LIMIT_EXCEEDED: "capability_file_limit_exceeded",
        _FILE_UNREADABLE: "capability_file_unreadable",
        _FILE_SCAN_FAILED: "capability_scan_failed",
    }
    spots: list[AgentPluginCapabilityBlindSpot] = []
    for component in components:
        for file_review in component.file_reviews:
            if file_review.status in {_FILE_SCANNED, _FILE_NOT_APPLICABLE}:
                continue
            if file_review.reason and file_review.reason.startswith("associated_resource_"):
                reason = file_review.reason
            else:
                reason = reason_by_status.get(
                    file_review.status,
                    file_review.reason or "capability_surface_unreviewed",
                )
            spots.append(
                AgentPluginCapabilityBlindSpot(
                    component_kind=f"{component.component_kind}_file",
                    component_id=file_review.path,
                    component_path=file_review.path,
                    reason=reason,
                )
            )
    return spots


def _dedupe_blind_spots(
    spots: list[AgentPluginCapabilityBlindSpot],
) -> tuple[AgentPluginCapabilityBlindSpot, ...]:
    unique = {
        (item.component_kind, item.component_id, item.component_path, item.reason): item
        for item in spots
    }
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                item.component_kind,
                item.component_id,
                item.component_path,
                item.reason,
            ),
        )
    )


def _aggregate_capabilities(
    components: list[AgentPluginComponentCapabilityReview],
) -> tuple[AgentPluginObservedCapability, ...]:
    grouped: dict[tuple[str, str, str], list[AgentPluginCapabilityEvidence]] = {}
    for component in components:
        for capability in component.capabilities:
            evidence = AgentPluginCapabilityEvidence(
                component_kind=component.component_kind,
                component_id=component.component_id,
                component_path=component.component_path,
                source_file=capability.source_file,
                source_line=capability.source_line,
                original_capability=capability,
            )
            grouped.setdefault(_capability_key(capability), []).append(evidence)

    observed: list[AgentPluginObservedCapability] = []
    for key in sorted(grouped):
        evidence = tuple(sorted(grouped[key], key=_evidence_key))
        representative = evidence[0].original_capability.model_dump(mode="json")
        observed.append(
            AgentPluginObservedCapability(
                type=str(representative["type"]),
                resource=representative.get("resource"),
                details=dict(representative.get("details", {})),
                evidence=evidence,
            )
        )
    return tuple(observed)


def _plugin_identity(inventory: AgentPluginInventory) -> dict[str, object]:
    return {
        "format": inventory.format,
        "spec_version": inventory.spec_version,
        "name": inventory.manifest.name,
        "version": inventory.manifest.version,
        "manifest_path": inventory.manifest.path,
    }


def review_agent_plugin_capabilities(
    path: Path | str,
    *,
    inventory: AgentPluginInventory | None = None,
    limits: AgentPluginLimits = DEFAULT_AGENT_PLUGIN_LIMITS,
    capability_limits: AgentPluginCapabilityLimits = DEFAULT_AGENT_PLUGIN_CAPABILITY_LIMITS,
) -> AgentPluginCapabilityReview:
    """Review observed static capabilities without executing plugin code."""
    root = Path(path).expanduser().resolve()
    inventory = inventory or load_agent_plugin(root, limits=limits)
    if inventory.status != "loaded":
        components: list[AgentPluginComponentCapabilityReview] = []
        blind_spots = [
            AgentPluginCapabilityBlindSpot(
                component_kind="plugin",
                component_id="plugin",
                component_path=".",
                reason="structural_plugin_rejected",
            )
        ]
    else:
        components = _skill_reviews(root, inventory, capability_limits)
        components.extend(_mcp_reviews(root, inventory, capability_limits))
        blind_spots = _component_blind_spots(components)
        blind_spots.extend(_file_blind_spots(components))
        blind_spots.extend(_package_blind_spots(inventory))

    components = sorted(components, key=_component_key)
    blind_spots_data = _dedupe_blind_spots(blind_spots)
    component_review_complete = all(item.capability_scan_status == _REVIEWED for item in components)
    portable_complete = (
        inventory.status == "loaded"
        and inventory.coverage.portable_core == "COMPLETE"
        and component_review_complete
    )
    capability_coverage = AgentPluginCapabilityCoverage(
        portable_core="COMPLETE" if portable_complete else "INCOMPLETE",
        overall_artifact=(
            "COMPLETE" if portable_complete and not blind_spots_data else "INCOMPLETE"
        ),
    )
    diagnostics = list(inventory.diagnostics)
    diagnostics.extend(diagnostic for item in components for diagnostic in item.diagnostics)
    return AgentPluginCapabilityReview(
        plugin_identity=_plugin_identity(inventory),
        status="reviewed" if inventory.status == "loaded" else "rejected",
        structural_coverage=inventory.coverage,
        capability_coverage=capability_coverage,
        components=tuple(components),
        observed_capabilities=_aggregate_capabilities(components),
        unknown_surfaces=tuple(inventory.unknown_surfaces),
        blind_spots=blind_spots_data,
        diagnostics=_dedupe_diagnostics(diagnostics),
    )


def agent_plugin_capabilities_to_data(
    review: AgentPluginCapabilityReview,
) -> dict[str, object]:
    """Return deterministic internal data for tests and future adapters."""
    return review.to_data()


inspect_agent_plugin_capabilities = review_agent_plugin_capabilities
