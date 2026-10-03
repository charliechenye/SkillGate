"""Internal content, capability, and coverage drift for Agent Plugins.

This module is deliberately separate from the repository baseline and policy
models.  It compares two in-memory reviews of one Agent Plugin package and
does not create findings, approval decisions, or CLI output.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from skillgate.agent_plugin_capabilities import (
    DEFAULT_AGENT_PLUGIN_CAPABILITY_LIMITS,
    AgentPluginCapabilityBlindSpot,
    AgentPluginCapabilityCoverage,
    AgentPluginCapabilityFileReview,
    AgentPluginCapabilityLimits,
    AgentPluginCapabilityReview,
    AgentPluginObservedCapability,
    _capability_key,
    review_agent_plugin_capabilities,
)
from skillgate.agent_plugins import (
    DEFAULT_AGENT_PLUGIN_LIMITS,
    AgentPluginCoverage,
    AgentPluginDiagnostic,
    AgentPluginInventory,
    AgentPluginLimits,
    AgentPluginPackageSurface,
    load_agent_plugin,
)
from skillgate.models import Capability

AGENT_PLUGIN_DRIFT_FORMAT = "agent_plugin_drift"
AGENT_PLUGIN_DRIFT_SNAPSHOT_VERSION = "1"
AGENT_PLUGIN_DRIFT_TOOL_VERSION = "skillgate-agent-plugin-drift/0.2A"

DRIFT_CHANGED = "CHANGED"
DRIFT_UNCHANGED = "UNCHANGED"
DRIFT_UNKNOWN = "UNKNOWN"

_PORTABLE_COMPONENT_KINDS = frozenset({"manifest", "skill", "skills", "mcp", "mcp_server"})
_FIXED_PORTABLE_PATHS = frozenset({"plugin.json", "mcp.json", "skills"})
_UNSAFE_IDENTITY_REASONS = frozenset(
    {
        "file_changed_during_read",
        "file_unreadable",
        "read_error",
        "path_unavailable",
        "outside_component_boundary",
        "outside_plugin_boundary",
    }
)
_COVERAGE_DIAGNOSTIC_WORDS = frozenset(
    {
        "invalid",
        "incomplete",
        "limit",
        "outside",
        "skipped",
        "unknown",
        "unreadable",
        "unsupported",
    }
)


@dataclass(frozen=True)
class AgentPluginDriftFile:
    """One plugin-relative physical file identity in a drift snapshot."""

    path: str
    sha256: str | None = None
    size_bytes: int | None = None
    identity_complete: bool = False
    size_reliable: bool = False
    identity_skipped_reason: str | None = None
    owners: tuple[str, ...] = ()
    portable_core: bool = False

    def to_data(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "identity_complete": self.identity_complete,
            "size_reliable": self.size_reliable,
            "identity_skipped_reason": self.identity_skipped_reason,
            "owners": list(self.owners),
            "portable_core": self.portable_core,
        }


@dataclass(frozen=True)
class AgentPluginDriftMembership:
    """A component or package surface, intentionally independent of status."""

    component_kind: str
    component_id: str
    component_path: str
    portable_core: bool

    @property
    def key(self) -> tuple[str, str, str, bool]:
        return (
            self.component_kind,
            self.component_id,
            self.component_path,
            self.portable_core,
        )

    def to_data(self) -> dict[str, object]:
        return {
            "component_kind": self.component_kind,
            "component_id": self.component_id,
            "component_path": self.component_path,
            "portable_core": self.portable_core,
        }


@dataclass(frozen=True)
class AgentPluginDriftContentCoverage:
    """Completeness of physical content identity, separate from drift state."""

    portable_core: str
    overall_artifact: str
    incomplete_portable_paths: tuple[str, ...] = ()
    incomplete_overall_paths: tuple[str, ...] = ()

    def to_data(self) -> dict[str, object]:
        return {
            "portable_core": self.portable_core,
            "overall_artifact": self.overall_artifact,
            "incomplete_portable_paths": list(self.incomplete_portable_paths),
            "incomplete_overall_paths": list(self.incomplete_overall_paths),
        }


@dataclass(frozen=True)
class AgentPluginDriftCoverageState:
    """Coverage identity used by the coverage-drift comparison."""

    structural_portable_core: str
    structural_overall_artifact: str
    capability_portable_core: str
    capability_overall_artifact: str
    blind_spots: tuple[AgentPluginCapabilityBlindSpot, ...] = ()
    incomplete_components: tuple[tuple[str, str, str, str, str], ...] = ()
    incomplete_package_surfaces: tuple[tuple[str, str, str], ...] = ()
    diagnostic_states: tuple[tuple[str, str | None], ...] = ()

    @property
    def identity_key(self) -> tuple[object, ...]:
        return (
            self.structural_portable_core,
            self.structural_overall_artifact,
            self.capability_portable_core,
            self.capability_overall_artifact,
            tuple(
                (
                    item.component_kind,
                    item.component_id,
                    item.component_path,
                    item.reason,
                )
                for item in self.blind_spots
            ),
            self.incomplete_components,
            self.incomplete_package_surfaces,
            self.diagnostic_states,
        )

    def to_data(self) -> dict[str, object]:
        return {
            "structural": {
                "portable_core": self.structural_portable_core,
                "overall_artifact": self.structural_overall_artifact,
            },
            "capability": {
                "portable_core": self.capability_portable_core,
                "overall_artifact": self.capability_overall_artifact,
            },
            "blind_spots": [item.to_data() for item in self.blind_spots],
            "incomplete_components": [list(item) for item in self.incomplete_components],
            "incomplete_package_surfaces": [
                list(item) for item in self.incomplete_package_surfaces
            ],
            "diagnostic_states": [list(item) for item in self.diagnostic_states],
        }


@dataclass(frozen=True)
class AgentPluginDriftSnapshot:
    """Deterministic in-memory review state for one Agent Plugin package."""

    snapshot_format_version: str
    tool_version: str
    plugin_identity: dict[str, object]
    content_files: tuple[AgentPluginDriftFile, ...]
    component_membership: tuple[AgentPluginDriftMembership, ...]
    structural_coverage: AgentPluginCoverage
    capability_coverage: AgentPluginCapabilityCoverage
    content_identity_coverage: AgentPluginDriftContentCoverage
    coverage_state: AgentPluginDriftCoverageState
    observed_capabilities: tuple[AgentPluginObservedCapability, ...]
    diagnostics: tuple[AgentPluginDiagnostic, ...] = ()

    @property
    def files(self) -> tuple[AgentPluginDriftFile, ...]:
        """Convenience alias for callers that treat files as the identity set."""
        return self.content_files

    @property
    def coverage(self) -> AgentPluginDriftCoverageState:
        return self.coverage_state

    @property
    def blind_spots(self) -> tuple[AgentPluginCapabilityBlindSpot, ...]:
        return self.coverage_state.blind_spots

    def to_data(self) -> dict[str, object]:
        return {
            "format": AGENT_PLUGIN_DRIFT_FORMAT,
            "snapshot_format_version": self.snapshot_format_version,
            "tool_version": self.tool_version,
            "plugin_identity": dict(self.plugin_identity),
            "content_files": [item.to_data() for item in self.content_files],
            "component_membership": [item.to_data() for item in self.component_membership],
            "structural_coverage": self.structural_coverage.to_data(),
            "capability_coverage": self.capability_coverage.to_data(),
            "content_identity_coverage": self.content_identity_coverage.to_data(),
            "coverage_state": self.coverage_state.to_data(),
            "observed_capabilities": [item.to_data() for item in self.observed_capabilities],
            "diagnostics": [item.to_data() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class AgentPluginDriftFileChange:
    """A content change retaining both bounded identities and ownership."""

    change: str
    path: str
    before: AgentPluginDriftFile | None = None
    after: AgentPluginDriftFile | None = None

    def to_data(self) -> dict[str, object]:
        return {
            "change": self.change,
            "path": self.path,
            "before": None if self.before is None else self.before.to_data(),
            "after": None if self.after is None else self.after.to_data(),
        }


@dataclass(frozen=True)
class AgentPluginContentDrift:
    portable_core: str
    overall_artifact: str
    added_files: tuple[str, ...] = ()
    removed_files: tuple[str, ...] = ()
    modified_files: tuple[str, ...] = ()
    added_membership: tuple[AgentPluginDriftMembership, ...] = ()
    removed_membership: tuple[AgentPluginDriftMembership, ...] = ()
    identity_changed: bool = False
    incomplete_before_portable: tuple[str, ...] = ()
    incomplete_after_portable: tuple[str, ...] = ()
    incomplete_before_overall: tuple[str, ...] = ()
    incomplete_after_overall: tuple[str, ...] = ()
    file_changes: tuple[AgentPluginDriftFileChange, ...] = ()

    @property
    def state(self) -> str:
        """The aggregate state, with overall artifact scope as the default."""
        return self.overall_artifact

    def to_data(self) -> dict[str, object]:
        return {
            "portable_core": self.portable_core,
            "overall_artifact": self.overall_artifact,
            "added_files": list(self.added_files),
            "removed_files": list(self.removed_files),
            "modified_files": list(self.modified_files),
            "added_membership": [item.to_data() for item in self.added_membership],
            "removed_membership": [item.to_data() for item in self.removed_membership],
            "identity_changed": self.identity_changed,
            "incomplete_before_portable": list(self.incomplete_before_portable),
            "incomplete_after_portable": list(self.incomplete_after_portable),
            "incomplete_before_overall": list(self.incomplete_before_overall),
            "incomplete_after_overall": list(self.incomplete_after_overall),
            "file_changes": [item.to_data() for item in self.file_changes],
        }


@dataclass(frozen=True)
class AgentPluginCapabilityDrift:
    portable_core: str
    overall_artifact: str
    added_capabilities: tuple[AgentPluginObservedCapability, ...] = ()
    removed_capabilities: tuple[AgentPluginObservedCapability, ...] = ()

    @property
    def state(self) -> str:
        return self.overall_artifact

    @property
    def added(self) -> tuple[AgentPluginObservedCapability, ...]:
        return self.added_capabilities

    @property
    def removed(self) -> tuple[AgentPluginObservedCapability, ...]:
        return self.removed_capabilities

    def to_data(self) -> dict[str, object]:
        return {
            "portable_core": self.portable_core,
            "overall_artifact": self.overall_artifact,
            "added_capabilities": [item.to_data() for item in self.added_capabilities],
            "removed_capabilities": [item.to_data() for item in self.removed_capabilities],
        }


@dataclass(frozen=True)
class AgentPluginCoverageDrift:
    changed: bool
    before: AgentPluginDriftCoverageState
    after: AgentPluginDriftCoverageState
    before_structural_coverage: AgentPluginCoverage
    after_structural_coverage: AgentPluginCoverage
    before_capability_coverage: AgentPluginCapabilityCoverage
    after_capability_coverage: AgentPluginCapabilityCoverage
    added_blind_spots: tuple[AgentPluginCapabilityBlindSpot, ...] = ()
    removed_blind_spots: tuple[AgentPluginCapabilityBlindSpot, ...] = ()

    def to_data(self) -> dict[str, object]:
        return {
            "changed": self.changed,
            "before": {
                "structural_coverage": self.before_structural_coverage.to_data(),
                "capability_coverage": self.before_capability_coverage.to_data(),
                "coverage_state": self.before.to_data(),
            },
            "after": {
                "structural_coverage": self.after_structural_coverage.to_data(),
                "capability_coverage": self.after_capability_coverage.to_data(),
                "coverage_state": self.after.to_data(),
            },
            "added_blind_spots": [item.to_data() for item in self.added_blind_spots],
            "removed_blind_spots": [item.to_data() for item in self.removed_blind_spots],
        }


@dataclass(frozen=True)
class AgentPluginDriftReport:
    """Independent content/capability/coverage comparison result."""

    format: str
    snapshot_format_version: str
    before_plugin_identity: dict[str, object]
    after_plugin_identity: dict[str, object]
    content: AgentPluginContentDrift
    capability: AgentPluginCapabilityDrift
    coverage: AgentPluginCoverageDrift
    diagnostics: tuple[AgentPluginDiagnostic, ...] = ()

    @property
    def content_drift(self) -> AgentPluginContentDrift:
        return self.content

    @property
    def capability_drift(self) -> AgentPluginCapabilityDrift:
        return self.capability

    @property
    def coverage_drift(self) -> AgentPluginCoverageDrift:
        return self.coverage

    def to_data(self) -> dict[str, object]:
        return {
            "format": self.format,
            "snapshot_format_version": self.snapshot_format_version,
            "before_plugin_identity": dict(self.before_plugin_identity),
            "after_plugin_identity": dict(self.after_plugin_identity),
            "content": self.content.to_data(),
            "capability": self.capability.to_data(),
            "coverage": self.coverage.to_data(),
            "diagnostics": [item.to_data() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class _FileCandidate:
    path: str
    sha256: str | None
    size_bytes: int | None
    reason: str | None
    status: str | None
    owner: str
    portable_core: bool

    @property
    def size_reliable(self) -> bool:
        if self.size_bytes is None:
            return False
        if self.sha256 is not None:
            return True
        if self.reason in _UNSAFE_IDENTITY_REASONS:
            return False
        return self.status not in {"unreadable"}


def _diagnostic(code: str, message: str, path: str | None = None) -> AgentPluginDiagnostic:
    return AgentPluginDiagnostic(code=code, message=message, path=path)


def _sorted_diagnostics(
    diagnostics: Iterable[AgentPluginDiagnostic],
) -> tuple[AgentPluginDiagnostic, ...]:
    unique = {(item.code, item.message, item.path): item for item in diagnostics}
    return tuple(
        sorted(unique.values(), key=lambda item: (item.path or "", item.code, item.message))
    )


def _safe_relative_path(value: str) -> str | None:
    raw = value.replace("\\", "/")
    path = PurePosixPath(raw)
    if not raw or raw == "." or path.is_absolute() or ".." in path.parts:
        return None
    return path.as_posix()


def _is_marker_path(path: str) -> bool:
    return any(part.startswith("<") for part in PurePosixPath(path).parts)


def _owner_for_component(component_kind: str, component_id: str, component_path: str) -> str:
    return f"{component_kind}:{component_id}:{component_path}"


def _portable_component(component_kind: str) -> bool:
    return component_kind in _PORTABLE_COMPONENT_KINDS


def _candidate_from_provenance(
    entry: Any,
    *,
    diagnostics: list[AgentPluginDiagnostic],
) -> _FileCandidate | None:
    path = _safe_relative_path(entry.path)
    if path is None:
        diagnostics.append(
            _diagnostic(
                "drift_path_unavailable",
                "a provenance path could not be represented as a safe plugin-relative path",
                str(entry.path),
            )
        )
        return None
    if _is_marker_path(path):
        return None
    if entry.component in {"skills", "mcp_server", "extension"}:
        return None
    # Provenance also names fixed directories and declaration-only components.
    # Retain an unidentifiable entry only when it could describe a physical
    # file; membership handles directories and declarations separately.
    if (
        entry.sha256 is None
        and entry.size_bytes is None
        and entry.identity_skipped_reason == "not_regular_file"
        and path not in {"plugin.json", "mcp.json"}
        and entry.component != "skill"
    ):
        return None
    return _FileCandidate(
        path=path,
        sha256=entry.sha256,
        size_bytes=entry.size_bytes,
        reason=entry.identity_skipped_reason,
        status=entry.status,
        owner=f"provenance:{entry.component}:{path}",
        portable_core=(
            entry.component in {"manifest", "skill", "mcp"}
            or (entry.component == "package_surface" and path in _FIXED_PORTABLE_PATHS)
        ),
    )


def _candidate_from_file_review(
    component_kind: str,
    component_id: str,
    component_path: str,
    review: AgentPluginCapabilityFileReview,
    *,
    diagnostics: list[AgentPluginDiagnostic],
) -> _FileCandidate | None:
    path = _safe_relative_path(review.path)
    if path is None:
        diagnostics.append(
            _diagnostic(
                "drift_path_unavailable",
                "a capability file path could not be represented as a safe plugin-relative path",
                review.path,
            )
        )
        return None
    if _is_marker_path(path):
        return None
    return _FileCandidate(
        path=path,
        sha256=review.sha256,
        size_bytes=review.size_bytes,
        reason=review.reason,
        status=review.status,
        owner=_owner_for_component(component_kind, component_id, component_path),
        portable_core=_portable_component(component_kind),
    )


def _merge_file_candidates(
    candidates: Iterable[_FileCandidate],
) -> tuple[tuple[AgentPluginDriftFile, ...], tuple[AgentPluginDiagnostic, ...]]:
    grouped: dict[str, list[_FileCandidate]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate.path, []).append(candidate)

    files: list[AgentPluginDriftFile] = []
    diagnostics: list[AgentPluginDiagnostic] = []
    for path in sorted(grouped):
        records = grouped[path]
        shas = {item.sha256 for item in records if item.sha256 is not None}
        sizes = {item.size_bytes for item in records if item.size_bytes is not None}
        reasons = sorted({item.reason for item in records if item.reason})
        conflict = len(shas) > 1 or len(sizes) > 1
        unsafe = any(item.reason in _UNSAFE_IDENTITY_REASONS for item in records)
        if conflict:
            diagnostics.append(
                _diagnostic(
                    "drift_identity_conflict",
                    "the same plugin-relative path had conflicting content identity records",
                    path,
                )
            )
        if unsafe:
            diagnostics.append(
                _diagnostic(
                    "drift_identity_incomplete",
                    "content identity was withheld because a bounded read was unsafe",
                    path,
                )
            )

        sha256 = next(iter(shas)) if len(shas) == 1 and not conflict and not unsafe else None
        size_bytes = next(iter(sizes)) if len(sizes) == 1 and not conflict else None
        size_reliable = (
            bool(size_bytes is not None)
            and not conflict
            and any(item.size_reliable for item in records)
            and not unsafe
        )
        identity_complete = sha256 is not None
        reason = "conflicting_identity" if conflict else ";".join(reasons) or None
        files.append(
            AgentPluginDriftFile(
                path=path,
                sha256=sha256,
                size_bytes=size_bytes,
                identity_complete=identity_complete,
                size_reliable=size_reliable,
                identity_skipped_reason=reason,
                owners=tuple(sorted({item.owner for item in records})),
                portable_core=any(item.portable_core for item in records),
            )
        )
    return tuple(files), _sorted_diagnostics(diagnostics)


def _add_membership(
    memberships: set[AgentPluginDriftMembership],
    component_kind: str,
    component_id: str,
    component_path: str,
    portable_core: bool,
) -> None:
    memberships.add(
        AgentPluginDriftMembership(
            component_kind=component_kind,
            component_id=component_id,
            component_path=component_path,
            portable_core=portable_core,
        )
    )


def _component_membership(
    inventory: AgentPluginInventory,
    review: AgentPluginCapabilityReview,
) -> tuple[AgentPluginDriftMembership, ...]:
    memberships: set[AgentPluginDriftMembership] = set()
    _add_membership(memberships, "manifest", "plugin", inventory.manifest.path, True)
    if inventory.skills_status != "absent":
        _add_membership(memberships, "skills", "skills", "skills", True)
    for skill in inventory.skills:
        skill_path = skill.path.rsplit("/", 1)[0]
        _add_membership(memberships, "skill", PurePosixPath(skill_path).name, skill_path, True)
    if inventory.mcp.status != "absent":
        _add_membership(memberships, "mcp", "mcp.json", inventory.mcp.path, True)
        for server in inventory.mcp.servers:
            _add_membership(memberships, "mcp_server", server.name, server.path, True)

    for component in review.components:
        _add_membership(
            memberships,
            component.component_kind,
            component.component_id,
            component.component_path,
            _portable_component(component.component_kind),
        )
    for extension in inventory.extensions:
        _add_membership(
            memberships,
            "client_extension",
            extension.namespace,
            extension.namespace,
            False,
        )
    for surface in inventory.package_surfaces:
        _add_package_surface_membership(memberships, surface)
    represented_unknowns = {item.component_path for item in memberships}
    for path in inventory.unknown_surfaces:
        if path not in represented_unknowns:
            _add_membership(memberships, "package_surface", path, path, False)
    return tuple(sorted(memberships, key=lambda item: item.key))


def _add_package_surface_membership(
    memberships: set[AgentPluginDriftMembership],
    surface: AgentPluginPackageSurface,
) -> None:
    if surface.kind == "client_extension":
        kind = "client_extension"
        portable = False
    else:
        kind = "package_surface"
        portable = surface.kind == "portable_component"
    _add_membership(memberships, kind, surface.path, surface.path, portable)


def _marker_paths(
    review: AgentPluginCapabilityReview,
) -> tuple[tuple[str, bool], ...]:
    paths: set[tuple[str, bool]] = set()
    for component in review.components:
        portable = _portable_component(component.component_kind)
        for file_review in component.file_reviews:
            path = _safe_relative_path(file_review.path)
            if path is not None and _is_marker_path(path):
                paths.add((path, portable))
    return tuple(sorted(paths))


def _component_incompleteness(
    review: AgentPluginCapabilityReview,
) -> tuple[tuple[str, str, str, str, str], ...]:
    states: set[tuple[str, str, str, str, str]] = set()
    for component in review.components:
        if (
            component.structural_status == "valid"
            and component.capability_scan_status == "reviewed"
        ):
            continue
        states.add(
            (
                component.component_kind,
                component.component_id,
                component.component_path,
                component.structural_status,
                component.capability_scan_status,
            )
        )
    if review.status != "reviewed":
        states.add(("plugin", "plugin", ".", review.status, "not_attempted"))
    return tuple(sorted(states))


def _package_incompleteness(
    inventory: AgentPluginInventory,
) -> tuple[tuple[str, str, str], ...]:
    states: set[tuple[str, str, str]] = set()
    for surface in inventory.package_surfaces:
        if surface.kind != "portable_component" or surface.status != "known":
            states.add((surface.path, surface.kind, surface.status))
    for extension in inventory.extensions:
        # Extension status is intentionally opaque in PR1; retain its state
        # without treating a reviewed/understood extension as portable.
        states.add(
            (
                extension.namespace,
                "client_extension",
                extension.status,
            )
        )
    return tuple(sorted(states))


def _coverage_diagnostic_states(
    diagnostics: Iterable[AgentPluginDiagnostic],
) -> tuple[tuple[str, str | None], ...]:
    states: set[tuple[str, str | None]] = set()
    for item in diagnostics:
        code_words = set(item.code.split("_"))
        if code_words & _COVERAGE_DIAGNOSTIC_WORDS:
            states.add((item.code, item.path))
    return tuple(sorted(states))


def _coverage_state(
    inventory: AgentPluginInventory,
    review: AgentPluginCapabilityReview,
) -> AgentPluginDriftCoverageState:
    return AgentPluginDriftCoverageState(
        structural_portable_core=inventory.coverage.portable_core,
        structural_overall_artifact=inventory.coverage.overall_artifact,
        capability_portable_core=review.capability_coverage.portable_core,
        capability_overall_artifact=review.capability_coverage.overall_artifact,
        blind_spots=tuple(review.blind_spots),
        incomplete_components=_component_incompleteness(review),
        incomplete_package_surfaces=_package_incompleteness(inventory),
        diagnostic_states=_coverage_diagnostic_states(
            [*inventory.diagnostics, *review.diagnostics]
        ),
    )


def _content_identity_coverage(
    files: tuple[AgentPluginDriftFile, ...],
    memberships: tuple[AgentPluginDriftMembership, ...],
    review: AgentPluginCapabilityReview,
    marker_paths: tuple[tuple[str, bool], ...],
) -> AgentPluginDriftContentCoverage:
    files_by_path = {item.path: item for item in files}
    incomplete_portable: set[str] = set()
    incomplete_overall: set[str] = set()

    for item in files:
        if item.identity_complete:
            continue
        incomplete_overall.add(item.path)
        if item.portable_core:
            incomplete_portable.add(item.path)
    for path, portable in marker_paths:
        incomplete_overall.add(path)
        if portable:
            incomplete_portable.add(path)

    # A package directory or opaque extension has membership, but no complete
    # recursive file identity in PR1.  Keep it in completeness without making
    # the content comparison invent a digest for the directory.
    for membership in memberships:
        if membership.portable_core or membership.component_kind not in {
            "client_extension",
            "package_surface",
        }:
            continue
        record = files_by_path.get(membership.component_path)
        if record is None or not record.identity_complete:
            incomplete_overall.add(membership.component_path)

    # If a portable component was not capability-reviewed at all, PR1 only
    # proves its fixed declaration in some cases; supporting files remain
    # unaccounted for.  An MCP/skill component with concrete file reviews is
    # already represented above, so this does not penalize ordinary invalid
    # server entries whose mcp.json bytes are known.
    for component in review.components:
        if component.component_kind not in {"skill", "skills", "mcp", "mcp_server"}:
            continue
        if component.capability_scan_status == "reviewed":
            continue
        real_reviews = [item for item in component.file_reviews if not _is_marker_path(item.path)]
        if not real_reviews:
            incomplete_portable.add(component.component_path)
            incomplete_overall.add(component.component_path)

    return AgentPluginDriftContentCoverage(
        portable_core=("COMPLETE" if not incomplete_portable else "INCOMPLETE"),
        overall_artifact=("COMPLETE" if not incomplete_overall else "INCOMPLETE"),
        incomplete_portable_paths=tuple(sorted(incomplete_portable)),
        incomplete_overall_paths=tuple(sorted(incomplete_overall)),
    )


def _build_snapshot(
    inventory: AgentPluginInventory,
    review: AgentPluginCapabilityReview,
) -> AgentPluginDriftSnapshot:
    diagnostics: list[AgentPluginDiagnostic] = []
    candidates: list[_FileCandidate] = []
    for entry in inventory.provenance.entries:
        candidate = _candidate_from_provenance(entry, diagnostics=diagnostics)
        if candidate is not None:
            candidates.append(candidate)
    for component in review.components:
        for file_review in component.file_reviews:
            candidate = _candidate_from_file_review(
                component.component_kind,
                component.component_id,
                component.component_path,
                file_review,
                diagnostics=diagnostics,
            )
            if candidate is not None:
                candidates.append(candidate)

    files, identity_diagnostics = _merge_file_candidates(candidates)
    diagnostics.extend(identity_diagnostics)
    memberships = _component_membership(inventory, review)
    content_coverage = _content_identity_coverage(
        files,
        memberships,
        review,
        _marker_paths(review),
    )
    return AgentPluginDriftSnapshot(
        snapshot_format_version=AGENT_PLUGIN_DRIFT_SNAPSHOT_VERSION,
        tool_version=AGENT_PLUGIN_DRIFT_TOOL_VERSION,
        plugin_identity=dict(review.plugin_identity),
        content_files=files,
        component_membership=memberships,
        structural_coverage=review.structural_coverage,
        capability_coverage=review.capability_coverage,
        content_identity_coverage=content_coverage,
        coverage_state=_coverage_state(inventory, review),
        observed_capabilities=tuple(review.observed_capabilities),
        diagnostics=_sorted_diagnostics([*review.diagnostics, *diagnostics]),
    )


def build_agent_plugin_drift_snapshot(
    path: Path | str,
    *,
    limits: AgentPluginLimits = DEFAULT_AGENT_PLUGIN_LIMITS,
    capability_limits: AgentPluginCapabilityLimits = DEFAULT_AGENT_PLUGIN_CAPABILITY_LIMITS,
) -> AgentPluginDriftSnapshot:
    """Load and review one package, binding the snapshot to that review."""
    root = Path(path).expanduser().resolve()
    inventory = load_agent_plugin(root, limits=limits)
    review = review_agent_plugin_capabilities(
        root,
        inventory=inventory,
        limits=limits,
        capability_limits=capability_limits,
    )
    return _build_snapshot(inventory, review)


def _observed_capability_key(
    capability: AgentPluginObservedCapability,
) -> tuple[str, str, str]:
    if capability.evidence:
        # Reuse PR2's exact aggregate identity key.  Evidence is deliberately
        # excluded by _capability_key, so source-file and source-line changes
        # cannot manufacture a capability delta.
        return _capability_key(capability.evidence[0].original_capability)
    fallback = Capability(
        type=capability.type,
        resource=capability.resource,
        source_file="",
        details=dict(capability.details),
    )
    return _capability_key(fallback)


def _capability_is_portable(capability: AgentPluginObservedCapability) -> bool:
    return any(_portable_component(item.component_kind) for item in capability.evidence)


def _file_changed(before: AgentPluginDriftFile, after: AgentPluginDriftFile) -> tuple[bool, bool]:
    """Return (known_changed, comparison_incomplete) for one shared path."""
    if before.sha256 is not None and after.sha256 is not None:
        return before.sha256 != after.sha256, False
    if (
        before.size_bytes is not None
        and after.size_bytes is not None
        and before.size_reliable
        and after.size_reliable
    ):
        if before.size_bytes != after.size_bytes:
            return True, False
        return False, True
    return False, True


def _membership_delta(
    before: AgentPluginDriftSnapshot,
    after: AgentPluginDriftSnapshot,
) -> tuple[tuple[AgentPluginDriftMembership, ...], tuple[AgentPluginDriftMembership, ...]]:
    before_map = {item.key: item for item in before.component_membership}
    after_map = {item.key: item for item in after.component_membership}
    added = tuple(after_map[key] for key in sorted(set(after_map) - set(before_map)))
    removed = tuple(before_map[key] for key in sorted(set(before_map) - set(after_map)))
    return added, removed


def _content_scope_state(
    *,
    known_delta: bool,
    before_complete: bool,
    after_complete: bool,
) -> str:
    if known_delta:
        return DRIFT_CHANGED
    if before_complete and after_complete:
        return DRIFT_UNCHANGED
    return DRIFT_UNKNOWN


def _content_drift(
    before: AgentPluginDriftSnapshot,
    after: AgentPluginDriftSnapshot,
) -> AgentPluginContentDrift:
    before_files = {item.path: item for item in before.content_files}
    after_files = {item.path: item for item in after.content_files}
    added_paths = sorted(set(after_files) - set(before_files))
    removed_paths = sorted(set(before_files) - set(after_files))
    modified_paths: list[str] = []
    for path in sorted(set(before_files) & set(after_files)):
        changed, _ = _file_changed(before_files[path], after_files[path])
        if changed:
            modified_paths.append(path)

    added_membership, removed_membership = _membership_delta(before, after)
    identity_changed = before.plugin_identity != after.plugin_identity
    portable_added_files = any(after_files[path].portable_core for path in added_paths)
    portable_removed_files = any(before_files[path].portable_core for path in removed_paths)
    portable_modified_files = any(
        before_files[path].portable_core or after_files[path].portable_core
        for path in modified_paths
    )
    overall_added_files = bool(added_paths)
    overall_removed_files = bool(removed_paths)
    overall_modified_files = bool(modified_paths)
    portable_membership_delta = any(
        item.portable_core for item in (*added_membership, *removed_membership)
    )
    overall_membership_delta = bool(added_membership or removed_membership)
    portable_known_delta = (
        identity_changed
        or portable_added_files
        or portable_removed_files
        or portable_modified_files
        or portable_membership_delta
    )
    overall_known_delta = (
        identity_changed
        or overall_added_files
        or overall_removed_files
        or overall_modified_files
        or overall_membership_delta
    )
    file_changes = tuple(
        [AgentPluginDriftFileChange("added", path, after=after_files[path]) for path in added_paths]
        + [
            AgentPluginDriftFileChange("removed", path, before=before_files[path])
            for path in removed_paths
        ]
        + [
            AgentPluginDriftFileChange(
                "modified",
                path,
                before=before_files[path],
                after=after_files[path],
            )
            for path in modified_paths
        ]
    )
    before_portable_complete = before.content_identity_coverage.portable_core == "COMPLETE"
    after_portable_complete = after.content_identity_coverage.portable_core == "COMPLETE"
    before_overall_complete = before.content_identity_coverage.overall_artifact == "COMPLETE"
    after_overall_complete = after.content_identity_coverage.overall_artifact == "COMPLETE"
    return AgentPluginContentDrift(
        portable_core=_content_scope_state(
            known_delta=portable_known_delta,
            before_complete=before_portable_complete,
            after_complete=after_portable_complete,
        ),
        overall_artifact=_content_scope_state(
            known_delta=overall_known_delta,
            before_complete=before_overall_complete,
            after_complete=after_overall_complete,
        ),
        added_files=tuple(added_paths),
        removed_files=tuple(removed_paths),
        modified_files=tuple(modified_paths),
        added_membership=added_membership,
        removed_membership=removed_membership,
        identity_changed=identity_changed,
        incomplete_before_portable=before.content_identity_coverage.incomplete_portable_paths,
        incomplete_after_portable=after.content_identity_coverage.incomplete_portable_paths,
        incomplete_before_overall=before.content_identity_coverage.incomplete_overall_paths,
        incomplete_after_overall=after.content_identity_coverage.incomplete_overall_paths,
        file_changes=file_changes,
    )


def _capability_drift(
    before: AgentPluginDriftSnapshot,
    after: AgentPluginDriftSnapshot,
) -> AgentPluginCapabilityDrift:
    before_map = {_observed_capability_key(item): item for item in before.observed_capabilities}
    after_map = {_observed_capability_key(item): item for item in after.observed_capabilities}
    added_keys = sorted(set(after_map) - set(before_map))
    removed_keys = sorted(set(before_map) - set(after_map))
    added = tuple(after_map[key] for key in added_keys)
    removed = tuple(before_map[key] for key in removed_keys)
    portable_delta = any(_capability_is_portable(item) for item in (*added, *removed))
    overall_delta = bool(added or removed)
    portable_complete = (
        before.capability_coverage.portable_core == "COMPLETE"
        and after.capability_coverage.portable_core == "COMPLETE"
    )
    overall_complete = (
        before.capability_coverage.overall_artifact == "COMPLETE"
        and after.capability_coverage.overall_artifact == "COMPLETE"
    )
    return AgentPluginCapabilityDrift(
        portable_core=(
            DRIFT_CHANGED
            if portable_delta
            else DRIFT_UNCHANGED
            if portable_complete
            else DRIFT_UNKNOWN
        ),
        overall_artifact=(
            DRIFT_CHANGED
            if overall_delta
            else DRIFT_UNCHANGED
            if overall_complete
            else DRIFT_UNKNOWN
        ),
        added_capabilities=added,
        removed_capabilities=removed,
    )


def _coverage_drift(
    before: AgentPluginDriftSnapshot,
    after: AgentPluginDriftSnapshot,
) -> AgentPluginCoverageDrift:
    before_blind_spots = {
        (
            item.component_kind,
            item.component_id,
            item.component_path,
            item.reason,
        ): item
        for item in before.coverage_state.blind_spots
    }
    after_blind_spots = {
        (
            item.component_kind,
            item.component_id,
            item.component_path,
            item.reason,
        ): item
        for item in after.coverage_state.blind_spots
    }
    return AgentPluginCoverageDrift(
        changed=before.coverage_state.identity_key != after.coverage_state.identity_key,
        before=before.coverage_state,
        after=after.coverage_state,
        before_structural_coverage=before.structural_coverage,
        after_structural_coverage=after.structural_coverage,
        before_capability_coverage=before.capability_coverage,
        after_capability_coverage=after.capability_coverage,
        added_blind_spots=tuple(
            after_blind_spots[key]
            for key in sorted(set(after_blind_spots) - set(before_blind_spots))
        ),
        removed_blind_spots=tuple(
            before_blind_spots[key]
            for key in sorted(set(before_blind_spots) - set(after_blind_spots))
        ),
    )


def compare_agent_plugin_drift(
    before: AgentPluginDriftSnapshot,
    after: AgentPluginDriftSnapshot,
) -> AgentPluginDriftReport:
    """Compare two self-bound snapshots without applying policy."""
    if before.snapshot_format_version != after.snapshot_format_version:
        diagnostics = (
            _diagnostic(
                "drift_snapshot_format_mismatch",
                "before and after snapshots use different drift snapshot formats",
            ),
        )
    else:
        diagnostics = ()
    return AgentPluginDriftReport(
        format=AGENT_PLUGIN_DRIFT_FORMAT,
        snapshot_format_version=AGENT_PLUGIN_DRIFT_SNAPSHOT_VERSION,
        before_plugin_identity=dict(before.plugin_identity),
        after_plugin_identity=dict(after.plugin_identity),
        content=_content_drift(before, after),
        capability=_capability_drift(before, after),
        coverage=_coverage_drift(before, after),
        diagnostics=_sorted_diagnostics([*before.diagnostics, *after.diagnostics, *diagnostics]),
    )


def agent_plugin_drift_to_data(
    report: AgentPluginDriftReport,
) -> dict[str, object]:
    """Return deterministic internal data for tests and future adapters."""
    return report.to_data()


# Intuitive aliases for internal callers; neither is wired to the public CLI.
compare_agent_plugin_drift_snapshots = compare_agent_plugin_drift
diff_agent_plugin_drift = compare_agent_plugin_drift
