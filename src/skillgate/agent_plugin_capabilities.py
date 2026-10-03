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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
from skillgate.discovery import discover_paths
from skillgate.models import Capability
from skillgate.scan import scan_paths

_ROOT_COMPONENT_ID = "mcp.json"
_REVIEWED = "reviewed"
_INCOMPLETE = "incomplete"
_INVALID = "invalid"
_SKIPPED = "skipped"


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

    def to_data(self) -> dict[str, object]:
        return {
            "component_kind": self.component_kind,
            "component_id": self.component_id,
            "component_path": self.component_path,
            "structural_status": self.structural_status,
            "capability_scan_status": self.capability_scan_status,
            "scanned_files": list(self.scanned_files),
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


def _scan_selected_paths(
    root: Path,
    paths: list[Path],
    *,
    component_path: str,
) -> tuple[str, tuple[str, ...], tuple[Capability, ...], tuple[AgentPluginDiagnostic, ...]]:
    if not paths:
        return (
            _INCOMPLETE,
            (),
            (),
            (
                _diagnostic(
                    "capability_discovery_empty",
                    "no files were selected for capability scanning",
                    component_path,
                ),
            ),
        )
    try:
        report = scan_paths(root, paths)
    except Exception:
        return (
            _INCOMPLETE,
            (),
            (),
            (
                _diagnostic(
                    "capability_scan_failed",
                    "capability scanning failed for this component",
                    component_path,
                ),
            ),
        )

    scanned_files = {item.path for item in report.scanned_files}
    for capability in report.capabilities:
        source_file = capability.source_file
        if source_file.startswith("<") or Path(source_file).is_absolute():
            continue
        scanned_files.add(source_file)
    return (
        _REVIEWED,
        tuple(sorted(scanned_files)),
        tuple(sorted(report.capabilities, key=_capability_key)),
        (),
    )


def _scan_skill(root: Path, skill: AgentPluginSkill) -> AgentPluginComponentCapabilityReview:
    component_id = _skill_component_id(skill)
    component_path = _skill_component_path(skill)
    component_root = root / Path(skill.path).parent
    try:
        resolved_component_root = component_root.resolve()
        resolved_component_root.relative_to(root.resolve())
        paths = discover_paths(resolved_component_root)
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

    status, scanned_files, capabilities, diagnostics = _scan_selected_paths(
        root,
        paths,
        component_path=component_path,
    )
    return AgentPluginComponentCapabilityReview(
        component_kind="skill",
        component_id=component_id,
        component_path=component_path,
        structural_status=skill.status,
        capability_scan_status=status,
        scanned_files=scanned_files,
        capabilities=capabilities,
        diagnostics=diagnostics,
    )


def _skill_reviews(
    root: Path, inventory: AgentPluginInventory
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
            reviews.append(_scan_skill(root, skill))
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


def _mcp_reviews(
    root: Path, inventory: AgentPluginInventory
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

    status, scanned_files, capabilities, scan_diagnostics = _scan_selected_paths(
        root,
        [root / root_path],
        component_path=root_path,
    )
    by_config_path, by_name, valid_by_config_path = _mcp_server_maps(mcp.servers)
    invalid_server_present = any(item.status != "valid" for item in mcp.servers)
    root_capabilities: list[Capability] = []
    server_capabilities: dict[str, list[Capability]] = {item.name: [] for item in mcp.servers}
    root_attribution_diagnostics: list[AgentPluginDiagnostic] = []
    server_attribution_diagnostics: dict[str, list[AgentPluginDiagnostic]] = {
        item.name: [] for item in mcp.servers
    }
    if status == _REVIEWED:
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
                scanned_files=scanned_files if status == _REVIEWED else (),
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
        components = _skill_reviews(root, inventory)
        components.extend(_mcp_reviews(root, inventory))
        blind_spots = _component_blind_spots(components)
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
