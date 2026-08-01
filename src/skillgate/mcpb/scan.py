from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path, PurePosixPath

from skillgate import __version__
from skillgate.archive import DEFAULT_ARCHIVE_LIMITS, ArchiveMember, inspect_archive
from skillgate.discovery import discover_paths
from skillgate.mcp_app_assets import (
    MCP_APP_MAX_ASSET_BYTES,
    McpAppAssetInventory,
    McpAppAssetRecord,
    McpAppHostBridgeRecord,
    _asset_kind,
    inventory_local_mcp_app_assets,
    mcp_app_asset_capabilities,
)
from skillgate.mcp_apps import detect_bridge_markers, inventory_mcp_apps
from skillgate.models import SCHEMA_VERSION, Capability, Finding
from skillgate.rules.base import make_capability, make_finding
from skillgate.scan import findings_summary, scan_paths, unique_capabilities, unique_findings

from .manifest import ManifestAnalysis, parse_manifest
from .models import (
    McpbAppAsset,
    McpbArchiveSummary,
    McpbBinaryArtifact,
    McpbBundleManifest,
    McpbMemberState,
    McpbScanResult,
)

EXCLUDED_DIRS = {
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".git",
    ".pytest_cache",
    ".ruff_cache",
}
TOP_LEVEL_RUNTIME_FILES = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "uv.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}
SHELL_BASENAMES = {"bash", "sh", "zsh", "powershell", "pwsh", "cmd", "cmd.exe"}
SECRET_NAME_RE = re.compile(
    r"(?i)(?:^|[_-])"
    r"(?:TOKEN|SECRET|PASSWORD|CREDENTIALS?|API[_-]?KEY|ACCESS[_-]?KEY|"
    r"PRIVATE[_-]?KEY|SECRET[_-]?KEY)"
    r"(?:$|[_-])"
)
SHARED_LIBRARY_EXTENSIONS = {".dll", ".so", ".dylib"}
EXECUTABLE_EXTENSIONS = {".exe"}
MACHO_MAGIC = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
PREFIX_BYTES = 8


def scan_mcpb(path: Path | str, *, format_aware: bool = False) -> McpbScanResult:
    limits = replace(DEFAULT_ARCHIVE_LIMITS, allow_nested_archives=True)
    with inspect_archive(path, limits=limits) as archive:
        member_by_path = {member.normalized_path: member for member in archive.members}
        manifest_member = member_by_path.get("manifest.json")
        if manifest_member is None or manifest_member.member_type != "file":
            from .errors import McpbError

            raise McpbError(
                "MCPB manifest is missing",
                code="mcpb_manifest_missing",
                manifest_path="manifest.json",
            )
        analysis = parse_manifest(archive.extraction_root, manifest_member, limits=limits)
        embedded = _embedded_binaries(archive.extraction_root, archive.members, analysis)
        selected = _selected_source_paths(
            archive.extraction_root, archive.members, analysis, embedded
        )
        manifest_data = json.loads(
            (archive.extraction_root / "manifest.json").read_text(
                encoding="utf-8", errors="replace"
            )
        )
        manifest_apps = inventory_mcp_apps(manifest_data, declaration_path="manifest", scope="mcpb")
        positive_app_bundle = not manifest_apps.is_empty
        app_asset_inventory = _mcpb_app_asset_inventory(
            archive.extraction_root,
            archive.members,
            manifest_path=archive.extraction_root / "manifest.json",
            positive_app_bundle=positive_app_bundle,
        )
        if positive_app_bundle:
            selected = _with_all_mcp_app_web_assets(
                archive.extraction_root, selected, app_asset_inventory
            )
        generic_report = scan_paths(archive.extraction_root, selected, format_aware=format_aware)
        findings = [*generic_report.findings, *_mcpb_findings(archive.members, analysis, embedded)]
        capabilities = [
            *generic_report.capabilities,
            *_mcpb_capabilities(analysis, embedded, archive.members),
            *mcp_app_asset_capabilities(app_asset_inventory),
        ]
        findings = unique_findings(findings)
        capabilities = unique_capabilities(capabilities)
        scan_report = generic_report.model_copy(
            update={
                "findings": findings,
                "capabilities": capabilities,
                "summary": findings_summary(
                    findings,
                    scanned_files=len(generic_report.scanned_files),
                    capabilities=len(capabilities),
                ),
            }
        )
        scanned_paths = {file.path for file in generic_report.scanned_files}
        bundle_manifest = _bundle_manifest(
            archive, analysis, embedded, scanned_paths, app_asset_inventory
        )
        return McpbScanResult(
            schema_version=SCHEMA_VERSION,
            tool_version=__version__,
            bundle_manifest=bundle_manifest,
            scan_report=scan_report,
        )


def _selected_source_paths(
    root: Path,
    members: list[ArchiveMember],
    analysis: ManifestAnalysis,
    embedded: list[McpbBinaryArtifact],
) -> list[Path]:
    member_by_path = {member.normalized_path: member for member in members}
    embedded_paths = {item.path for item in embedded}
    selected: set[Path] = set()

    def add_if_scannable(path: str) -> None:
        member = member_by_path.get(path)
        if not member or not _member_can_scan(member, embedded_paths):
            return
        selected.add((root / member.normalized_path).resolve())

    add_if_scannable(analysis.summary.entry_point)
    entry_parent = PurePosixPath(analysis.summary.entry_point).parent.as_posix()
    entry_prefix = "" if entry_parent == "." else f"{entry_parent}/"
    for member in members:
        if member.normalized_path.startswith(entry_prefix):
            add_if_scannable(member.normalized_path)
    for ref in analysis.summary.referenced_files:
        add_if_scannable(ref)
    for member in members:
        path = PurePosixPath(member.normalized_path)
        if len(path.parts) != 1:
            continue
        if path.name in TOP_LEVEL_RUNTIME_FILES or (
            path.name.startswith("requirements") and path.suffix == ".txt"
        ):
            add_if_scannable(member.normalized_path)
    try:
        for discovered in discover_paths(root):
            rel = discovered.resolve().relative_to(root.resolve()).as_posix()
            add_if_scannable(rel)
    except OSError:
        pass
    return sorted(selected, key=lambda item: item.relative_to(root.resolve()).as_posix())


def _with_all_mcp_app_web_assets(
    root: Path,
    selected: list[Path],
    inventory: McpAppAssetInventory,
) -> list[Path]:
    selected_set = set(selected)
    for asset in inventory.assets:
        if asset.skipped_reason is not None:
            continue
        selected_set.add((root / asset.path).resolve())
    return sorted(selected_set, key=lambda item: item.relative_to(root.resolve()).as_posix())


def _member_can_scan(member: ArchiveMember, embedded_paths: set[str]) -> bool:
    return (
        member.member_type == "file"
        and member.normalized_path != "manifest.json"
        and not member.is_nested_archive
        and member.is_scannable_text
        and member.normalized_path not in embedded_paths
        and not _is_excluded(member.normalized_path)
    )


def _mcpb_app_asset_inventory(
    root: Path,
    members: list[ArchiveMember],
    *,
    manifest_path: Path,
    positive_app_bundle: bool,
) -> McpAppAssetInventory:
    if not positive_app_bundle:
        return inventory_local_mcp_app_assets(root, {manifest_path})
    asset_records: dict[tuple[str, str], McpAppAssetRecord] = {}
    bridges: dict[tuple[str, tuple[str, ...], str], McpAppHostBridgeRecord] = {}
    for member in members:
        if (
            member.member_type != "file"
            or member.is_nested_archive
            or _is_excluded(member.normalized_path)
            or _asset_kind(member.normalized_path) is None
        ):
            continue
        record, text = _mcpb_asset_record(root, member, "mcpb_app_bundle")
        asset_records[(record.path, record.association)] = record
        if text is None:
            continue
        markers = detect_bridge_markers(text)
        if markers:
            bridge = McpAppHostBridgeRecord(
                path=record.path,
                markers=markers,
                association=record.association,
            )
            bridges[(bridge.path, bridge.markers, bridge.association)] = bridge
    return McpAppAssetInventory(
        assets=tuple(
            sorted(asset_records.values(), key=lambda item: (item.path, item.association))
        ),
        bridges=tuple(
            sorted(bridges.values(), key=lambda item: (item.path, item.markers, item.association))
        ),
    )


def _mcpb_asset_record(
    root: Path, member: ArchiveMember, association: str
) -> tuple[McpAppAssetRecord, str | None]:
    path = root / member.normalized_path
    kind = _asset_kind(member.normalized_path) or "unknown"
    if member.uncompressed_size > MCP_APP_MAX_ASSET_BYTES:
        return (
            McpAppAssetRecord(
                member.normalized_path,
                kind,
                association,
                member.uncompressed_size,
                member.sha256,
                "asset_too_large",
            ),
            None,
        )
    if not member.is_scannable_text:
        return (
            McpAppAssetRecord(
                member.normalized_path,
                kind,
                association,
                member.uncompressed_size,
                member.sha256,
                "asset_not_utf8",
            ),
            None,
        )
    try:
        with path.open("rb") as stream:
            data = stream.read(MCP_APP_MAX_ASSET_BYTES + 1)
    except OSError:
        return (
            McpAppAssetRecord(
                member.normalized_path,
                kind,
                association,
                None,
                member.sha256,
                "missing_reference",
            ),
            None,
        )
    if len(data) > MCP_APP_MAX_ASSET_BYTES:
        return (
            McpAppAssetRecord(
                member.normalized_path,
                kind,
                association,
                len(data),
                member.sha256,
                "asset_too_large",
            ),
            None,
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return (
            McpAppAssetRecord(
                member.normalized_path,
                kind,
                association,
                len(data),
                member.sha256,
                "asset_not_utf8",
            ),
            None,
        )
    return (
        McpAppAssetRecord(
            member.normalized_path,
            kind,
            association,
            len(data),
            member.sha256,
            None,
        ),
        text,
    )


def _is_excluded(path: str) -> bool:
    return any(part in EXCLUDED_DIRS for part in PurePosixPath(path).parts)


def _embedded_binaries(
    root: Path,
    members: list[ArchiveMember],
    analysis: ManifestAnalysis,
) -> list[McpbBinaryArtifact]:
    artifacts: dict[str, McpbBinaryArtifact] = {}
    for member in members:
        if member.member_type != "file" or member.is_nested_archive:
            continue
        kind = _executable_kind(root / member.normalized_path, member.normalized_path)
        is_entry = member.normalized_path == analysis.summary.entry_point
        if kind is None and is_entry and analysis.summary.server_type == "binary":
            kind = "declared_binary"
        if kind is None:
            continue
        if member.normalized_path in artifacts:
            existing = artifacts[member.normalized_path]
            artifacts[member.normalized_path] = existing.model_copy(
                update={"is_entry_point": existing.is_entry_point or is_entry}
            )
        else:
            artifacts[member.normalized_path] = McpbBinaryArtifact(
                path=member.normalized_path,
                kind=kind,
                is_entry_point=is_entry,
            )
    return sorted(artifacts.values(), key=lambda item: (item.path, item.kind))


def _executable_kind(path: Path, normalized_path: str) -> str | None:
    try:
        with path.open("rb") as stream:
            prefix = stream.read(PREFIX_BYTES)
    except OSError:
        prefix = b""
    suffix = PurePosixPath(normalized_path).suffix.lower()
    if prefix.startswith(b"MZ"):
        return "pe"
    if prefix.startswith(b"\x7fELF"):
        return "elf"
    if prefix[:4] in MACHO_MAGIC:
        return "mach_o"
    if suffix in SHARED_LIBRARY_EXTENSIONS:
        return "shared_library"
    if suffix in EXECUTABLE_EXTENSIONS:
        return "executable_extension"
    return None


def _looks_like_secret_env_name(name: str) -> bool:
    return SECRET_NAME_RE.search(name) is not None


def _mcpb_findings(
    members: list[ArchiveMember],
    analysis: ManifestAnalysis,
    embedded: list[McpbBinaryArtifact],
) -> list[Finding]:
    findings: list[Finding] = []
    member_by_path = {member.normalized_path: member for member in members}
    entry = member_by_path.get(analysis.summary.entry_point)
    missing_entry = entry is None
    if missing_entry:
        findings.append(_sg014("high", f"Entry point missing: {analysis.summary.entry_point}"))
    elif entry.member_type != "file":
        findings.append(
            _sg014("high", f"Entry point is not a regular file: {analysis.summary.entry_point}")
        )
    missing_startup = {
        ref
        for ref in analysis.startup_references
        if ref != analysis.summary.entry_point and ref not in member_by_path
    }
    for ref in sorted(missing_startup):
        findings.append(_sg014("high", f"Startup reference missing: {ref}"))
    missing_ancillary = {
        ref
        for ref in analysis.ancillary_references
        if ref not in member_by_path
        and ref not in missing_startup
        and not (missing_entry and ref == analysis.summary.entry_point)
    }
    for ref in sorted(missing_ancillary):
        findings.append(_sg014("medium", f"Ancillary reference missing: {ref}"))
    if analysis.version_conflict:
        findings.append(_sg014("medium", "manifest_version conflicts with dxt_version"))
    if analysis.unknown_server_type:
        findings.append(_sg014("medium", f"Unfamiliar server type: {analysis.summary.server_type}"))
    if analysis.extension_mismatch:
        findings.append(
            _sg014(
                "medium",
                (
                    "Server type conflicts with entry point: "
                    f"{analysis.summary.server_type} {analysis.summary.entry_point}"
                ),
            )
        )

    for variant in analysis.startup_variants:
        basename = _command_basename(variant.command)
        if basename in SHELL_BASENAMES:
            findings.append(
                make_finding(
                    rule_id="SG001",
                    title="Shell execution detected",
                    description="The MCPB startup command invokes a shell.",
                    severity="medium",
                    capability="shell_execution",
                    file_path="manifest.json",
                    line_number=None,
                    evidence=(
                        f"Startup {variant.platform}: "
                        f"{variant.command} {' '.join(variant.sanitized_args)}"
                    ).strip(),
                    remediation="Review whether shell execution is necessary and policy-approved.",
                )
            )
        for endpoint in variant.runtime_endpoints:
            findings.append(
                make_finding(
                    rule_id="SG003",
                    title="Network egress detected",
                    description="The MCPB startup configuration references a network endpoint.",
                    severity="medium",
                    capability="network_egress",
                    file_path="manifest.json",
                    line_number=None,
                    evidence=f"Endpoint: {endpoint}",
                    remediation="Allowlist the endpoint or remove unexpected network access.",
                )
            )
        for secret in sorted(
            {
                *variant.sensitive_user_config_refs,
                *[name for name in variant.env_names if _looks_like_secret_env_name(name)],
            }
        ):
            findings.append(
                make_finding(
                    rule_id="SG005",
                    title="Secret or credential access detected",
                    description="The MCPB startup configuration references a secret name.",
                    severity="high",
                    capability="secret_access",
                    file_path="manifest.json",
                    line_number=None,
                    evidence=f"Secret reference: {secret}",
                    remediation="Avoid broad secret access or require explicit review.",
                )
            )
    nested_paths = sorted(member.normalized_path for member in members if member.is_nested_archive)
    for path in nested_paths:
        findings.append(_sg015(path, f"Retained nested archive: {path}"))
    for artifact in embedded:
        label = (
            "Embedded shared library"
            if artifact.kind == "shared_library"
            else "Embedded executable"
        )
        findings.append(_sg015(artifact.path, f"{label}: {artifact.path}"))
    return findings


def _sg014(severity: str, evidence: str) -> Finding:
    return make_finding(
        rule_id="SG014",
        title="MCPB startup or bundle reference mismatch",
        description=(
            "Detects missing or conflicting MCPB startup files, local references, "
            "manifest versions, and server declarations."
        ),
        severity=severity,  # type: ignore[arg-type]
        capability="mcpb_startup",
        file_path="manifest.json",
        line_number=None,
        evidence=evidence,
        remediation=(
            "Correct the manifest or bundle contents so declared startup behavior matches "
            "the packaged files."
        ),
    )


def _sg015(path: str, evidence: str) -> Finding:
    return make_finding(
        rule_id="SG015",
        title="MCPB embedded executable or nested archive requires review",
        description=(
            "Detects bundled executable artifacts and retained nested archives that "
            "SkillGate does not execute or recursively inspect."
        ),
        severity="high",
        capability="mcpb_embedded_artifact",
        file_path=path,
        line_number=None,
        evidence=evidence,
        remediation=(
            "Review the artifact provenance and contents before installing or approving "
            "the MCP bundle."
        ),
    )


def _mcpb_capabilities(
    analysis: ManifestAnalysis,
    embedded: list[McpbBinaryArtifact],
    members: list[ArchiveMember],
) -> list[Capability]:
    capabilities: list[Capability] = []
    for variant in analysis.startup_variants:
        details = {
            "platform": variant.platform,
            "server_type": analysis.summary.server_type,
            "entry_point": analysis.summary.entry_point,
            "command": variant.command,
            "args": variant.sanitized_args,
            "env_names": variant.env_names,
        }
        capabilities.append(
            make_capability(
                "mcpb_startup",
                "manifest.json",
                None,
                resource=analysis.summary.entry_point,
                **details,
            )
        )
        if _command_basename(variant.command) in SHELL_BASENAMES:
            capabilities.append(
                make_capability(
                    "shell_execution",
                    "manifest.json",
                    None,
                    resource=variant.command,
                    **details,
                )
            )
        for endpoint in variant.runtime_endpoints:
            capabilities.append(
                make_capability(
                    "network_egress",
                    "manifest.json",
                    None,
                    resource=endpoint,
                    **details,
                )
            )
        for secret in sorted(
            {
                *variant.sensitive_user_config_refs,
                *[name for name in variant.env_names if _looks_like_secret_env_name(name)],
            }
        ):
            capabilities.append(
                make_capability("secret_access", "manifest.json", None, resource=secret)
            )
    for path in sorted(member.normalized_path for member in members if member.is_nested_archive):
        capabilities.append(
            make_capability(
                "mcpb_embedded_artifact",
                path,
                None,
                resource=path,
                kind="nested_archive",
                is_entry_point=False,
            )
        )
    for artifact in embedded:
        capabilities.append(
            make_capability(
                "mcpb_embedded_artifact",
                artifact.path,
                None,
                resource=artifact.path,
                kind=artifact.kind,
                is_entry_point=artifact.is_entry_point,
            )
        )
    return capabilities


def _command_basename(command: str) -> str:
    return command.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _bundle_manifest(
    archive,
    analysis: ManifestAnalysis,
    embedded: list[McpbBinaryArtifact],
    scanned_paths: set[str],
    app_asset_inventory: McpAppAssetInventory,
) -> McpbBundleManifest:
    embedded_paths = {item.path for item in embedded}
    members = [
        _member_state(member, scanned_paths=scanned_paths, embedded_paths=embedded_paths)
        for member in archive.members
    ]
    nested = sorted(
        member.normalized_path for member in archive.members if member.is_nested_archive
    )
    return McpbBundleManifest(
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        archive=McpbArchiveSummary(
            sha256=archive.archive_sha256,
            format=archive.archive_format,
            member_count=archive.member_count,
            total_compressed_bytes=archive.total_compressed_bytes,
            total_uncompressed_bytes=archive.total_uncompressed_bytes,
            limits=archive.limits.to_data(),
        ),
        manifest=analysis.summary,
        members=sorted(members, key=lambda item: item.path),
        embedded_binaries=embedded,
        nested_archives=nested,
        mcp_app_assets=[
            McpbAppAsset(
                path=asset.path,
                kind=asset.kind,
                association=asset.association,
                size_bytes=asset.size_bytes,
                sha256=asset.sha256,
                skipped_reason=asset.skipped_reason,
            )
            for asset in app_asset_inventory.assets
        ],
    )


def _member_state(
    member: ArchiveMember, *, scanned_paths: set[str], embedded_paths: set[str]
) -> McpbMemberState:
    classification = _classification(member, embedded_paths)
    scanned = member.normalized_path in scanned_paths
    skip_reason = None if scanned else _skip_reason(member, classification)
    return McpbMemberState(
        path=member.normalized_path,
        member_type=member.member_type,
        sha256=member.sha256,
        compressed_size=member.compressed_size,
        uncompressed_size=member.uncompressed_size,
        compression_ratio=round(member.compression_ratio, 4)
        if member.compression_ratio is not None
        else None,
        classification=classification,
        nested_archive=member.is_nested_archive,
        scanned=scanned,
        skip_reason=skip_reason,
    )


def _classification(member: ArchiveMember, embedded_paths: set[str]) -> str:
    if member.member_type == "directory":
        return "directory"
    if member.normalized_path == "manifest.json":
        return "manifest"
    if member.is_nested_archive:
        return "nested_archive"
    if member.normalized_path in embedded_paths:
        return "embedded_executable"
    if member.is_scannable_text:
        return "scannable_text"
    if member.skip_reason == "binary content":
        return "binary"
    return "unsupported"


def _skip_reason(member: ArchiveMember, classification: str) -> str | None:
    if classification == "directory":
        return "directory"
    if classification == "manifest":
        return "parsed as MCPB manifest"
    if classification == "nested_archive":
        return "nested archive retained but not recursively inspected"
    if classification == "embedded_executable":
        return "embedded executable requires review"
    if _is_excluded(member.normalized_path):
        return "dependency or build content excluded"
    if classification == "binary":
        return "binary content"
    if classification == "unsupported":
        return "unsupported file type"
    return "not selected for MCPB MVP source scan"
