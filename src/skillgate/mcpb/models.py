from __future__ import annotations

from pydantic import Field

from skillgate.models import ScanReport, StableModel, model_to_data


class McpbStartupVariant(StableModel):
    platform: str
    command: str
    args: list[str]
    env_names: list[str]


class McpbManifestSummary(StableModel):
    path: str
    manifest_version: str | None
    name: str
    version: str
    server_type: str
    entry_point: str
    startup_variants: list[McpbStartupVariant]
    env_names: list[str]
    user_config_names: list[str]
    sensitive_user_config_names: list[str]
    referenced_files: list[str]
    runtime_endpoints: list[str]
    metadata_urls: list[str]


class McpbArchiveSummary(StableModel):
    sha256: str
    format: str
    member_count: int
    total_compressed_bytes: int
    total_uncompressed_bytes: int
    limits: dict[str, object]


class McpbMemberState(StableModel):
    path: str
    member_type: str
    sha256: str | None
    compressed_size: int
    uncompressed_size: int
    compression_ratio: float | None
    classification: str
    nested_archive: bool
    scanned: bool
    skip_reason: str | None


class McpbBinaryArtifact(StableModel):
    path: str
    kind: str
    is_entry_point: bool


class McpbAppAsset(StableModel):
    path: str
    kind: str
    association: str
    size_bytes: int | None
    sha256: str | None
    skipped_reason: str | None


class McpbBundleManifest(StableModel):
    schema_version: str
    tool_version: str
    archive: McpbArchiveSummary
    manifest: McpbManifestSummary
    members: list[McpbMemberState]
    embedded_binaries: list[McpbBinaryArtifact]
    nested_archives: list[str]
    mcp_app_assets: list[McpbAppAsset] = Field(default_factory=list)


class McpbScanResult(StableModel):
    schema_version: str
    tool_version: str
    bundle_manifest: McpbBundleManifest
    scan_report: ScanReport


def mcpb_scan_payload(result: McpbScanResult) -> dict[str, object]:
    return {
        "schema_version": result.schema_version,
        "tool_version": result.tool_version,
        "bundle_manifest": model_to_data(result.bundle_manifest),
        "scan_report": model_to_data(result.scan_report),
    }
