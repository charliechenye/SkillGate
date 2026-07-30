from __future__ import annotations

import fnmatch
from typing import Any

from skillgate.models import (
    SCHEMA_VERSION,
    Capability,
    Finding,
    ScanReport,
    severity_at_or_above,
)

TRUST_BOUNDARY_TYPES = {
    "local_execution": {"shell_execution", "remote_download_execution", "destructive_action"},
    "remote_endpoints": {"network_egress"},
    "secrets": {"secret_access"},
    "generated_files": {"filesystem_write"},
    "mcp_servers": {
        "mcp_server",
        "mcp_registry_server",
        "mcp_protocol_version",
        "mcp_extension",
        "mcp_unknown_declaration",
    },
    "mcp_apps": {
        "mcp_app_resource",
        "mcp_app_asset",
        "mcp_app_origin",
        "mcp_app_permission",
        "mcp_app_tool_surface",
        "mcp_app_host_bridge",
        "mcp_app_unknown_declaration",
    },
    "prompt_controls": {"prompt_override"},
    "obfuscation": {"obfuscation"},
}
UNKNOWN_RESOURCE = "<unknown>"


def normalized_resource(value: str | None) -> str:
    return value if value else UNKNOWN_RESOURCE


def finding_key(finding: Finding) -> tuple[str, str, int, str]:
    return (
        finding.file_path,
        finding.rule_id,
        finding.line_number or 0,
        finding.id,
    )


def capability_key(capability: Capability) -> tuple[str, str, str, int]:
    return (
        capability.source_file,
        capability.type,
        normalized_resource(capability.resource),
        capability.source_line or 0,
    )


def trust_boundary_for(capability_type: str) -> str | None:
    for boundary, capability_types in TRUST_BOUNDARY_TYPES.items():
        if capability_type in capability_types:
            return boundary
    return None


def related_rule_ids(
    findings: list[Finding], source_files: set[str], capability_types: set[str]
) -> list[str]:
    return sorted(
        {
            finding.rule_id
            for finding in findings
            if finding.file_path in source_files and finding.capability in capability_types
        }
    )


def build_trust_boundaries(
    capabilities: list[Capability], findings: list[Finding]
) -> list[dict[str, Any]]:
    boundaries = []
    for name, capability_types in sorted(TRUST_BOUNDARY_TYPES.items()):
        boundary_capabilities = [
            capability for capability in capabilities if capability.type in capability_types
        ]
        source_files = {capability.source_file for capability in boundary_capabilities}
        boundaries.append(
            {
                "name": name,
                "capability_types": sorted(capability_types),
                "count": len(boundary_capabilities),
                "resources": sorted(
                    {
                        normalized_resource(capability.resource)
                        for capability in boundary_capabilities
                    }
                ),
                "source_files": sorted(source_files),
                "rule_ids": related_rule_ids(findings, source_files, capability_types),
            }
        )
    return boundaries


def build_file_inventory(
    scanned_files: list[str], capabilities: list[Capability], findings: list[Finding]
) -> list[dict[str, Any]]:
    files = sorted(
        {
            *scanned_files,
            *{capability.source_file for capability in capabilities},
            *{finding.file_path for finding in findings},
        }
    )
    records = []
    for path in files:
        file_capabilities = [
            {
                "type": capability.type,
                "resource": normalized_resource(capability.resource),
                "line": capability.source_line,
            }
            for capability in sorted(capabilities, key=capability_key)
            if capability.source_file == path
        ]
        file_findings = [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "line": finding.line_number,
                "title": finding.title,
            }
            for finding in sorted(findings, key=finding_key)
            if finding.file_path == path
        ]
        if file_capabilities or file_findings:
            records.append(
                {
                    "path": path,
                    "capabilities": file_capabilities,
                    "findings": file_findings,
                }
            )
    return records


def matches_any(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(value, pattern) for pattern in patterns)


def filtered_inventory_inputs(
    report: ScanReport,
    capability_types: list[str] | None = None,
    severity: str | None = None,
    source_files: list[str] | None = None,
) -> tuple[list[str], list[Capability], list[Finding], dict[str, object]]:
    capability_filter = sorted(set(capability_types or []))
    source_filter = sorted(set(source_files or []))
    scanned_files = [item.path for item in report.scanned_files]
    capabilities = list(report.capabilities)
    findings = list(report.findings)
    if capability_filter:
        capabilities = [item for item in capabilities if item.type in capability_filter]
        findings = [item for item in findings if item.capability in capability_filter]
    if severity:
        findings = [item for item in findings if severity_at_or_above(item.severity, severity)]
    if source_filter:
        scanned_files = [path for path in scanned_files if matches_any(path, source_filter)]
        capabilities = [
            item for item in capabilities if matches_any(item.source_file, source_filter)
        ]
        findings = [item for item in findings if matches_any(item.file_path, source_filter)]
    filters: dict[str, object] = {
        "capability": capability_filter,
        "severity": severity,
        "source_file": source_filter,
    }
    return scanned_files, capabilities, findings, filters


def inventory_payload(
    report: ScanReport,
    capability_types: list[str] | None = None,
    severity: str | None = None,
    source_files: list[str] | None = None,
) -> dict[str, Any]:
    scanned_files, capabilities, findings, filters = filtered_inventory_inputs(
        report,
        capability_types,
        severity,
        source_files,
    )
    files = build_file_inventory(scanned_files, capabilities, findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": report.tool_version,
        "scan_root": report.scan_root,
        "filters": filters,
        "files": files,
        "trust_boundaries": build_trust_boundaries(capabilities, findings),
        "summary": {
            "files": len(files),
            "scanned_files": len(scanned_files),
            "capabilities": len(capabilities),
            "findings": len(findings),
        },
    }


def inventory_text(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "SkillGate inventory",
        "",
        f"Scanned files: {summary['scanned_files']}",
        f"Inventory files: {summary['files']}",
        f"Capabilities: {summary['capabilities']}",
        f"Findings: {summary['findings']}",
        "",
        "Trust boundaries:",
    ]
    for boundary in payload["trust_boundaries"]:
        resources = ", ".join(boundary["resources"]) if boundary["resources"] else "-"
        source_files = ", ".join(boundary["source_files"]) if boundary["source_files"] else "-"
        rule_ids = ", ".join(boundary["rule_ids"]) if boundary["rule_ids"] else "-"
        lines.append(
            f"- {boundary['name']}: {boundary['count']} "
            f"resources=[{resources}] files=[{source_files}] rules=[{rule_ids}]"
        )
    if payload["files"]:
        lines.extend(["", "Files:"])
    for file_record in payload["files"]:
        lines.extend(["", file_record["path"]])
        for capability in file_record["capabilities"]:
            line = capability["line"] or 1
            lines.append(
                f"  capability  {capability['type']}  {capability['resource']}  line {line}"
            )
        for finding in file_record["findings"]:
            line = finding["line"] or 1
            lines.append(
                f"  finding     {finding['severity']}  "
                f"{finding['rule_id']}  line {line}  {finding['title']}"
            )
    return "\n".join(lines) + "\n"
