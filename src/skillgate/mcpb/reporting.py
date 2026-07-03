from __future__ import annotations

from skillgate.models import stable_json

from .models import McpbScanResult, mcpb_scan_payload


def mcpb_scan_text(result: McpbScanResult) -> str:
    manifest = result.bundle_manifest.manifest
    members = result.bundle_manifest.members
    scanned = sum(1 for member in members if member.scanned)
    skipped = len(members) - scanned
    lines = [
        "SkillGate MCPB scan completed",
        "",
        f"Bundle: {manifest.name}@{manifest.version}",
        f"Manifest version: {manifest.manifest_version or 'unknown'}",
        f"Server type: {manifest.server_type}",
        f"Entry point: {manifest.entry_point}",
        f"Startup variants: {len(manifest.startup_variants)}",
        f"Archive members: {len(members)}",
        f"Scanned members: {scanned}",
        f"Skipped members: {skipped}",
        f"Embedded executables: {len(result.bundle_manifest.embedded_binaries)}",
        f"Nested archives: {len(result.bundle_manifest.nested_archives)}",
        f"Capabilities: {len(result.scan_report.capabilities)}",
        f"Findings: {len(result.scan_report.findings)}",
    ]
    for finding in result.scan_report.findings:
        lines.extend(
            [
                "",
                f"{finding.severity.upper():<13}  {finding.rule_id}  {finding.title}",
                f"             {finding.file_path}:{finding.line_number or 1}",
            ]
        )
        if finding.evidence:
            lines.append(f"             {finding.evidence}")
    return "\n".join(lines) + "\n"


def mcpb_scan_json(result: McpbScanResult) -> str:
    return stable_json(mcpb_scan_payload(result))


def mcpb_manifest_json(result: McpbScanResult) -> str:
    return stable_json(result.bundle_manifest)
