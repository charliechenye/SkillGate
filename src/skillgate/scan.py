from __future__ import annotations

import json
from pathlib import Path

from skillgate import __version__
from skillgate.discovery import discover_paths, scan_file_metadata
from skillgate.models import SCHEMA_VERSION, Capability, Finding, ScanReport, stable_json
from skillgate.rules import DEFAULT_RULES
from skillgate.rules.base import FileContent


def capability_key(capability: Capability) -> tuple[str, str, str, int, str]:
    return (
        capability.type,
        capability.resource or "",
        capability.source_file,
        capability.source_line or 0,
        stable_json(capability.details),
    )


def finding_key(finding: Finding) -> tuple[str, str, int, str]:
    return (
        finding.rule_id,
        finding.file_path,
        finding.line_number or 0,
        finding.evidence or "",
    )


def unique_capabilities(capabilities: list[Capability]) -> list[Capability]:
    by_key = {capability_key(capability): capability for capability in capabilities}
    return [by_key[key] for key in sorted(by_key)]


def unique_findings(findings: list[Finding]) -> list[Finding]:
    by_id = {finding.id: finding for finding in findings}
    return sorted(by_id.values(), key=finding_key)


def load_file_content(root: Path, path: Path, file_type: str) -> FileContent:
    return FileContent(
        path=path.resolve().relative_to(root.resolve()).as_posix(),
        file_type=file_type,
        text=path.read_text(encoding="utf-8", errors="replace"),
    )


def scan_repository(root: Path) -> ScanReport:
    root = root.resolve()
    paths = discover_paths(root)
    scanned_files = [scan_file_metadata(root, path) for path in paths]
    findings: list[Finding] = []
    capabilities: list[Capability] = []
    metadata_by_path = {item.path: item for item in scanned_files}
    for path in paths:
        rel = path.resolve().relative_to(root).as_posix()
        file = load_file_content(root, path, metadata_by_path[rel].file_type)
        for rule in DEFAULT_RULES:
            result = rule.analyze(file)
            findings.extend(result.findings)
            capabilities.extend(result.capabilities)
    findings = unique_findings(findings)
    capabilities = unique_capabilities(capabilities)
    summary = {
        "scanned_files": len(scanned_files),
        "capabilities": len(capabilities),
        "findings": len(findings),
        "findings_by_severity": {
            severity: sum(1 for finding in findings if finding.severity == severity)
            for severity in ["informational", "low", "medium", "high", "critical"]
        },
    }
    return ScanReport(
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        scan_root=".",
        scanned_files=sorted(scanned_files, key=lambda item: item.path),
        capabilities=capabilities,
        findings=findings,
        summary=summary,
    )


def canonical_capability(capability: Capability) -> str:
    data = capability.model_dump(mode="json")
    data["source_line"] = data["source_line"] or None
    return json.dumps(data, sort_keys=True, separators=(",", ":"))
