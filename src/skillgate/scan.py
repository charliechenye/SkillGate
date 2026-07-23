from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from skillgate import __version__
from skillgate.discovery import discover_paths, scan_file_metadata
from skillgate.models import (
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    Capability,
    Finding,
    ScanReport,
    stable_json,
)
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


def load_file_content(
    root: Path, path: Path, file_type: str, *, format_aware: bool = False
) -> FileContent:
    return FileContent(
        path=path.resolve().relative_to(root.resolve()).as_posix(),
        file_type=file_type,
        text=path.read_text(encoding="utf-8", errors="replace"),
        format_aware=format_aware,
    )


def findings_summary(
    findings: list[Finding], scanned_files: int, capabilities: int
) -> dict[str, object]:
    return {
        "scanned_files": scanned_files,
        "capabilities": capabilities,
        "findings": len(findings),
        "findings_by_severity": {
            severity: sum(1 for finding in findings if finding.severity == severity)
            for severity in ["informational", "low", "medium", "high", "critical"]
        },
    }


def scan_paths(root: Path, paths: Iterable[Path], *, format_aware: bool = False) -> ScanReport:
    root = root.resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("scan root must be an existing directory")
    resolved_paths = []
    for path in paths:
        candidate = path if path.is_absolute() else root / path
        resolved = candidate.resolve()
        if not resolved.exists() or not resolved.is_file():
            raise ValueError("scan path must be an existing file")
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError("scan path resolves outside the scan root") from exc
        resolved_paths.append(resolved)
    paths = sorted(
        set(resolved_paths),
        key=lambda item: item.relative_to(root).as_posix(),
    )
    scanned_files = [scan_file_metadata(root, path) for path in paths]
    findings: list[Finding] = []
    capabilities: list[Capability] = []
    metadata_by_path = {item.path: item for item in scanned_files}
    for path in paths:
        rel = path.resolve().relative_to(root).as_posix()
        file = load_file_content(
            root, path, metadata_by_path[rel].file_type, format_aware=format_aware
        )
        for rule in DEFAULT_RULES:
            result = rule.analyze(file)
            findings.extend(result.findings)
            capabilities.extend(result.capabilities)
    findings = unique_findings(findings)
    capabilities = unique_capabilities(capabilities)
    summary = findings_summary(findings, len(scanned_files), len(capabilities))
    return ScanReport(
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        scan_root=".",
        scanned_files=sorted(scanned_files, key=lambda item: item.path),
        capabilities=capabilities,
        findings=findings,
        summary=summary,
    )


def scan_repository(root: Path, *, format_aware: bool = False) -> ScanReport:
    return scan_paths(root, discover_paths(root), format_aware=format_aware)


def filter_report_by_severity(report: ScanReport, threshold: str | None) -> ScanReport:
    if threshold is None:
        return report
    if threshold not in SEVERITY_ORDER:
        raise ValueError(f"Unknown severity: {threshold}")
    minimum = SEVERITY_ORDER[threshold]
    findings = [
        finding for finding in report.findings if SEVERITY_ORDER[finding.severity] >= minimum
    ]
    return report.model_copy(
        update={
            "findings": findings,
            "summary": findings_summary(
                findings,
                scanned_files=len(report.scanned_files),
                capabilities=len(report.capabilities),
            ),
        }
    )


def canonical_capability(capability: Capability) -> str:
    data = capability.model_dump(mode="json")
    # Source lines are review context, not capability identity. Keeping them out
    # of the baseline key prevents harmless line movement from looking like a
    # newly introduced capability.
    data.pop("source_line", None)
    return json.dumps(data, sort_keys=True, separators=(",", ":"))
