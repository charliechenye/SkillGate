from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from skillgate import __version__
from skillgate.models import (
    SCHEMA_VERSION,
    BaselineLock,
    Capability,
    DiffReport,
    Finding,
    stable_json,
)
from skillgate.rules.base import make_finding
from skillgate.scan import canonical_capability, scan_repository


def create_baseline(root: Path, *, format_aware: bool = False) -> BaselineLock:
    report = scan_repository(root, format_aware=format_aware)
    return BaselineLock(
        schema_version=SCHEMA_VERSION,
        created_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        files=report.scanned_files,
        capabilities=report.capabilities,
    )


def save_baseline(lock: BaselineLock, output: Path) -> None:
    output.write_text(stable_json(lock), encoding="utf-8")


def load_baseline(path: Path) -> BaselineLock:
    try:
        return BaselineLock.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise ValueError(f"Unable to load baseline file: {path}") from exc


def capability_lookup(capabilities: list[Capability]) -> dict[str, Capability]:
    return {canonical_capability(capability): capability for capability in capabilities}


def mcp_by_server(capabilities: list[Capability]) -> dict[str, Capability]:
    return {
        capability.resource or "": capability
        for capability in capabilities
        if capability.type == "mcp_server" and capability.resource
    }


def mcp_change_findings(before: list[Capability], after: list[Capability]) -> list[Finding]:
    findings: list[Finding] = []
    old = mcp_by_server(before)
    new = mcp_by_server(after)
    servers = sorted(set(old) | set(new))
    for server in servers:
        old_cap = old.get(server)
        new_cap = new.get(server)
        if old_cap is None:
            evidence = f"New MCP server: {server}"
        elif new_cap is None:
            evidence = f"Removed MCP server: {server}"
        elif old_cap.details != new_cap.details:
            before_values = {
                key: old_cap.details.get(key) for key in ["command", "args", "env", "endpoints"]
            }
            after_values = {
                key: new_cap.details.get(key) for key in ["command", "args", "env", "endpoints"]
            }
            evidence = f"MCP server changed: {server}; before={before_values}; after={after_values}"
        else:
            continue
        findings.append(
            make_finding(
                rule_id="SG010",
                title="MCP capability changed from baseline",
                description="An MCP server definition differs from the approved baseline.",
                severity="high",
                capability="mcp_server",
                file_path=(new_cap or old_cap).source_file,  # type: ignore[union-attr]
                line_number=None,
                evidence=evidence,
                remediation="Review and approve the MCP capability change.",
            )
        )
    return findings


def diff_against_baseline(
    root: Path, baseline: BaselineLock, *, format_aware: bool = False
) -> tuple[DiffReport, object]:
    report = scan_repository(root, format_aware=format_aware)
    baseline_files = {item.path: item for item in baseline.files}
    current_files = {item.path: item for item in report.scanned_files}
    added_files = sorted(set(current_files) - set(baseline_files))
    removed_files = sorted(set(baseline_files) - set(current_files))
    modified_files = sorted(
        path
        for path in set(current_files) & set(baseline_files)
        if current_files[path].sha256 != baseline_files[path].sha256
    )
    old_caps = capability_lookup(baseline.capabilities)
    new_caps = capability_lookup(report.capabilities)
    added_capabilities = [new_caps[key] for key in sorted(set(new_caps) - set(old_caps))]
    removed_capabilities = [old_caps[key] for key in sorted(set(old_caps) - set(new_caps))]
    findings = mcp_change_findings(baseline.capabilities, report.capabilities)
    diff = DiffReport(
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        scan_root=".",
        added_files=added_files,
        removed_files=removed_files,
        modified_files=modified_files,
        added_capabilities=added_capabilities,
        removed_capabilities=removed_capabilities,
        findings=findings,
        summary={
            "added_files": len(added_files),
            "removed_files": len(removed_files),
            "modified_files": len(modified_files),
            "added_capabilities": len(added_capabilities),
            "removed_capabilities": len(removed_capabilities),
            "findings": len(findings),
        },
    )
    return diff, report
