from __future__ import annotations

import os
from typing import Any

from skillgate.identity import finding_fingerprint
from skillgate.inventory import normalized_resource, trust_boundary_for
from skillgate.models import (
    Capability,
    DiffReport,
    Finding,
    PolicyResult,
    ScanReport,
    model_to_data,
    severity_at_or_above,
    stable_json,
)


def compact(value: object, limit: int = 180) -> str:
    text = stable_json(value).strip() if isinstance(value, dict | list) else str(value)
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def markdown_cell(value: object) -> str:
    text = compact(value)
    return text.replace("|", "\\|")


def capability_record(capability: Capability) -> dict[str, Any]:
    return {
        "type": capability.type,
        "resource": normalized_resource(capability.resource),
        "source_file": capability.source_file,
        "source_line": capability.source_line,
        "trust_boundary": trust_boundary_for(capability.type) or "other",
    }


def finding_record(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "fingerprint": finding_fingerprint(finding),
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "capability": finding.capability,
        "title": finding.title,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "evidence": finding.evidence,
    }


def changed_trust_boundaries(
    added: list[Capability], removed: list[Capability]
) -> list[dict[str, Any]]:
    by_name: dict[str, dict[str, Any]] = {}
    for label, capabilities in [("introduced", added), ("removed", removed)]:
        for capability in capabilities:
            name = trust_boundary_for(capability.type) or "other"
            item = by_name.setdefault(
                name,
                {"name": name, "introduced": [], "removed": []},
            )
            item[label].append(capability_record(capability))
    return [
        {
            "name": name,
            "introduced": sorted(item["introduced"], key=lambda value: stable_json(value)),
            "removed": sorted(item["removed"], key=lambda value: stable_json(value)),
        }
        for name, item in sorted(by_name.items())
    ]


def code_scanning_url() -> str | None:
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        return None
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    return f"{server}/{repository}/security/code-scanning"


def artifact_records(
    sarif_artifact: str | None = None,
    json_artifact: str | None = None,
) -> dict[str, str | None]:
    return {
        "sarif": sarif_artifact,
        "json": json_artifact,
        "code_scanning": code_scanning_url(),
    }


def review_summary_payload(
    report: ScanReport,
    diff_report: DiffReport | None = None,
    policy_result: PolicyResult | None = None,
    sarif_artifact: str | None = None,
    json_artifact: str | None = None,
) -> dict[str, Any]:
    added_capabilities = diff_report.added_capabilities if diff_report else []
    removed_capabilities = diff_report.removed_capabilities if diff_report else []
    changed_files = (
        set(diff_report.added_files + diff_report.modified_files) if diff_report else set()
    )
    high_risk_findings = [
        finding
        for finding in report.findings
        if severity_at_or_above(finding.severity, "high")
        and (not diff_report or finding.file_path in changed_files)
    ]
    high_risk_label = "new_high_risk_findings" if diff_report else "current_high_risk_findings"
    return {
        "schema_version": report.schema_version,
        "tool_version": report.tool_version,
        "scan_root": report.scan_root,
        "status": {
            "policy_blocked": policy_result.blocked if policy_result else None,
            "baseline_compared": diff_report is not None,
            "policy_evaluated": policy_result is not None,
        },
        "summary": {
            "introduced_capabilities": len(added_capabilities),
            "removed_capabilities": len(removed_capabilities),
            "changed_trust_boundaries": len(
                changed_trust_boundaries(added_capabilities, removed_capabilities)
            ),
            high_risk_label: len(high_risk_findings),
            "policy_violations": len(policy_result.violations) if policy_result else 0,
            "active_waivers": len(policy_result.active_waivers) if policy_result else 0,
        },
        "introduced_capabilities": [
            capability_record(capability) for capability in added_capabilities
        ],
        "removed_capabilities": [
            capability_record(capability) for capability in removed_capabilities
        ],
        "changed_trust_boundaries": changed_trust_boundaries(
            added_capabilities,
            removed_capabilities,
        ),
        high_risk_label: [finding_record(finding) for finding in high_risk_findings],
        "policy_violations": (
            [model_to_data(violation) for violation in policy_result.violations]
            if policy_result
            else []
        ),
        "active_waivers": policy_result.active_waivers if policy_result else [],
        "artifacts": artifact_records(sarif_artifact, json_artifact),
    }


def table_or_none(headers: list[str], rows: list[list[object]]) -> list[str]:
    if not rows:
        return ["None."]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(markdown_cell(value) for value in row) + " |")
    return lines


def render_capability_rows(items: list[dict[str, Any]]) -> list[list[object]]:
    return [
        [
            item["type"],
            item["resource"],
            item["trust_boundary"],
            f"{item['source_file']}:{item['source_line'] or 1}",
        ]
        for item in items
    ]


def render_review_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# SkillGate Review Summary",
        "",
        f"- Introduced capabilities: {summary['introduced_capabilities']}",
        f"- Removed capabilities: {summary['removed_capabilities']}",
        f"- Changed trust boundaries: {summary['changed_trust_boundaries']}",
        f"- Policy violations: {summary['policy_violations']}",
        f"- Active waivers: {summary['active_waivers']}",
        "",
        "## Introduced Capabilities",
        *table_or_none(
            ["Type", "Resource", "Trust boundary", "Source"],
            render_capability_rows(payload["introduced_capabilities"]),
        ),
        "",
        "## Removed Capabilities",
        *table_or_none(
            ["Type", "Resource", "Trust boundary", "Source"],
            render_capability_rows(payload["removed_capabilities"]),
        ),
        "",
        "## Changed Trust Boundaries",
    ]
    boundary_rows = [
        [
            item["name"],
            len(item["introduced"]),
            len(item["removed"]),
        ]
        for item in payload["changed_trust_boundaries"]
    ]
    lines.extend(table_or_none(["Boundary", "Introduced", "Removed"], boundary_rows))

    finding_key = (
        "new_high_risk_findings"
        if "new_high_risk_findings" in payload
        else "current_high_risk_findings"
    )
    finding_heading = (
        "New High-Risk Findings"
        if finding_key == "new_high_risk_findings"
        else "Current High-Risk Findings"
    )
    finding_rows = [
        [
            item["severity"],
            item["rule_id"],
            item["title"],
            f"{item['file_path']}:{item['line_number'] or 1}",
            item.get("evidence") or "",
        ]
        for item in payload[finding_key]
    ]
    lines.extend(
        [
            "",
            f"## {finding_heading}",
            *table_or_none(["Severity", "Rule", "Title", "Source", "Evidence"], finding_rows),
            "",
            "## Policy Violations",
        ]
    )
    violation_rows = [
        [
            item["severity"],
            item["message"],
            item.get("reason") or "",
            item.get("approval_hint") or "",
        ]
        for item in payload["policy_violations"]
    ]
    lines.extend(table_or_none(["Severity", "Message", "Why", "Approve by"], violation_rows))

    waiver_rows = [
        [
            item.get("id") or item.get("selector") or "",
            item.get("owner") or "",
            item.get("expires_on") or "",
            item.get("reason") or "",
        ]
        for item in payload["active_waivers"]
    ]
    lines.extend(
        [
            "",
            "## Active Waivers",
            *table_or_none(["Waiver", "Owner", "Expires", "Reason"], waiver_rows),
            "",
            "## Artifacts",
        ]
    )
    artifacts = payload["artifacts"]
    artifact_rows = [
        ["SARIF", artifacts["sarif"] or ""],
        ["Review JSON", artifacts["json"] or ""],
        ["GitHub code scanning", artifacts["code_scanning"] or ""],
    ]
    lines.extend(table_or_none(["Artifact", "Location"], artifact_rows))
    return "\n".join(lines) + "\n"
