from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from rich.console import Console

from skillgate.models import DiffReport, PolicyResult, ScanReport, stable_json
from skillgate.sarif import sarif_report


def scan_text(report: ScanReport) -> str:
    lines = [
        "SkillGate scan completed",
        "",
        f"Scanned files: {report.summary['scanned_files']}",
        f"Capabilities: {report.summary['capabilities']}",
        f"Findings: {report.summary['findings']}",
    ]
    for finding in report.findings:
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


def append_scan_failure_text(content: str, threshold: str) -> str:
    return f"{content}\nFAILED: scan found findings at or above {threshold}\n"


def policy_suggestions(result: PolicyResult) -> list[dict[str, Any]]:
    suggestions: list[dict[str, Any]] = []
    seen = set()
    for violation in result.violations:
        if violation.suggested_policy is None:
            continue
        key = stable_json(violation.suggested_policy)
        if key not in seen:
            seen.add(key)
            suggestions.append(violation.suggested_policy)
    return suggestions


def check_text(result: PolicyResult, dry_run: bool = False) -> str:
    if not result.blocked:
        prefix = "DRY RUN: " if dry_run else ""
        lines = [f"{prefix}ALLOWED: repository policy check passed"]
        append_waiver_sections(lines, result)
        return "\n".join(lines) + "\n"
    heading = (
        "DRY RUN: repository would be blocked by policy"
        if dry_run
        else "BLOCKED: repository introduces unapproved AI-agent capabilities"
    )
    lines = [heading, "", "Violations:"]
    for violation in result.violations:
        lines.append(f"- {violation.message}")
        if violation.reason:
            lines.append(f"  why: {violation.reason}")
        if violation.approval_hint:
            lines.append(f"  approve by: {violation.approval_hint}")
    suggestions = policy_suggestions(result)
    if suggestions:
        lines.extend(["", "Suggested policy additions:"])
        lines.extend(f"- {stable_json(suggestion).strip()}" for suggestion in suggestions)
    append_waiver_sections(lines, result)
    return "\n".join(lines) + "\n"


def append_waiver_sections(lines: list[str], result: PolicyResult) -> None:
    if result.active_waivers:
        lines.extend(["", "Active waivers:"])
        for waiver in result.active_waivers:
            label = waiver.get("id") or waiver.get("selector")
            lines.append(
                f"- {label} owner={waiver.get('owner')} expires={waiver.get('expires_on')}"
            )
    if result.expired_waivers:
        lines.extend(["", "Expired waivers:"])
        for waiver in result.expired_waivers:
            label = waiver.get("id") or waiver.get("selector")
            lines.append(
                f"- {label} owner={waiver.get('owner')} expired={waiver.get('expires_on')}"
            )
    if result.waived_violations:
        lines.extend(["", "Waived violations:"])
        for item in result.waived_violations:
            waiver = item.get("waiver", {})
            label = waiver.get("id") or waiver.get("selector")
            lines.append(f"- {item.get('message')} by {label}")


def diff_text(report: DiffReport) -> str:
    lines = [
        "SkillGate diff completed",
        "",
        f"Added files: {len(report.added_files)}",
        f"Removed files: {len(report.removed_files)}",
        f"Modified files: {len(report.modified_files)}",
        f"Added capabilities: {len(report.added_capabilities)}",
        f"Removed capabilities: {len(report.removed_capabilities)}",
        f"Findings: {len(report.findings)}",
    ]
    for label, values in [
        ("Added files", report.added_files),
        ("Removed files", report.removed_files),
        ("Modified files", report.modified_files),
    ]:
        if values:
            lines.extend(["", f"{label}:"])
            lines.extend(f"- {value}" for value in values)
    for finding in report.findings:
        lines.extend(["", f"{finding.severity.upper():<13}  {finding.rule_id}  {finding.title}"])
        if finding.evidence:
            lines.append(f"             {finding.evidence}")
    return "\n".join(lines) + "\n"


def render_scan(
    report: ScanReport,
    output_format: str,
    sarif_category: str = "local_repository",
    policy_result: PolicyResult | None = None,
) -> str:
    if output_format == "json":
        return stable_json(report)
    if output_format == "sarif":
        return stable_json(
            sarif_report(report, category=sarif_category, policy_result=policy_result)
        )
    return scan_text(report)


def render_diff(report: DiffReport, output_format: str) -> str:
    if output_format == "json":
        return stable_json(report)
    return diff_text(report)


def write_or_print(content: str, output: Path | None, console: Console | None = None) -> None:
    if output:
        output.write_text(content, encoding="utf-8")
    else:
        if console is not None:
            console.file.write(content)
        else:
            sys.stdout.write(content)


def jsonable(value: Any) -> str:
    return stable_json(value)
