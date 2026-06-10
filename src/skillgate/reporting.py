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


def check_text(result: PolicyResult) -> str:
    if not result.blocked:
        return "ALLOWED: repository policy check passed\n"
    lines = ["BLOCKED: repository introduces unapproved AI-agent capabilities", "", "Violations:"]
    lines.extend(f"- {violation.message}" for violation in result.violations)
    return "\n".join(lines) + "\n"


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


def render_scan(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return stable_json(report)
    if output_format == "sarif":
        return stable_json(sarif_report(report))
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
