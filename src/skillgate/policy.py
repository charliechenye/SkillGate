from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

import yaml

from skillgate.models import (
    Capability,
    Finding,
    PolicyResult,
    PolicyViolation,
    ScanReport,
    severity_at_or_above,
)


def load_policy(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ValueError(f"Unable to read policy file: {path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Unable to parse policy file: {path}") from exc
    if not isinstance(data, dict):
        raise ValueError("Policy file must contain a YAML mapping.")
    return data


def allowed_by_globs(value: str | None, patterns: list[str]) -> bool:
    if value is None:
        return False
    return any(fnmatch.fnmatch(value, pattern) for pattern in patterns)


def violation(
    message: str,
    severity: str,
    finding: Finding | None = None,
    capability: Capability | None = None,
) -> PolicyViolation:
    return PolicyViolation(
        message=message,
        severity=severity,  # type: ignore[arg-type]
        finding_id=finding.id if finding else None,
        capability=capability,
    )


def evaluate_policy(
    report: ScanReport,
    policy_data: dict[str, Any],
    diff_findings: list[Finding] | None = None,
) -> PolicyResult:
    policy = policy_data.get("policy") if isinstance(policy_data.get("policy"), dict) else {}
    violations: list[PolicyViolation] = []
    threshold = policy.get("risk_threshold", {}).get("block", "critical")
    findings = [*report.findings, *(diff_findings or [])]
    for finding in findings:
        if severity_at_or_above(finding.severity, threshold):
            message = (
                "Finding severity is at or above block threshold: "
                f"{finding.rule_id} {finding.title}"
            )
            violations.append(
                violation(
                    message,
                    finding.severity,
                    finding=finding,
                )
            )
    if policy.get("shell", {}).get("allow") is False:
        for capability in report.capabilities:
            if capability.type in {"shell_execution", "remote_download_execution"}:
                violations.append(
                    violation("Shell execution is not allowed", "high", capability=capability)
                )
    write_allow = policy.get("filesystem", {}).get("write")
    if isinstance(write_allow, list):
        patterns = [str(item) for item in write_allow]
        for capability in report.capabilities:
            if capability.type == "filesystem_write" and not allowed_by_globs(
                capability.resource, patterns
            ):
                resource = capability.resource or "<unknown>"
                violations.append(
                    violation(
                        f"Filesystem write path is not allowlisted: {resource}",
                        "medium",
                        capability=capability,
                    )
                )
    network_allow = policy.get("network", {}).get("allow")
    if isinstance(network_allow, list):
        hosts = [str(item) for item in network_allow]
        for capability in report.capabilities:
            if capability.type == "network_egress" and capability.resource not in hosts:
                resource = capability.resource or "<unknown>"
                violations.append(
                    violation(
                        f"Network host is not allowlisted: {resource}",
                        "medium",
                        capability=capability,
                    )
                )
    secrets_deny = policy.get("secrets", {}).get("deny")
    if secrets_deny == ["*"]:
        for capability in report.capabilities:
            if capability.type == "secret_access":
                resource = capability.resource or "<unknown>"
                violations.append(
                    violation(f"Secret access is denied: {resource}", "high", capability=capability)
                )
    if policy.get("mcp", {}).get("require_review_on_change") is True:
        for finding in diff_findings or []:
            if finding.rule_id == "SG010":
                violations.append(
                    violation("MCP capability changed from baseline", "high", finding=finding)
                )
    unique: dict[str, PolicyViolation] = {}
    for item in violations:
        key = f"{item.message}|{item.finding_id or ''}"
        unique[key] = item
    return PolicyResult(blocked=bool(unique), violations=list(unique.values()))
