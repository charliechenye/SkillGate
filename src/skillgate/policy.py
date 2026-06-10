from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode

from skillgate.models import (
    Capability,
    Finding,
    PolicyResult,
    PolicyViolation,
    ScanReport,
    severity_at_or_above,
)


class PolicyLoadError(ValueError):
    def __init__(
        self,
        message: str,
        path: Path,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.path = path
        self.line = line
        self.column = column

    def __str__(self) -> str:
        if self.line is not None and self.column is not None:
            return f"{self.path}:{self.line}:{self.column}: {self.message}"
        if self.line is not None:
            return f"{self.path}:{self.line}: {self.message}"
        return f"{self.path}: {self.message}"


def mark_location(node: Node | None) -> tuple[int | None, int | None]:
    if node is None:
        return None, None
    return node.start_mark.line + 1, node.start_mark.column + 1


def child_node(mapping: MappingNode | None, key: str) -> Node | None:
    if mapping is None:
        return None
    for key_node, value_node in mapping.value:
        if isinstance(key_node, ScalarNode) and key_node.value == key:
            return value_node
    return None


def node_at_path(root: Node | None, path: list[str]) -> Node | None:
    node = root
    for part in path:
        if not isinstance(node, MappingNode):
            return node
        node = child_node(node, part)
    return node


def raise_policy_error(message: str, path: Path, node: Node | None = None) -> None:
    line, column = mark_location(node)
    raise PolicyLoadError(message, path, line, column)


def load_policy(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
        root_node = yaml.compose(text)
        data = yaml.safe_load(text) or {}
    except OSError as exc:
        raise PolicyLoadError("Unable to read policy file", path) from exc
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else None
        column = mark.column + 1 if mark else None
        raise PolicyLoadError("Unable to parse YAML policy file", path, line, column) from exc
    if not isinstance(data, dict):
        raise_policy_error("Policy file must contain a YAML mapping", path, root_node)
    policy = data.get("policy")
    policy_node = node_at_path(root_node, ["policy"])
    if policy is not None and not isinstance(policy, dict):
        raise_policy_error("policy must be a YAML mapping", path, policy_node)
    if isinstance(policy, dict):
        for section in ["shell", "filesystem", "network", "secrets", "mcp", "risk_threshold"]:
            section_value = policy.get(section)
            section_node = node_at_path(root_node, ["policy", section])
            if section_value is not None and not isinstance(section_value, dict):
                raise_policy_error(f"policy.{section} must be a YAML mapping", path, section_node)
        threshold = policy.get("risk_threshold", {}).get("block")
        if threshold is not None and threshold not in {
            "informational",
            "low",
            "medium",
            "high",
            "critical",
        }:
            threshold_node = node_at_path(root_node, ["policy", "risk_threshold", "block"])
            raise_policy_error(
                "policy.risk_threshold.block must be one of: "
                "informational, low, medium, high, critical",
                path,
                threshold_node,
            )
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
