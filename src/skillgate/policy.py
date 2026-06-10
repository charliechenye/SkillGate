from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

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


def child_nodes(mapping: MappingNode | None) -> dict[str, Node]:
    if mapping is None:
        return {}
    values = {}
    for key_node, value_node in mapping.value:
        if isinstance(key_node, ScalarNode):
            values[key_node.value] = value_node
    return values


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


def ensure_mapping(value: object, path: Path, node: Node | None, label: str) -> None:
    if value is not None and not isinstance(value, dict):
        raise_policy_error(f"{label} must be a YAML mapping", path, node)


def ensure_bool(value: object, path: Path, node: Node | None, label: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise_policy_error(f"{label} must be a boolean", path, node)


def ensure_string_list(value: object, path: Path, node: Node | None, label: str) -> None:
    if value is None:
        return
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise_policy_error(f"{label} must be a list of strings", path, node)


def ensure_allowed_keys(
    actual: dict[str, object],
    allowed: set[str],
    root_node: Node | None,
    path: Path,
    label: str,
) -> None:
    mapping = root_node if isinstance(root_node, MappingNode) else None
    nodes = child_nodes(mapping)
    for key in sorted(actual, key=str):
        if key not in allowed:
            raise_policy_error(f"Unknown {label} key: {key}", path, nodes.get(key))


def sequence_item_node(node: Node | None, index: int) -> Node | None:
    if isinstance(node, SequenceNode) and index < len(node.value):
        return node.value[index]
    return node


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
    ensure_allowed_keys(data, {"version", "policy"}, root_node, path, "top-level")
    version = data.get("version")
    if version is not None and version != 1:
        raise_policy_error(
            "policy schema version must be 1",
            path,
            node_at_path(root_node, ["version"]),
        )
    policy = data.get("policy")
    policy_node = node_at_path(root_node, ["policy"])
    ensure_mapping(policy, path, policy_node, "policy")
    if isinstance(policy, dict):
        ensure_allowed_keys(
            policy,
            {"shell", "filesystem", "network", "secrets", "mcp", "risk_threshold"},
            policy_node,
            path,
            "policy",
        )
        for section in ["shell", "filesystem", "network", "secrets", "mcp", "risk_threshold"]:
            section_value = policy.get(section)
            section_node = node_at_path(root_node, ["policy", section])
            ensure_mapping(section_value, path, section_node, f"policy.{section}")
        shell = policy.get("shell", {})
        if isinstance(shell, dict):
            ensure_allowed_keys(
                shell, {"allow"}, node_at_path(root_node, ["policy", "shell"]), path, "policy.shell"
            )
            ensure_bool(
                shell.get("allow"),
                path,
                node_at_path(root_node, ["policy", "shell", "allow"]),
                "policy.shell.allow",
            )
        filesystem = policy.get("filesystem", {})
        if isinstance(filesystem, dict):
            ensure_allowed_keys(
                filesystem,
                {"read", "write"},
                node_at_path(root_node, ["policy", "filesystem"]),
                path,
                "policy.filesystem",
            )
            for key in ["read", "write"]:
                value = filesystem.get(key)
                node = node_at_path(root_node, ["policy", "filesystem", key])
                ensure_string_list(value, path, node, f"policy.filesystem.{key}")
        network = policy.get("network", {})
        if isinstance(network, dict):
            ensure_allowed_keys(
                network,
                {"allow"},
                node_at_path(root_node, ["policy", "network"]),
                path,
                "policy.network",
            )
            ensure_string_list(
                network.get("allow"),
                path,
                node_at_path(root_node, ["policy", "network", "allow"]),
                "policy.network.allow",
            )
        secrets = policy.get("secrets", {})
        if isinstance(secrets, dict):
            ensure_allowed_keys(
                secrets,
                {"deny"},
                node_at_path(root_node, ["policy", "secrets"]),
                path,
                "policy.secrets",
            )
            ensure_string_list(
                secrets.get("deny"),
                path,
                node_at_path(root_node, ["policy", "secrets", "deny"]),
                "policy.secrets.deny",
            )
        mcp = policy.get("mcp", {})
        if isinstance(mcp, dict):
            ensure_allowed_keys(
                mcp,
                {"require_review_on_change"},
                node_at_path(root_node, ["policy", "mcp"]),
                path,
                "policy.mcp",
            )
            ensure_bool(
                mcp.get("require_review_on_change"),
                path,
                node_at_path(root_node, ["policy", "mcp", "require_review_on_change"]),
                "policy.mcp.require_review_on_change",
            )
        risk_threshold = policy.get("risk_threshold", {})
        if isinstance(risk_threshold, dict):
            ensure_allowed_keys(
                risk_threshold,
                {"block"},
                node_at_path(root_node, ["policy", "risk_threshold"]),
                path,
                "policy.risk_threshold",
            )
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
