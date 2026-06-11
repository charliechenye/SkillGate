from __future__ import annotations

import fnmatch
import ipaddress
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

NETWORK_CATEGORIES = {
    "source_control",
    "package_registry",
    "ai_api",
    "cloud_metadata",
    "localhost",
    "private_network",
    "public_internet",
}
SOURCE_CONTROL_HOSTS = {
    "github.com",
    "api.github.com",
    "gitlab.com",
    "bitbucket.org",
}
PACKAGE_REGISTRY_HOSTS = {
    "registry.npmjs.org",
    "npmjs.com",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "rubygems.org",
    "packagist.org",
}
AI_API_HOSTS = {
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
}
CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
}


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


def ensure_category_list(value: object, path: Path, node: Node | None, label: str) -> None:
    ensure_string_list(value, path, node, label)
    if isinstance(value, list):
        for index, item in enumerate(value):
            if item not in NETWORK_CATEGORIES:
                raise_policy_error(
                    f"{label} must contain known categories: "
                    f"{', '.join(sorted(NETWORK_CATEGORIES))}",
                    path,
                    sequence_item_node(node, index),
                )


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
                shell,
                {"allow", "commands"},
                node_at_path(root_node, ["policy", "shell"]),
                path,
                "policy.shell",
            )
            ensure_bool(
                shell.get("allow"),
                path,
                node_at_path(root_node, ["policy", "shell", "allow"]),
                "policy.shell.allow",
            )
            commands = shell.get("commands")
            ensure_mapping(
                commands,
                path,
                node_at_path(root_node, ["policy", "shell", "commands"]),
                "policy.shell.commands",
            )
            if isinstance(commands, dict):
                ensure_allowed_keys(
                    commands,
                    {"allow"},
                    node_at_path(root_node, ["policy", "shell", "commands"]),
                    path,
                    "policy.shell.commands",
                )
                ensure_string_list(
                    commands.get("allow"),
                    path,
                    node_at_path(root_node, ["policy", "shell", "commands", "allow"]),
                    "policy.shell.commands.allow",
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
                {"allow", "allow_categories", "deny_categories"},
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
            ensure_category_list(
                network.get("allow_categories"),
                path,
                node_at_path(root_node, ["policy", "network", "allow_categories"]),
                "policy.network.allow_categories",
            )
            ensure_category_list(
                network.get("deny_categories"),
                path,
                node_at_path(root_node, ["policy", "network", "deny_categories"]),
                "policy.network.deny_categories",
            )
        secrets = policy.get("secrets", {})
        if isinstance(secrets, dict):
            ensure_allowed_keys(
                secrets,
                {"deny", "env"},
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
            env = secrets.get("env")
            ensure_mapping(
                env,
                path,
                node_at_path(root_node, ["policy", "secrets", "env"]),
                "policy.secrets.env",
            )
            if isinstance(env, dict):
                ensure_allowed_keys(
                    env,
                    {"allow"},
                    node_at_path(root_node, ["policy", "secrets", "env"]),
                    path,
                    "policy.secrets.env",
                )
                ensure_string_list(
                    env.get("allow"),
                    path,
                    node_at_path(root_node, ["policy", "secrets", "env", "allow"]),
                    "policy.secrets.env.allow",
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


def host_category(host: str | None) -> str | None:
    if not host:
        return None
    normalized = host.lower()
    if normalized in CLOUD_METADATA_HOSTS:
        return "cloud_metadata"
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return "localhost"
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None
    if address is not None:
        if address.is_loopback:
            return "localhost"
        if address.is_private or address.is_link_local:
            return "private_network"
    if normalized in SOURCE_CONTROL_HOSTS or normalized.endswith(".githubusercontent.com"):
        return "source_control"
    if normalized in PACKAGE_REGISTRY_HOSTS:
        return "package_registry"
    if normalized in AI_API_HOSTS:
        return "ai_api"
    return "public_internet"


def capability_command(capability: Capability) -> str | None:
    value = capability.details.get("command")
    return value if isinstance(value, str) else None


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
    shell_command_allow = policy.get("shell", {}).get("commands", {}).get("allow")
    if isinstance(shell_command_allow, list):
        patterns = [str(item) for item in shell_command_allow]
        for capability in report.capabilities:
            if capability.type == "shell_execution" and not allowed_by_globs(
                capability_command(capability), patterns
            ):
                command = capability_command(capability) or "<unknown>"
                violations.append(
                    violation(
                        f"Shell command is not allowlisted: {command}",
                        "high",
                        capability=capability,
                    )
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
    network_allow_categories = policy.get("network", {}).get("allow_categories")
    network_deny_categories = policy.get("network", {}).get("deny_categories")
    if isinstance(network_allow, list):
        hosts = [str(item) for item in network_allow]
        for capability in report.capabilities:
            if capability.type != "network_egress":
                continue
            category = host_category(capability.resource)
            if isinstance(network_deny_categories, list) and category in {
                str(item) for item in network_deny_categories
            }:
                resource = capability.resource or "<unknown>"
                violations.append(
                    violation(
                        f"Network host category is denied: {resource} ({category})",
                        "medium",
                        capability=capability,
                    )
                )
                continue
            category_allowed = isinstance(network_allow_categories, list) and category in {
                str(item) for item in network_allow_categories
            }
            if capability.resource not in hosts and not category_allowed:
                resource = capability.resource or "<unknown>"
                violations.append(
                    violation(
                        f"Network host is not allowlisted: {resource}",
                        "medium",
                        capability=capability,
                    )
                )
    elif isinstance(network_allow_categories, list) or isinstance(network_deny_categories, list):
        allowed_categories = (
            {str(item) for item in network_allow_categories}
            if isinstance(network_allow_categories, list)
            else None
        )
        denied_categories = (
            {str(item) for item in network_deny_categories}
            if isinstance(network_deny_categories, list)
            else set()
        )
        for capability in report.capabilities:
            if capability.type != "network_egress":
                continue
            category = host_category(capability.resource)
            resource = capability.resource or "<unknown>"
            if category in denied_categories:
                violations.append(
                    violation(
                        f"Network host category is denied: {resource} ({category})",
                        "medium",
                        capability=capability,
                    )
                )
            elif allowed_categories is not None and category not in allowed_categories:
                violations.append(
                    violation(
                        "Network host category is not allowlisted: "
                        f"{resource} ({category or '<unknown>'})",
                        "medium",
                        capability=capability,
                    )
                )
    secrets_deny = policy.get("secrets", {}).get("deny")
    if secrets_deny == ["*"]:
        env_allow = policy.get("secrets", {}).get("env", {}).get("allow")
        allowed_env = [str(item) for item in env_allow] if isinstance(env_allow, list) else []
        for capability in report.capabilities:
            if capability.type == "secret_access":
                resource = capability.resource or "<unknown>"
                if not allowed_by_globs(capability.resource, allowed_env):
                    violations.append(
                        violation(
                            f"Secret access is denied: {resource}",
                            "high",
                            capability=capability,
                        )
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
