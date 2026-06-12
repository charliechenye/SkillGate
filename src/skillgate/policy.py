from __future__ import annotations

import fnmatch
import ipaddress
import re
from datetime import date
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
CAPABILITY_GROUPS = {
    "mcp.remote_http",
    "network.ai_api",
    "network.any",
    "network.cloud_metadata",
    "network.localhost",
    "network.package_registry",
    "network.private_network",
    "network.public_internet",
    "network.source_control",
    "secrets.cloud",
    "shell.local_script",
}
NETWORK_GROUP_BY_CATEGORY = {
    "ai_api": "network.ai_api",
    "cloud_metadata": "network.cloud_metadata",
    "localhost": "network.localhost",
    "package_registry": "network.package_registry",
    "private_network": "network.private_network",
    "public_internet": "network.public_internet",
    "source_control": "network.source_control",
}
CLOUD_SECRET_RE = re.compile(
    r"(?i)(AWS_|AZURE_|GOOGLE_|GCP_|OPENAI_|ANTHROPIC_|CLOUD_|API_KEY|SERVICE_ACCOUNT)"
)
REMOTE_HTTP_TRANSPORTS = {"http", "sse", "streamable-http", "websocket"}


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


def ensure_string(value: object, path: Path, node: Node | None, label: str) -> None:
    if value is not None and not isinstance(value, str):
        raise_policy_error(f"{label} must be a string", path, node)


def ensure_date_string(value: object, path: Path, node: Node | None, label: str) -> None:
    if isinstance(value, date):
        return
    ensure_string(value, path, node, label)
    if isinstance(value, str):
        try:
            date.fromisoformat(value)
        except ValueError:
            raise_policy_error(
                f"{label} must be an ISO date in YYYY-MM-DD format",
                path,
                node,
            )


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


def ensure_capability_group_list(value: object, path: Path, node: Node | None, label: str) -> None:
    ensure_string_list(value, path, node, label)
    if isinstance(value, list):
        for index, item in enumerate(value):
            if item not in CAPABILITY_GROUPS:
                raise_policy_error(
                    f"{label} must contain known capability groups: "
                    f"{', '.join(sorted(CAPABILITY_GROUPS))}",
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


FINDING_WAIVER_SELECTOR_KEYS = {"id", "rule_id", "capability", "file_path", "title", "evidence"}
NARROW_FINDING_SELECTOR_KEYS = {"id", "file_path", "title", "evidence"}


def is_broad_selector(selector: dict[str, object]) -> bool:
    string_values = [value for value in selector.values() if isinstance(value, str)]
    if not selector or any(value.strip() in {"", "*", "**"} for value in string_values):
        return True
    if "id" in selector:
        return False
    if len(selector) < 2:
        return True
    return not bool(NARROW_FINDING_SELECTOR_KEYS & set(selector))


def validate_waivers(
    waivers: dict[str, object],
    root_node: Node | None,
    path: Path,
) -> None:
    waiver_node = node_at_path(root_node, ["policy", "waivers"])
    ensure_allowed_keys(
        waivers,
        {"allow_broad_selectors", "entries"},
        waiver_node,
        path,
        "policy.waivers",
    )
    ensure_bool(
        waivers.get("allow_broad_selectors"),
        path,
        node_at_path(root_node, ["policy", "waivers", "allow_broad_selectors"]),
        "policy.waivers.allow_broad_selectors",
    )
    entries = waivers.get("entries")
    if entries is None:
        return
    entries_node = node_at_path(root_node, ["policy", "waivers", "entries"])
    if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
        raise_policy_error("policy.waivers.entries must be a list of mappings", path, entries_node)
    allow_broad = waivers.get("allow_broad_selectors") is True
    for index, entry in enumerate(entries):
        entry_node = sequence_item_node(entries_node, index)
        validate_waiver_entry(entry, root_node, path, entry_node, index, allow_broad)


def validate_waiver_entry(
    entry: dict[str, object],
    root_node: Node | None,
    path: Path,
    entry_node: Node | None,
    index: int,
    allow_broad: bool,
) -> None:
    ensure_allowed_keys(
        entry,
        {"id", "owner", "reason", "created_on", "expires_on", "ticket", "finding"},
        entry_node,
        path,
        "policy.waivers.entries",
    )
    for key in ["owner", "reason", "created_on", "expires_on"]:
        if key not in entry:
            raise_policy_error(
                f"policy.waivers.entries.{key} is required",
                path,
                child_node(entry_node if isinstance(entry_node, MappingNode) else None, key),
            )
    for key in ["id", "owner", "reason", "ticket"]:
        ensure_string(
            entry.get(key),
            path,
            node_at_path(root_node, ["policy", "waivers", "entries", str(index), key]),
            f"policy.waivers.entries.{key}",
        )
    ensure_date_string(
        entry.get("created_on"),
        path,
        node_at_path(root_node, ["policy", "waivers", "entries", str(index), "created_on"]),
        "policy.waivers.entries.created_on",
    )
    ensure_date_string(
        entry.get("expires_on"),
        path,
        node_at_path(root_node, ["policy", "waivers", "entries", str(index), "expires_on"]),
        "policy.waivers.entries.expires_on",
    )
    for key in ["created_on", "expires_on"]:
        if isinstance(entry.get(key), date):
            entry[key] = entry[key].isoformat()
    if isinstance(entry.get("created_on"), str) and isinstance(entry.get("expires_on"), str):
        if date.fromisoformat(entry["created_on"]) > date.fromisoformat(entry["expires_on"]):
            raise_policy_error(
                "policy.waivers.entries.created_on must be on or before expires_on",
                path,
                child_node(
                    entry_node if isinstance(entry_node, MappingNode) else None,
                    "created_on",
                ),
            )
    finding = entry.get("finding")
    finding_node = child_node(
        entry_node if isinstance(entry_node, MappingNode) else None,
        "finding",
    )
    if finding is None:
        raise_policy_error("policy.waivers.entries.finding is required", path, entry_node)
    ensure_mapping(finding, path, finding_node, "policy.waivers.entries.finding")
    if not isinstance(finding, dict):
        return
    ensure_allowed_keys(
        finding,
        FINDING_WAIVER_SELECTOR_KEYS,
        finding_node,
        path,
        "policy.waivers.entries.finding",
    )
    for key in FINDING_WAIVER_SELECTOR_KEYS:
        ensure_string(
            finding.get(key),
            path,
            child_node(finding_node if isinstance(finding_node, MappingNode) else None, key),
            f"policy.waivers.entries.finding.{key}",
        )
    if not allow_broad and is_broad_selector(finding):
        raise_policy_error(
            "policy.waivers.entries.finding selector is too broad; add id, file_path plus rule_id, "
            "or set policy.waivers.allow_broad_selectors to true",
            path,
            finding_node,
        )


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
            {
                "capabilities",
                "shell",
                "filesystem",
                "network",
                "secrets",
                "mcp",
                "risk_threshold",
                "waivers",
            },
            policy_node,
            path,
            "policy",
        )
        for section in [
            "capabilities",
            "shell",
            "filesystem",
            "network",
            "secrets",
            "mcp",
            "risk_threshold",
            "waivers",
        ]:
            section_value = policy.get(section)
            section_node = node_at_path(root_node, ["policy", section])
            ensure_mapping(section_value, path, section_node, f"policy.{section}")
        capabilities = policy.get("capabilities", {})
        if isinstance(capabilities, dict):
            ensure_allowed_keys(
                capabilities,
                {"allow", "deny"},
                node_at_path(root_node, ["policy", "capabilities"]),
                path,
                "policy.capabilities",
            )
            ensure_capability_group_list(
                capabilities.get("allow"),
                path,
                node_at_path(root_node, ["policy", "capabilities", "allow"]),
                "policy.capabilities.allow",
            )
            ensure_capability_group_list(
                capabilities.get("deny"),
                path,
                node_at_path(root_node, ["policy", "capabilities", "deny"]),
                "policy.capabilities.deny",
            )
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
        waivers = policy.get("waivers", {})
        if isinstance(waivers, dict):
            validate_waivers(waivers, root_node, path)
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


def policy_groups(policy: dict[str, Any], key: str) -> set[str]:
    values = policy.get("capabilities", {}).get(key)
    return {str(item) for item in values} if isinstance(values, list) else set()


def mcp_transport_type(capability: Capability) -> str | None:
    value = capability.details.get("transport_type") or capability.details.get("type")
    return value.lower() if isinstance(value, str) else None


def is_local_shell_command(command: str | None) -> bool:
    if not command:
        return False
    lowered = command.lower()
    if "http://" in lowered or "https://" in lowered:
        return False
    return bool(
        re.search(r"\b[\w./\\-]+\.(?:sh|bash|py|js|ts|mjs|cjs|ps1)\b", command)
        or re.search(r"\b(?:subprocess\.run|child_process\.(?:exec|spawn))\b", command)
    )


def capability_matches_group(capability: Capability, group: str) -> bool:
    if group == "network.any":
        return capability.type == "network_egress"
    if group.startswith("network."):
        category = group.removeprefix("network.")
        return (
            capability.type == "network_egress" and host_category(capability.resource) == category
        )
    if group == "shell.local_script":
        return capability.type == "shell_execution" and is_local_shell_command(
            capability_command(capability)
        )
    if group == "mcp.remote_http":
        transport = mcp_transport_type(capability)
        return (
            capability.type in {"mcp_server", "mcp_transport_risk", "network_egress"}
            and transport in REMOTE_HTTP_TRANSPORTS
        )
    if group == "secrets.cloud":
        return capability.type == "secret_access" and bool(
            CLOUD_SECRET_RE.search(capability.resource or "")
        )
    return False


def matching_groups(capability: Capability, groups: set[str]) -> set[str]:
    return {group for group in groups if capability_matches_group(capability, group)}


def group_suggestion_for_capability(capability: Capability) -> str | None:
    if capability.type == "network_egress":
        category = host_category(capability.resource)
        return NETWORK_GROUP_BY_CATEGORY.get(category or "")
    if capability.type == "shell_execution" and is_local_shell_command(
        capability_command(capability)
    ):
        return "shell.local_script"
    if capability.type == "secret_access" and CLOUD_SECRET_RE.search(capability.resource or ""):
        return "secrets.cloud"
    if capability_matches_group(capability, "mcp.remote_http"):
        return "mcp.remote_http"
    return None


def suggested_capability_group(group: str) -> dict[str, Any]:
    return {"policy": {"capabilities": {"allow": [group]}}}


def network_suggestion(capability: Capability) -> dict[str, Any] | None:
    if capability.resource:
        return {"policy": {"network": {"allow": [capability.resource]}}}
    group = group_suggestion_for_capability(capability)
    return suggested_capability_group(group) if group else None


def shell_suggestion(capability: Capability) -> dict[str, Any] | None:
    command = capability_command(capability)
    if command:
        return {"policy": {"shell": {"commands": {"allow": [command]}}}}
    group = group_suggestion_for_capability(capability)
    return suggested_capability_group(group) if group else None


def filesystem_suggestion(capability: Capability) -> dict[str, Any] | None:
    if capability.resource:
        return {"policy": {"filesystem": {"write": [capability.resource]}}}
    return None


def secret_suggestion(capability: Capability) -> dict[str, Any] | None:
    if capability.resource:
        return {"policy": {"secrets": {"env": {"allow": [capability.resource]}}}}
    group = group_suggestion_for_capability(capability)
    return suggested_capability_group(group) if group else None


def policy_waiver_entries(policy: dict[str, Any]) -> list[dict[str, Any]]:
    waivers = policy.get("waivers")
    if not isinstance(waivers, dict):
        return []
    entries = waivers.get("entries")
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def waiver_selector_label(entry: dict[str, Any]) -> str:
    waiver_id = entry.get("id")
    if isinstance(waiver_id, str) and waiver_id:
        return waiver_id
    finding = entry.get("finding")
    if isinstance(finding, dict):
        return ", ".join(f"{key}={finding[key]}" for key in sorted(finding))
    return "<unknown waiver>"


def waiver_summary(entry: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "id": entry.get("id"),
        "owner": entry.get("owner"),
        "reason": entry.get("reason"),
        "created_on": entry.get("created_on"),
        "expires_on": entry.get("expires_on"),
        "ticket": entry.get("ticket"),
        "finding": entry.get("finding"),
        "selector": waiver_selector_label(entry),
    }
    return {key: value for key, value in summary.items() if value is not None}


def waiver_expires_on(entry: dict[str, Any]) -> date:
    value = entry.get("expires_on")
    return date.fromisoformat(value) if isinstance(value, str) else date.min


def finding_value(finding: Finding, key: str) -> str | None:
    value = getattr(finding, key)
    return value if isinstance(value, str) else None


def finding_matches_waiver(finding: Finding, entry: dict[str, Any]) -> bool:
    selector = entry.get("finding")
    if not isinstance(selector, dict):
        return False
    for key, pattern in selector.items():
        if not isinstance(pattern, str):
            return False
        value = finding_value(finding, key)
        if value is None or not fnmatch.fnmatch(value, pattern):
            return False
    return True


def matching_waiver_for_violation(
    item: PolicyViolation,
    findings_by_id: dict[str, Finding],
    active_waivers: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if item.finding_id is None:
        return None
    finding = findings_by_id.get(item.finding_id)
    if finding is None:
        return None
    for waiver in active_waivers:
        if finding_matches_waiver(finding, waiver):
            return waiver_summary(waiver)
    return None


def violation(
    message: str,
    severity: str,
    finding: Finding | None = None,
    capability: Capability | None = None,
    reason: str | None = None,
    approval_hint: str | None = None,
    suggestion: dict[str, Any] | None = None,
) -> PolicyViolation:
    return PolicyViolation(
        message=message,
        severity=severity,  # type: ignore[arg-type]
        finding_id=finding.id if finding else None,
        capability=capability,
        reason=reason,
        approval_hint=approval_hint,
        suggested_policy=suggestion,
    )


def evaluate_policy(
    report: ScanReport,
    policy_data: dict[str, Any],
    diff_findings: list[Finding] | None = None,
    today: date | None = None,
) -> PolicyResult:
    policy = policy_data.get("policy") if isinstance(policy_data.get("policy"), dict) else {}
    violations: list[PolicyViolation] = []
    current_date = today or date.today()
    waiver_entries = policy_waiver_entries(policy)
    active_waiver_entries = [
        entry for entry in waiver_entries if waiver_expires_on(entry) >= current_date
    ]
    expired_waiver_entries = [
        entry for entry in waiver_entries if waiver_expires_on(entry) < current_date
    ]
    active_waivers = [waiver_summary(entry) for entry in active_waiver_entries]
    expired_waivers = [waiver_summary(entry) for entry in expired_waiver_entries]
    threshold = policy.get("risk_threshold", {}).get("block", "critical")
    allowed_groups = policy_groups(policy, "allow")
    denied_groups = policy_groups(policy, "deny")
    denied_capability_ids: set[int] = set()
    mcp_remote_http_hosts = {
        str(endpoint)
        for capability in report.capabilities
        if capability_matches_group(capability, "mcp.remote_http")
        for endpoint in capability.details.get("endpoints", [])
        if isinstance(endpoint, str)
    }
    findings = [*report.findings, *(diff_findings or [])]
    findings_by_id = {finding.id: finding for finding in findings}
    for waiver_entry in expired_waiver_entries:
        summary = waiver_summary(waiver_entry)
        violations.append(
            violation(
                f"Finding waiver expired: {summary.get('selector')}",
                "high",
                reason=(
                    f"Waiver owned by `{summary.get('owner')}` expired on "
                    f"{summary.get('expires_on')}."
                ),
                approval_hint="Remove the expired waiver or renew it with a new review date.",
            )
        )
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
                    reason=(
                        f"`policy.risk_threshold.block` is set to `{threshold}`, "
                        f"and {finding.rule_id} has severity `{finding.severity}`."
                    ),
                    approval_hint=(
                        "Review or remove the finding, or raise the risk threshold if this "
                        "severity is acceptable for the repository."
                    ),
                )
            )

    def effective_matching_groups(capability: Capability, groups: set[str]) -> set[str]:
        matched = matching_groups(capability, groups)
        if (
            "mcp.remote_http" in groups
            and capability.type == "network_egress"
            and capability.resource in mcp_remote_http_hosts
        ):
            matched.add("mcp.remote_http")
        return matched

    for capability in report.capabilities:
        denied = effective_matching_groups(capability, denied_groups)
        if denied:
            denied_capability_ids.add(id(capability))
            group = sorted(denied)[0]
            violations.append(
                violation(
                    f"Capability group is denied: {group}",
                    "high",
                    capability=capability,
                    reason=(
                        f"`policy.capabilities.deny` contains `{group}`, which matches this "
                        f"{capability.type} capability."
                    ),
                    approval_hint=(
                        f"Remove `{group}` from `policy.capabilities.deny` only if this "
                        "capability group is acceptable."
                    ),
                    suggestion=None,
                )
            )

    def group_allowed(capability: Capability) -> bool:
        if capability.type == "remote_download_execution":
            return False
        return bool(effective_matching_groups(capability, allowed_groups))

    if policy.get("shell", {}).get("allow") is False:
        for capability in report.capabilities:
            if capability.type in {"shell_execution", "remote_download_execution"}:
                if id(capability) in denied_capability_ids:
                    continue
                if group_allowed(capability):
                    continue
                if capability.type == "remote_download_execution":
                    message = "Remote download execution is not allowed"
                    reason = (
                        "`policy.shell.allow` is false, and remote download execution cannot "
                        "be approved by capability groups."
                    )
                    hint = (
                        "Remove the remote execution, pin and review the downloaded artifact, "
                        "or make a separate human approval decision."
                    )
                    suggestion = None
                else:
                    message = "Shell execution is not allowed"
                    command = capability_command(capability) or "<unknown>"
                    reason = (
                        "`policy.shell.allow` is false, and this capability invokes local "
                        f"shell/process execution: {command}."
                    )
                    group = group_suggestion_for_capability(capability)
                    hint = (
                        f"Approve this command with `policy.shell.commands.allow: [{command}]`"
                        if command != "<unknown>"
                        else (
                            "Approve a narrower shell command pattern if this execution is "
                            "expected."
                        )
                    )
                    if group:
                        hint += f" or allow capability group `{group}`."
                    suggestion = shell_suggestion(capability)
                violations.append(
                    violation(
                        message,
                        "high",
                        capability=capability,
                        reason=reason,
                        approval_hint=hint,
                        suggestion=suggestion,
                    )
                )
    shell_command_allow = policy.get("shell", {}).get("commands", {}).get("allow")
    if isinstance(shell_command_allow, list):
        patterns = [str(item) for item in shell_command_allow]
        for capability in report.capabilities:
            if id(capability) in denied_capability_ids or group_allowed(capability):
                continue
            if capability.type == "shell_execution" and not allowed_by_globs(
                capability_command(capability), patterns
            ):
                command = capability_command(capability) or "<unknown>"
                group = group_suggestion_for_capability(capability)
                hint = f"Add `{command}` to `policy.shell.commands.allow`."
                if group:
                    hint += f" For broader local-script approval, allow `{group}`."
                violations.append(
                    violation(
                        f"Shell command is not allowlisted: {command}",
                        "high",
                        capability=capability,
                        reason=(
                            "A shell command allowlist is configured, and this command did "
                            "not match any allowed pattern."
                        ),
                        approval_hint=hint,
                        suggestion=shell_suggestion(capability),
                    )
                )
    write_allow = policy.get("filesystem", {}).get("write")
    if isinstance(write_allow, list):
        patterns = [str(item) for item in write_allow]
        for capability in report.capabilities:
            if id(capability) in denied_capability_ids:
                continue
            if capability.type == "filesystem_write" and not allowed_by_globs(
                capability.resource, patterns
            ):
                resource = capability.resource or "<unknown>"
                violations.append(
                    violation(
                        f"Filesystem write path is not allowlisted: {resource}",
                        "medium",
                        capability=capability,
                        reason=(
                            "A filesystem write allowlist is configured, and this target did "
                            "not match any allowed pattern."
                        ),
                        approval_hint=f"Add `{resource}` to `policy.filesystem.write` if expected.",
                        suggestion=filesystem_suggestion(capability),
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
            if id(capability) in denied_capability_ids:
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
                        reason=(
                            f"`policy.network.deny_categories` contains `{category}`, which "
                            f"matches host `{resource}`."
                        ),
                        approval_hint=(
                            f"Remove `{category}` from `policy.network.deny_categories` only "
                            "if this category is acceptable."
                        ),
                    )
                )
                continue
            category_allowed = isinstance(network_allow_categories, list) and category in {
                str(item) for item in network_allow_categories
            }
            if (
                capability.resource not in hosts
                and not category_allowed
                and not group_allowed(capability)
            ):
                resource = capability.resource or "<unknown>"
                group = group_suggestion_for_capability(capability)
                hint = f"Add `{resource}` to `policy.network.allow` if expected."
                if group:
                    hint += f" For broader category approval, allow `{group}`."
                violations.append(
                    violation(
                        f"Network host is not allowlisted: {resource}",
                        "medium",
                        capability=capability,
                        reason=(
                            "A network allowlist is configured, and this host did not match "
                            "an exact host, network category, or allowed capability group."
                        ),
                        approval_hint=hint,
                        suggestion=network_suggestion(capability),
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
            if id(capability) in denied_capability_ids:
                continue
            category = host_category(capability.resource)
            resource = capability.resource or "<unknown>"
            if category in denied_categories:
                violations.append(
                    violation(
                        f"Network host category is denied: {resource} ({category})",
                        "medium",
                        capability=capability,
                        reason=(
                            f"`policy.network.deny_categories` contains `{category}`, which "
                            f"matches host `{resource}`."
                        ),
                        approval_hint=(
                            f"Remove `{category}` from `policy.network.deny_categories` only "
                            "if this category is acceptable."
                        ),
                    )
                )
            elif (
                allowed_categories is not None
                and category not in allowed_categories
                and not group_allowed(capability)
            ):
                group = group_suggestion_for_capability(capability)
                hint = f"Add `{category}` to `policy.network.allow_categories` if expected."
                if group:
                    hint += f" Or allow capability group `{group}`."
                violations.append(
                    violation(
                        "Network host category is not allowlisted: "
                        f"{resource} ({category or '<unknown>'})",
                        "medium",
                        capability=capability,
                        reason=(
                            "A network category allowlist is configured, and this host category "
                            "did not match."
                        ),
                        approval_hint=hint,
                        suggestion=network_suggestion(capability),
                    )
                )
    secrets_deny = policy.get("secrets", {}).get("deny")
    if secrets_deny == ["*"]:
        env_allow = policy.get("secrets", {}).get("env", {}).get("allow")
        allowed_env = [str(item) for item in env_allow] if isinstance(env_allow, list) else []
        for capability in report.capabilities:
            if capability.type == "secret_access":
                if id(capability) in denied_capability_ids:
                    continue
                if group_allowed(capability):
                    continue
                resource = capability.resource or "<unknown>"
                if not allowed_by_globs(capability.resource, allowed_env):
                    violations.append(
                        violation(
                            f"Secret access is denied: {resource}",
                            "high",
                            capability=capability,
                            reason=(
                                '`policy.secrets.deny` is ["*"], and this secret name is not '
                                "allowlisted."
                            ),
                            approval_hint=(
                                f"Add `{resource}` to `policy.secrets.env.allow` if expected."
                            ),
                            suggestion=secret_suggestion(capability),
                        )
                    )
    if policy.get("mcp", {}).get("require_review_on_change") is True:
        for finding in diff_findings or []:
            if finding.rule_id == "SG010":
                violations.append(
                    violation(
                        "MCP capability changed from baseline",
                        "high",
                        finding=finding,
                        reason=(
                            "`policy.mcp.require_review_on_change` is true, and the baseline "
                            "diff produced SG010."
                        ),
                        approval_hint=(
                            "Review the MCP change and update the approved baseline if expected; "
                            "do not disable MCP drift review unless the repository no longer "
                            "needs it."
                        ),
                    )
                )
    unique: dict[str, PolicyViolation] = {}
    waived_violations: list[dict[str, Any]] = []
    for item in violations:
        waiver = matching_waiver_for_violation(item, findings_by_id, active_waiver_entries)
        if waiver is not None:
            waived_violations.append(
                {
                    "finding_id": item.finding_id,
                    "message": item.message,
                    "severity": item.severity,
                    "waiver": waiver,
                }
            )
            continue
        key = f"{item.message}|{item.finding_id or ''}"
        unique[key] = item
    return PolicyResult(
        blocked=bool(unique),
        violations=list(unique.values()),
        active_waivers=active_waivers,
        expired_waivers=expired_waivers,
        waived_violations=waived_violations,
    )
