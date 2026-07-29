from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from skillgate.mcp_compatibility import (
    compatibility_capabilities,
    compatibility_details,
    inventory_mcp_compatibility,
)
from skillgate.models import Severity
from skillgate.rules.base import FileContent, RuleResult, make_capability, make_finding
from skillgate.rules.script_rules import host_from_token

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
PLACEHOLDER_RE = re.compile(r"\$\{([^}]+)\}")
SHELL_COMMANDS = {"bash", "sh", "zsh", "powershell", "pwsh", "cmd.exe"}
SECRET_NAME_RE = re.compile(r"(?i)(TOKEN|SECRET|KEY|PASSWORD|CREDENTIALS)")
SERVER_KEYS = {
    "args",
    "auth",
    "baseUrl",
    "command",
    "endpoint",
    "env",
    "headers",
    "serverUrl",
    "settings",
    "transport",
    "type",
    "url",
}
ENDPOINT_KEYS = {"url", "serverUrl", "endpoint", "baseUrl", "transport", "settings", "auth"}


@dataclass(frozen=True)
class McpServerDefinition:
    name: str
    config_path: str
    server: dict[str, Any]


def host_from_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = URL_RE.search(value)
    if match:
        return urlparse(match.group(0)).hostname
    return host_from_token(value)


def collect_string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        strings: list[str] = []
        for item in value:
            strings.extend(collect_string_values(item))
        return strings
    if isinstance(value, dict):
        strings = []
        for item in value.values():
            strings.extend(collect_string_values(item))
        return strings
    return []


def hosts_from_value(value: object) -> list[str]:
    hosts = []
    for item in collect_string_values(value):
        url_hosts = [urlparse(match.group(0)).hostname for match in URL_RE.finditer(item)]
        hosts.extend(host for host in url_hosts if host)
        if not url_hosts:
            for token in item.split():
                host = host_from_token(token)
                if host:
                    hosts.append(host)
    return sorted(set(hosts))


def dotted_path(parts: list[str]) -> str:
    return ".".join(parts)


def is_server_like(value: object) -> bool:
    return isinstance(value, dict) and any(key in value for key in SERVER_KEYS)


def find_servers(data: dict[str, Any]) -> list[McpServerDefinition]:
    servers: list[McpServerDefinition] = []

    def walk(value: object, path: list[str]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = [*path, str(key)]
                if key == "mcpServers" and isinstance(child, dict):
                    for name, server in child.items():
                        if isinstance(server, dict):
                            servers.append(
                                McpServerDefinition(
                                    name=str(name),
                                    config_path=dotted_path([*child_path, str(name)]),
                                    server=server,
                                )
                            )
                walk(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, [*path, str(index)])

    walk(data, [])
    for name, server in data.items():
        if name != "mcpServers" and is_server_like(server):
            servers.append(
                McpServerDefinition(name=str(name), config_path=str(name), server=server)
            )
    return sorted(
        {definition.config_path: definition for definition in servers}.values(),
        key=lambda definition: definition.config_path,
    )


def resource_name(definition: McpServerDefinition) -> str:
    top_level_mcp_path = f"mcpServers.{definition.name}"
    if definition.config_path in {top_level_mcp_path, definition.name}:
        return definition.name
    return definition.config_path


def normalize_args(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


def string_keys(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    return sorted(str(key) for key in value)


def transport_type(server: dict[str, Any]) -> str | None:
    transport = server.get("transport")
    if isinstance(transport, dict) and isinstance(transport.get("type"), str):
        return transport["type"]
    if isinstance(server.get("type"), str):
        return server["type"]
    if isinstance(transport, str):
        return transport
    return None


def endpoint_source_values(server: dict[str, Any], args: list[str]) -> dict[str, object]:
    values: dict[str, object] = {"args": args}
    for key in ENDPOINT_KEYS:
        values[key] = server.get(key)
    values["headers"] = server.get("headers")
    return values


def placeholder_names(value: object) -> list[str]:
    names = []
    for item in collect_string_values(value):
        names.extend(match.group(1) for match in PLACEHOLDER_RE.finditer(item))
    return sorted(set(names))


def secret_names(server: dict[str, Any], env_names: list[str]) -> list[str]:
    candidates = set(env_names)
    candidates.update(
        key for key in string_keys(server.get("headers")) if SECRET_NAME_RE.search(key)
    )
    candidates.update(key for key in string_keys(server.get("auth")) if SECRET_NAME_RE.search(key))
    candidates.update(name for name in placeholder_names(server) if SECRET_NAME_RE.search(name))
    return sorted(candidates)


class McpConfigRule:
    rule_id = "SG009"
    title = "MCP server configuration discovered"
    default_severity: Severity = "informational"

    def analyze(self, file: FileContent) -> RuleResult:
        if file.file_type != "mcp_config":
            return RuleResult()
        result = RuleResult()
        try:
            data = json.loads(file.text)
        except json.JSONDecodeError as exc:
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title="MCP configuration parse error",
                    description="The MCP configuration could not be parsed as JSON.",
                    severity="medium",
                    capability="mcp_server",
                    file_path=file.path,
                    line_number=exc.lineno,
                    evidence=exc.msg,
                )
            )
            return result
        if not isinstance(data, dict):
            return result
        root_compatibility = inventory_mcp_compatibility(
            data,
            declaration_path="",
            scope="config",
        )
        result.capabilities.extend(
            compatibility_capabilities(root_compatibility, source_file=file.path)
        )
        definitions = find_servers(data)
        for definition in definitions:
            name = resource_name(definition)
            server = definition.server
            compatibility = inventory_mcp_compatibility(
                server,
                declaration_path=definition.config_path,
                scope=f"server:{definition.name}",
            )
            command = server.get("command")
            args = normalize_args(server.get("args"))
            env = server.get("env") if isinstance(server.get("env"), dict) else {}
            env_names = sorted(str(key) for key in env)
            endpoints = hosts_from_value(endpoint_source_values(server, args))
            secrets = secret_names(server, env_names)
            details = {
                "server": definition.name,
                "config_path": definition.config_path,
                "command": command,
                "args": args,
                "env": env_names,
                "endpoints": endpoints,
                "type": server.get("type") if isinstance(server.get("type"), str) else None,
                "transport_type": transport_type(server),
                "headers": string_keys(server.get("headers")),
                "auth": string_keys(server.get("auth")),
                "secret_names": secrets,
                **compatibility_details(compatibility),
            }
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description="An MCP server configuration was discovered.",
                    severity="informational",
                    capability="mcp_server",
                    file_path=file.path,
                    line_number=None,
                    evidence=f"Server {name}: {command}",
                )
            )
            result.capabilities.append(
                make_capability("mcp_server", file.path, None, resource=name, **details)
            )
            result.capabilities.extend(
                compatibility_capabilities(compatibility, source_file=file.path)
            )
            if isinstance(command, str):
                result.capabilities.append(
                    make_capability("shell_execution", file.path, None, resource=command, **details)
                )
                if command.lower() in SHELL_COMMANDS:
                    result.findings.append(
                        make_finding(
                            rule_id=self.rule_id,
                            title="MCP server uses shell command",
                            description="The MCP server command invokes a shell.",
                            severity="high",
                            capability="shell_execution",
                            file_path=file.path,
                            line_number=None,
                            evidence=f"Server {name}: {command}",
                        )
                    )
            for endpoint in endpoints:
                result.capabilities.append(
                    make_capability("network_egress", file.path, None, resource=endpoint, **details)
                )
            for secret_name in secrets:
                result.findings.append(
                    make_finding(
                        rule_id=self.rule_id,
                        title="MCP server references secret environment variable",
                        description="The MCP server environment references a likely secret.",
                        severity="high",
                        capability="secret_access",
                        file_path=file.path,
                        line_number=None,
                        evidence=f"Environment variable: {secret_name}",
                    )
                )
                result.capabilities.append(
                    make_capability(
                        "secret_access", file.path, None, resource=secret_name, **details
                    )
                )
        return result
