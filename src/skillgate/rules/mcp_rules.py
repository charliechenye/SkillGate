from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from skillgate.models import Severity
from skillgate.rules.base import FileContent, RuleResult, make_capability, make_finding
from skillgate.rules.script_rules import host_from_token

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
SHELL_COMMANDS = {"bash", "sh", "zsh", "powershell", "pwsh", "cmd.exe"}
SECRET_NAME_RE = re.compile(r"(?i)(TOKEN|SECRET|KEY|PASSWORD|CREDENTIALS)")


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
            host = host_from_token(item)
            if host:
                hosts.append(host)
    return sorted(set(hosts))


def find_servers(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if isinstance(data.get("mcpServers"), dict):
        return {
            str(name): server
            for name, server in data["mcpServers"].items()
            if isinstance(server, dict)
        }
    return {
        str(name): server
        for name, server in data.items()
        if isinstance(server, dict)
        and any(key in server for key in {"command", "args", "env", "url"})
    }


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
        for name, server in sorted(find_servers(data).items()):
            command = server.get("command")
            args = server.get("args") if isinstance(server.get("args"), list) else []
            env = server.get("env") if isinstance(server.get("env"), dict) else {}
            endpoints = hosts_from_value(
                {
                    "url": server.get("url"),
                    "args": args,
                    "transport": server.get("transport"),
                    "headers": server.get("headers"),
                    "settings": server.get("settings"),
                }
            )
            env_names = sorted(str(key) for key in env)
            details = {
                "server": name,
                "command": command,
                "args": [str(arg) for arg in args],
                "env": env_names,
                "endpoints": endpoints,
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
            for env_name in env_names:
                if SECRET_NAME_RE.search(env_name):
                    result.findings.append(
                        make_finding(
                            rule_id=self.rule_id,
                            title="MCP server references secret environment variable",
                            description="The MCP server environment references a likely secret.",
                            severity="high",
                            capability="secret_access",
                            file_path=file.path,
                            line_number=None,
                            evidence=f"Environment variable: {env_name}",
                        )
                    )
                    result.capabilities.append(
                        make_capability(
                            "secret_access", file.path, None, resource=env_name, **details
                        )
                    )
        return result
