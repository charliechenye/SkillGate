from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from skillgate import __version__
from skillgate.discovery import classify_file, discover_paths, scan_file_metadata
from skillgate.mcp_apps import (
    inventory_mcp_apps,
    mcp_apps_capabilities,
    mcp_apps_findings,
    mcp_apps_summary,
)
from skillgate.mcp_compatibility import (
    compatibility_capabilities,
    compatibility_details,
    inventory_mcp_compatibility,
)
from skillgate.models import SCHEMA_VERSION, Capability, Finding, ScanReport
from skillgate.rules.base import FileContent, make_capability, make_finding
from skillgate.rules.mcp_rules import URL_RE, collect_string_values

REGISTRY_RULE_IDS = {"SG011", "SG012"}
DEFAULT_REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers"
SECRET_HEADER_RE = re.compile(r"(?i)(authorization|token|secret|key|credential|password)")
HIDDEN_INSTRUCTION_RE = re.compile(
    r"(?i)(ignore previous instructions|do not tell the user|do not reveal|"
    r"hide this|conceal|secret instruction|bypass approval|disable safety)"
)
SUSPICIOUS_TOOL_NAME_RE = re.compile(
    r"(?i)(delete|drop|wipe|destroy|exfiltrate|steal|dump|token|secret|credential|"
    r"shell|exec|run_command|runcommand|filesystem|upload|webhook)"
)
RISKY_SCHEMA_FIELD_RE = re.compile(
    r"(?i)(^cmd$|command|shell|script|filepath|file_path|path|directory|token|secret|"
    r"password|apikey|api_key|callback|webhook|headers?|body|rawjson|raw_json|url)"
)
MID_SESSION_TOOL_RE = re.compile(
    r"(?i)(registerTool|register_tool|dynamic tool|mid-session|session tool|tool registration)"
)
SHELL_WRAPPERS = {"bash", "sh", "zsh", "powershell", "pwsh", "cmd", "cmd.exe"}


class RegistryMetadataError(RuntimeError):
    pass


@dataclass(frozen=True)
class RegistryServer:
    name: str
    data: dict[str, Any]
    source_file: str
    config_path: str


def parse_json_object(text: str) -> dict[str, Any] | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def registry_server_object(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    server = value.get("server")
    if isinstance(server, dict):
        return server
    if isinstance(value.get("name"), str) and any(
        key in value
        for key in [
            "repository",
            "remotes",
            "packages",
            "tools",
            "_meta",
            "capabilities",
            "extensions",
            "protocolVersion",
            "protocolVersions",
            "supportedVersions",
        ]
    ):
        return value
    return None


def iter_registry_servers(data: dict[str, Any], source_file: str) -> list[RegistryServer]:
    candidates: list[tuple[str, object]] = []
    servers = data.get("servers")
    if isinstance(servers, list):
        candidates.extend((f"servers.{index}", item) for index, item in enumerate(servers))
    else:
        candidates.append(("server", data))
    parsed: list[RegistryServer] = []
    for config_path, candidate in candidates:
        server = registry_server_object(candidate)
        name = server.get("name") if isinstance(server, dict) else None
        if isinstance(server, dict) and isinstance(name, str) and name:
            parsed.append(
                RegistryServer(
                    name=name,
                    data=server,
                    source_file=source_file,
                    config_path=config_path,
                )
            )
    return parsed


def is_registry_document(data: dict[str, Any]) -> bool:
    if iter_registry_servers(data, "<memory>"):
        return True
    return any(key in data for key in ["mcpApps", "webmcp", "webMcp", "tools"])


def repository_url(server: dict[str, Any]) -> str | None:
    repository = server.get("repository")
    if isinstance(repository, dict) and isinstance(repository.get("url"), str):
        return repository["url"]
    if isinstance(repository, str):
        return repository
    return None


def list_of_dicts(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def remote_urls(server: dict[str, Any]) -> list[str]:
    urls = []
    for remote in list_of_dicts(server.get("remotes")):
        url = remote.get("url") or remote.get("serverUrl") or remote.get("endpoint")
        if isinstance(url, str):
            urls.append(url)
    return sorted(set(urls))


def transport_types(server: dict[str, Any]) -> list[str]:
    values = []
    for remote in list_of_dicts(server.get("remotes")):
        if isinstance(remote.get("type"), str):
            values.append(remote["type"])
        transport = remote.get("transport")
        if isinstance(transport, dict) and isinstance(transport.get("type"), str):
            values.append(transport["type"])
    for package in list_of_dicts(server.get("packages")):
        transport = package.get("transport")
        if isinstance(transport, dict) and isinstance(transport.get("type"), str):
            values.append(transport["type"])
    return sorted(set(values))


def package_identifiers(server: dict[str, Any]) -> list[str]:
    identifiers = []
    for package in list_of_dicts(server.get("packages")):
        identifier = package.get("identifier") or package.get("name")
        registry_type = package.get("registryType") or package.get("registry")
        if isinstance(identifier, str):
            identifiers.append(f"{registry_type}:{identifier}" if registry_type else identifier)
    return sorted(set(identifiers))


def header_names(value: object) -> list[str]:
    headers = []
    if isinstance(value, dict):
        headers.extend(str(key) for key in value)
    for header in list_of_dicts(value):
        name = header.get("name")
        if isinstance(name, str):
            headers.append(name)
    return sorted(set(headers))


def secret_header_names(server: dict[str, Any]) -> list[str]:
    names = []
    for remote in list_of_dicts(server.get("remotes")):
        headers = remote.get("headers")
        if isinstance(headers, dict):
            names.extend(name for name in headers if SECRET_HEADER_RE.search(str(name)))
        for header in list_of_dicts(headers):
            name = header.get("name")
            if isinstance(name, str) and (
                header.get("isSecret") is True or SECRET_HEADER_RE.search(name)
            ):
                names.append(name)
    return sorted(set(names))


def tool_entries(value: object, path: str = "") -> list[tuple[str, dict[str, Any]]]:
    entries: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if key == "tools" and isinstance(child, list):
                entries.extend(
                    (f"{child_path}.{index}", item)
                    for index, item in enumerate(child)
                    if isinstance(item, dict)
                )
            else:
                entries.extend(tool_entries(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            entries.extend(tool_entries(child, f"{path}.{index}" if path else str(index)))
    return entries


def tool_name(tool: dict[str, Any]) -> str:
    for key in ["name", "id", "title"]:
        value = tool.get(key)
        if isinstance(value, str) and value:
            return value
    return "<unnamed>"


def tool_description(tool: dict[str, Any]) -> str:
    parts = []
    for key in ["description", "title"]:
        value = tool.get(key)
        if isinstance(value, str):
            parts.append(value)
    annotations = tool.get("annotations")
    if isinstance(annotations, dict):
        parts.extend(str(value) for value in annotations.values() if isinstance(value, str))
    return "\n".join(parts)


def input_schema(tool: dict[str, Any]) -> object:
    for key in ["inputSchema", "schema", "parameters"]:
        if key in tool:
            return tool[key]
    return None


def schema_field_names(value: object) -> list[str]:
    names: list[str] = []
    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict):
            names.extend(str(key) for key in properties)
        for key, child in value.items():
            if key != "description":
                names.extend(schema_field_names(child))
    elif isinstance(value, list):
        for child in value:
            names.extend(schema_field_names(child))
    return sorted(set(names))


def host_is_local_or_private(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return False
    lowered = host.lower()
    if lowered in {"localhost", "127.0.0.1", "::1"} or lowered.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def remote_has_auth(remote: dict[str, Any]) -> bool:
    headers = remote.get("headers")
    auth = remote.get("auth")
    return bool(header_names(headers) or auth)


def tool_metadata_findings(server: RegistryServer) -> tuple[list[Finding], list[Capability]]:
    findings: list[Finding] = []
    capabilities: list[Capability] = []
    for config_path, tool in tool_entries(server.data):
        name = tool_name(tool)
        description = tool_description(tool)
        fields = schema_field_names(input_schema(tool))
        reasons = []
        if HIDDEN_INSTRUCTION_RE.search(description):
            reasons.append("hidden instruction language")
        if SUSPICIOUS_TOOL_NAME_RE.search(name) or any(ord(char) > 127 for char in name):
            reasons.append("suspicious tool name")
        risky_fields = [field for field in fields if RISKY_SCHEMA_FIELD_RE.search(field)]
        if risky_fields:
            reasons.append(f"risky input fields: {', '.join(risky_fields)}")
        if MID_SESSION_TOOL_RE.search(json.dumps(tool, sort_keys=True)):
            reasons.append("mid-session tool registration metadata")
        if not reasons:
            continue
        details = {
            "server": server.name,
            "config_path": f"{server.config_path}.{config_path}",
            "tool": name,
            "risks": sorted(reasons),
            "input_fields": fields,
        }
        evidence = f"{server.name}.{name}: {', '.join(sorted(reasons))}"
        findings.append(
            make_finding(
                rule_id="SG011",
                title="MCP tool metadata risk detected",
                description=(
                    "Declared MCP tool metadata contains hidden instructions, suspicious names, "
                    "or high-risk input schema fields."
                ),
                severity="high",
                capability="mcp_tool_metadata",
                file_path=server.source_file,
                line_number=None,
                evidence=evidence,
                remediation="Review declared tools before enabling or publishing the MCP server.",
            )
        )
        capabilities.append(
            make_capability(
                "mcp_tool_metadata",
                server.source_file,
                None,
                resource=f"{server.name}.{name}",
                **details,
            )
        )
    return findings, capabilities


def app_surface_findings(
    data: dict[str, Any], source_file: str
) -> tuple[list[Finding], list[Capability]]:
    serialized = json.dumps(data, sort_keys=True)
    if not MID_SESSION_TOOL_RE.search(serialized):
        return [], []
    origins = sorted(
        set(
            urlparse(match.group(0)).hostname or match.group(0)
            for match in URL_RE.finditer(serialized)
        )
    )
    details = {"origins": origins, "surface": "mcp_app_metadata"}
    finding = make_finding(
        rule_id="SG011",
        title="MCP app tool surface metadata detected",
        description=(
            "MCP app or WebMCP-style metadata declares dynamic tool surface hints that need review."
        ),
        severity="medium",
        capability="mcp_tool_metadata",
        file_path=source_file,
        line_number=None,
        evidence="MCP app metadata includes mid-session tool registration concepts.",
        remediation="Review dynamic tool registration and UI/resource origins before enabling.",
    )
    capability = make_capability(
        "mcp_tool_metadata",
        source_file,
        None,
        resource="mcp_app_metadata",
        **details,
    )
    return [finding], [capability]


def transport_findings(server: RegistryServer) -> tuple[list[Finding], list[Capability]]:
    findings: list[Finding] = []
    capabilities: list[Capability] = []

    def add(title: str, severity: str, evidence: str, details: dict[str, object]) -> None:
        findings.append(
            make_finding(
                rule_id="SG012",
                title=title,
                description=(
                    "Declared MCP transport metadata uses a known dangerous transport shape."
                ),
                severity=severity,  # type: ignore[arg-type]
                capability="mcp_transport_risk",
                file_path=server.source_file,
                line_number=None,
                evidence=evidence,
                remediation="Prefer authenticated remote transports or reviewed pinned commands.",
            )
        )
        capabilities.append(
            make_capability(
                "mcp_transport_risk",
                server.source_file,
                None,
                resource=server.name,
                server=server.name,
                config_path=server.config_path,
                **details,
            )
        )

    for index, remote in enumerate(list_of_dicts(server.data.get("remotes"))):
        url = remote.get("url") or remote.get("serverUrl") or remote.get("endpoint")
        remote_type = remote.get("type") if isinstance(remote.get("type"), str) else None
        secret_headers = [
            name for name in header_names(remote.get("headers")) if SECRET_HEADER_RE.search(name)
        ]
        if isinstance(url, str):
            if host_is_local_or_private(url):
                add(
                    "MCP remote transport bridges to local or private network",
                    "high",
                    f"Remote {index}: {url}",
                    {"url": url, "transport_type": remote_type},
                )
            if not remote_has_auth(remote) and not host_is_local_or_private(url):
                add(
                    "MCP remote transport does not declare authentication",
                    "medium",
                    f"Remote {index}: {url}",
                    {"url": url, "transport_type": remote_type},
                )
        for name in secret_headers:
            add(
                "MCP remote transport requires secret-bearing header",
                "high",
                f"Remote {index} header: {name}",
                {"header": name, "url": url, "transport_type": remote_type},
            )

    for index, package in enumerate(list_of_dicts(server.data.get("packages"))):
        transport = package.get("transport")
        transport_type = transport.get("type") if isinstance(transport, dict) else None
        identifier = package.get("identifier") or package.get("name") or f"package.{index}"
        if transport_type == "stdio":
            add(
                "MCP package uses stdio transport",
                "medium",
                f"Package {identifier}: stdio",
                {"package": str(identifier), "transport_type": "stdio"},
            )
        command = (
            transport.get("command") if isinstance(transport, dict) else package.get("command")
        )
        if isinstance(command, str) and command.lower() in SHELL_WRAPPERS:
            add(
                "MCP stdio transport invokes a shell wrapper",
                "high",
                f"Package {identifier}: {command}",
                {"command": command, "package": str(identifier), "transport_type": transport_type},
            )
        for value in collect_string_values(package):
            if value.split() and value.split()[0].lower() in SHELL_WRAPPERS:
                add(
                    "MCP stdio transport contains shell-wrapper command",
                    "high",
                    f"Package {identifier}: {value.split()[0]}",
                    {"package": str(identifier), "transport_type": transport_type},
                )
                break
    return findings, capabilities


def registry_server_capability(server: RegistryServer) -> Capability:
    compatibility = inventory_mcp_compatibility(
        server.data,
        declaration_path=server.config_path,
        scope=f"registry:{server.name}",
    )
    apps = inventory_mcp_apps(
        server.data,
        declaration_path=server.config_path,
        scope=f"registry:{server.name}",
    )
    details = {
        "server": server.name,
        "config_path": server.config_path,
        "description": server.data.get("description")
        if isinstance(server.data.get("description"), str)
        else None,
        "repository": repository_url(server.data),
        "version": server.data.get("version")
        if isinstance(server.data.get("version"), str)
        else None,
        "remote_urls": remote_urls(server.data),
        "transport_types": transport_types(server.data),
        "packages": package_identifiers(server.data),
        "secret_headers": secret_header_names(server.data),
        **compatibility_details(compatibility),
        **mcp_apps_summary(apps),
    }
    return make_capability(
        "mcp_registry_server", server.source_file, None, resource=server.name, **details
    )


def analyze_registry_file(file: FileContent):
    from skillgate.rules.base import RuleResult

    if file.file_type not in {"mcp_registry", "json_config"}:
        return RuleResult()
    data = parse_json_object(file.text)
    if data is None or not is_registry_document(data):
        return RuleResult()
    result = RuleResult()
    servers = iter_registry_servers(data, file.path)
    for server in servers:
        result.capabilities.append(registry_server_capability(server))
        compatibility = inventory_mcp_compatibility(
            server.data,
            declaration_path=server.config_path,
            scope=f"registry:{server.name}",
        )
        result.capabilities.extend(
            compatibility_capabilities(compatibility, source_file=server.source_file)
        )
        apps = inventory_mcp_apps(
            server.data,
            declaration_path=server.config_path,
            scope=f"registry:{server.name}",
        )
        result.capabilities.extend(mcp_apps_capabilities(apps, source_file=server.source_file))
        result.findings.extend(mcp_apps_findings(apps, source_file=server.source_file))
        findings, capabilities = tool_metadata_findings(server)
        result.findings.extend(findings)
        result.capabilities.extend(capabilities)
        findings, capabilities = transport_findings(server)
        result.findings.extend(findings)
        result.capabilities.extend(capabilities)
    findings, capabilities = app_surface_findings(data, file.path)
    result.findings.extend(findings)
    result.capabilities.extend(capabilities)
    return result


class McpRegistryMetadataRule:
    rule_id = "SG011"
    title = "MCP registry and tool metadata risk detected"
    default_severity = "high"

    def analyze(self, file: FileContent):
        return analyze_registry_file(file)


def registry_candidate_paths(path: Path) -> tuple[Path, list[Path]]:
    path = path.resolve()
    if path.is_file():
        return path.parent, [path]
    discovered = [
        item
        for item in discover_paths(path)
        if classify_file(item) in {"mcp_registry", "json_config"}
    ]
    return path, discovered


def collect_registry_servers(path: Path) -> list[RegistryServer]:
    root, paths = registry_candidate_paths(path)
    servers: list[RegistryServer] = []
    for item in paths:
        try:
            data = parse_json_object(item.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            raise RegistryMetadataError(f"unable to read {item}") from exc
        if data is None:
            continue
        rel = item.resolve().relative_to(root.resolve()).as_posix()
        servers.extend(iter_registry_servers(data, rel))
    return sorted(servers, key=lambda server: (server.source_file, server.name))


def scan_registry_path(path: Path) -> ScanReport:
    from skillgate.scan import (
        findings_summary,
        load_file_content,
        unique_capabilities,
        unique_findings,
    )

    root, paths = registry_candidate_paths(path)
    rule = McpRegistryMetadataRule()
    scanned_files = [scan_file_metadata(root, item) for item in paths]
    findings: list[Finding] = []
    capabilities: list[Capability] = []
    for item in paths:
        file = load_file_content(root, item, classify_file(item))
        result = rule.analyze(file)
        findings.extend(result.findings)
        capabilities.extend(result.capabilities)
    findings = unique_findings(findings)
    capabilities = unique_capabilities(capabilities)
    return ScanReport(
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        scan_root=".",
        scanned_files=sorted(scanned_files, key=lambda item: item.path),
        capabilities=capabilities,
        findings=findings,
        summary=findings_summary(findings, len(scanned_files), len(capabilities)),
    )


def registry_scan_text(report: ScanReport) -> str:
    lines = [
        "SkillGate MCP registry scan completed",
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


def registry_drift_rows(report: ScanReport) -> list[dict[str, Any]]:
    summary_rows = report.summary.get("registry_drift")
    if isinstance(summary_rows, list):
        return [row for row in summary_rows if isinstance(row, dict)]
    rows = []
    for capability in report.capabilities:
        if capability.type != "mcp_registry_drift":
            continue
        rows.append(
            {
                "server": capability.details.get("server") or "",
                "field": capability.details.get("field") or "",
                "local": capability.details.get("local"),
                "registry": capability.details.get("registry"),
                "source_file": capability.source_file,
                "registry_url": capability.details.get("registry_url") or "",
            }
        )
    return rows


def markdown_cell(value: object) -> str:
    text = json.dumps(value, sort_keys=True) if isinstance(value, dict | list) else str(value)
    text = " ".join(text.split())
    if len(text) > 180:
        text = text[:177] + "..."
    return text.replace("|", "\\|")


def registry_compare_markdown(report: ScanReport) -> str:
    rows = registry_drift_rows(report)
    lines = [
        "# SkillGate MCP Registry Comparison",
        "",
        f"Findings: {len([finding for finding in report.findings if finding.rule_id == 'SG013'])}",
        "",
        "## Registry Drift",
    ]
    if not rows:
        lines.append("None.")
        return "\n".join(lines) + "\n"
    lines.extend(
        [
            "| Field | Local | Registry | Source |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in rows:
        source = f"{row.get('source_file')} via {row.get('registry_url')}"
        lines.append(
            "| "
            + " | ".join(
                [
                    markdown_cell(row.get("field")),
                    markdown_cell(row.get("local")),
                    markdown_cell(row.get("registry")),
                    markdown_cell(source),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def fetch_registry_index(url: str) -> dict[str, Any]:
    local_path = Path(url)
    if local_path.exists():
        return load_registry_index_file(local_path)
    parsed = urlparse(url)
    if parsed.scheme == "file":
        path = Path(unquote(parsed.path))
        if parsed.netloc and not path.drive:
            path = Path(f"//{parsed.netloc}{path.as_posix()}")
        return load_registry_index_file(path)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RegistryMetadataError(f"registry request failed with HTTP {exc.code}: {url}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RegistryMetadataError(f"registry request failed: {url}") from exc
    if not isinstance(data, dict):
        raise RegistryMetadataError("registry response must be a JSON object")
    return data


def load_registry_index_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryMetadataError(f"unable to read registry metadata file: {path}") from exc
    if not isinstance(data, dict):
        raise RegistryMetadataError(f"registry metadata file must contain a JSON object: {path}")
    return data


def find_registry_server(data: dict[str, Any], name: str) -> RegistryServer | None:
    matches = [
        server
        for server in iter_registry_servers(data, "<registry>")
        if server.name.lower() == name.lower()
    ]
    if not matches:
        return None
    latest = [
        server
        for server in matches
        if isinstance(server.data.get("_meta"), dict)
        and "isLatest" in json.dumps(server.data["_meta"])
        and "true" in json.dumps(server.data["_meta"]).lower()
    ]
    return sorted(latest or matches, key=lambda server: server.data.get("version") or "")[-1]


def compare_values(
    local: RegistryServer,
    remote: RegistryServer,
) -> list[tuple[str, object, object]]:
    local_compatibility = compatibility_details(
        inventory_mcp_compatibility(
            local.data,
            declaration_path=local.config_path,
            scope=f"registry:{local.name}",
        )
    )
    remote_compatibility = compatibility_details(
        inventory_mcp_compatibility(
            remote.data,
            declaration_path=remote.config_path,
            scope=f"registry:{remote.name}",
        )
    )
    local_apps = mcp_apps_details_for_compare(local)
    remote_apps = mcp_apps_details_for_compare(remote)
    fields: list[tuple[str, object, object]] = [
        ("repository", repository_url(local.data), repository_url(remote.data)),
        ("version", local.data.get("version"), remote.data.get("version")),
        ("remote_urls", remote_urls(local.data), remote_urls(remote.data)),
        ("transport_types", transport_types(local.data), transport_types(remote.data)),
        ("packages", package_identifiers(local.data), package_identifiers(remote.data)),
        ("secret_headers", secret_header_names(local.data), secret_header_names(remote.data)),
        (
            "protocol_versions",
            local_compatibility["protocol_versions"],
            remote_compatibility["protocol_versions"],
        ),
        ("extensions", local_compatibility["extensions"], remote_compatibility["extensions"]),
        (
            "unknown_declarations",
            local_compatibility["unknown_declarations"],
            remote_compatibility["unknown_declarations"],
        ),
        ("mcp_apps", local_apps, remote_apps),
    ]
    return [(field, left, right) for field, left, right in fields if left != right]


def mcp_apps_details_for_compare(server: RegistryServer) -> dict[str, object]:
    details = mcp_apps_summary(
        inventory_mcp_apps(
            server.data,
            declaration_path=server.config_path,
            scope=f"registry:{server.name}",
        )
    )
    return details.get("mcp_apps", {}) if details else {}


def compare_registry_metadata(
    path: Path,
    server_name: str,
    registry_url: str = DEFAULT_REGISTRY_URL,
) -> ScanReport:
    from skillgate.scan import findings_summary, unique_capabilities, unique_findings

    locals_by_name = {server.name.lower(): server for server in collect_registry_servers(path)}
    local = locals_by_name.get(server_name.lower())
    if local is None:
        raise RegistryMetadataError(f"local MCP registry metadata did not include {server_name}")
    remote_data = fetch_registry_index(registry_url)
    remote = find_registry_server(remote_data, server_name)
    if remote is None:
        raise RegistryMetadataError(f"registry metadata did not include {server_name}")

    report = scan_registry_path(path)
    findings = list(report.findings)
    capabilities = list(report.capabilities)
    drift_rows = []
    for field, local_value, remote_value in compare_values(local, remote):
        drift_rows.append(
            {
                "server": server_name,
                "field": field,
                "local": local_value,
                "registry": remote_value,
                "source_file": local.source_file,
                "registry_url": registry_url,
            }
        )
        evidence = (
            f"{server_name} {field}: local={json.dumps(local_value, sort_keys=True)} "
            f"registry={json.dumps(remote_value, sort_keys=True)}"
        )
        findings.append(
            make_finding(
                rule_id="SG013",
                title="MCP registry metadata drift detected",
                description="Local MCP registry metadata differs from remote registry metadata.",
                severity="high",
                capability="mcp_registry_drift",
                file_path=local.source_file,
                line_number=None,
                evidence=evidence,
                remediation="Review and align declared MCP registry metadata before release.",
            )
        )
        capabilities.append(
            make_capability(
                "mcp_registry_drift",
                local.source_file,
                None,
                resource=f"{server_name}:{field}",
                field=field,
                local=local_value,
                registry=remote_value,
                registry_url=registry_url,
                server=server_name,
            )
        )
    findings = unique_findings(findings)
    capabilities = unique_capabilities(capabilities)
    return report.model_copy(
        update={
            "findings": findings,
            "capabilities": capabilities,
            "summary": {
                **findings_summary(findings, len(report.scanned_files), len(capabilities)),
                "registry_drift": drift_rows,
            },
        }
    )
