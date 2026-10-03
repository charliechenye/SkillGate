"""Static Agent Plugins 1.0 local-directory inventory.

This module intentionally stops at package structure, component status,
provenance context, and coverage. It does not scan aggregate capabilities,
evaluate policy, compute drift, execute commands, contact MCP servers, fetch
schemas, or interpret client extensions.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from skillgate.skills import (
    SKILL_FILE,
    SkillsValidationError,
    validate_skill_file,
)

AGENT_PLUGINS_FORMAT = "agent_plugins"
AGENT_PLUGINS_SPEC_VERSION = "1.0.0"
PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"

_MANIFEST_FIELDS = frozenset(
    {
        "$schema",
        "name",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
        "extensions",
    }
)
_MCP_FIELDS = frozenset({"$schema", "mcpServers"})
_STDIO_FIELDS = frozenset({"type", "command", "args", "env", "cwd"})
_HTTP_FIELDS = frozenset({"type", "url", "headers"})
_TRANSPORTS = frozenset({"stdio", "streamable-http", "sse"})
_FATAL_SKILL_FINDINGS = frozenset(
    {"SKILL001", "SKILL002", "SKILL003", "SKILL004", "SKILL006", "SKILL008"}
)
_EXTENSION_NAMESPACE_RE = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9-]+)+$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass(frozen=True)
class AgentPluginDiagnostic:
    code: str
    message: str
    path: str | None = None

    def to_data(self) -> dict[str, str]:
        data = {"code": self.code, "message": self.message}
        if self.path is not None:
            data["path"] = self.path
        return data


@dataclass(frozen=True)
class AgentPluginManifest:
    status: str
    schema: str | None
    name: str | None
    version: str | None
    path: str
    diagnostics: tuple[AgentPluginDiagnostic, ...] = ()

    def to_data(self) -> dict[str, object]:
        return {
            "status": self.status,
            "schema": self.schema,
            "name": self.name,
            "version": self.version,
            "path": self.path,
            "diagnostics": [item.to_data() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class AgentPluginSkill:
    name: str | None
    path: str
    status: str
    diagnostics: tuple[AgentPluginDiagnostic, ...] = ()

    @property
    def identity(self) -> str:
        return self.name or self.path

    def to_data(self) -> dict[str, object]:
        return {
            "identity": self.identity,
            "name": self.name,
            "path": self.path,
            "status": self.status,
            "diagnostics": [item.to_data() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class AgentPluginMcpServer:
    name: str
    transport: str | None
    path: str
    status: str
    diagnostics: tuple[AgentPluginDiagnostic, ...] = ()
    declared_fields: tuple[str, ...] = ()

    def to_data(self) -> dict[str, object]:
        return {
            "name": self.name,
            "transport": self.transport,
            "path": self.path,
            "status": self.status,
            "declared_fields": list(self.declared_fields),
            "diagnostics": [item.to_data() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class AgentPluginMcp:
    status: str
    path: str
    servers: tuple[AgentPluginMcpServer, ...] = ()
    diagnostics: tuple[AgentPluginDiagnostic, ...] = ()

    def to_data(self) -> dict[str, object]:
        return {
            "status": self.status,
            "path": self.path,
            "servers": [item.to_data() for item in self.servers],
            "diagnostics": [item.to_data() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class AgentPluginExtension:
    namespace: str
    manifest_data_present: bool
    directory_present: bool
    status: str = "unknown"
    diagnostics: tuple[AgentPluginDiagnostic, ...] = ()

    def to_data(self) -> dict[str, object]:
        return {
            "namespace": self.namespace,
            "manifest_data_present": self.manifest_data_present,
            "directory_present": self.directory_present,
            "status": self.status,
            "diagnostics": [item.to_data() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class AgentPluginCoverageCounts:
    discovered: int = 0
    reviewed: int = 0
    invalid: int = 0
    skipped: int = 0
    unknown: int = 0

    def to_data(self) -> dict[str, int]:
        return {
            "discovered": self.discovered,
            "reviewed": self.reviewed,
            "invalid": self.invalid,
            "skipped": self.skipped,
            "unknown": self.unknown,
        }


@dataclass(frozen=True)
class AgentPluginCoverage:
    portable_core: str
    overall_artifact: str
    portable_core_counts: AgentPluginCoverageCounts
    overall_counts: AgentPluginCoverageCounts

    def to_data(self) -> dict[str, object]:
        return {
            "portable_core": self.portable_core,
            "overall_artifact": self.overall_artifact,
            "portable_core_counts": self.portable_core_counts.to_data(),
            "overall_counts": self.overall_counts.to_data(),
        }


@dataclass(frozen=True)
class AgentPluginProvenanceEntry:
    component: str
    path: str
    status: str

    def to_data(self) -> dict[str, str]:
        return {
            "component": self.component,
            "path": self.path,
            "status": self.status,
        }


@dataclass(frozen=True)
class AgentPluginProvenance:
    root: str
    entries: tuple[AgentPluginProvenanceEntry, ...]

    def to_data(self) -> dict[str, object]:
        return {
            "root": self.root,
            "entries": [item.to_data() for item in self.entries],
        }


@dataclass(frozen=True)
class AgentPluginInventory:
    format: str
    spec_version: str | None
    status: str
    manifest: AgentPluginManifest
    skills: tuple[AgentPluginSkill, ...]
    skills_status: str
    mcp: AgentPluginMcp
    extensions: tuple[AgentPluginExtension, ...]
    coverage: AgentPluginCoverage
    unknown_surfaces: tuple[str, ...]
    diagnostics: tuple[AgentPluginDiagnostic, ...]
    provenance: AgentPluginProvenance

    def to_data(self) -> dict[str, object]:
        return {
            "format": self.format,
            "spec_version": self.spec_version,
            "status": self.status,
            "manifest": self.manifest.to_data(),
            "skills": [item.to_data() for item in self.skills],
            "skills_component": {
                "path": "skills",
                "status": self.skills_status,
            },
            "mcp": self.mcp.to_data(),
            "extensions": [item.to_data() for item in self.extensions],
            "coverage": self.coverage.to_data(),
            "unknown_surfaces": list(self.unknown_surfaces),
            "diagnostics": [item.to_data() for item in self.diagnostics],
            "provenance": self.provenance.to_data(),
        }


def _diagnostic(code: str, message: str, path: str | None = None) -> AgentPluginDiagnostic:
    return AgentPluginDiagnostic(code=code, message=message, path=path)


def _sorted_diagnostics(
    diagnostics: list[AgentPluginDiagnostic],
) -> tuple[AgentPluginDiagnostic, ...]:
    return tuple(sorted(diagnostics, key=lambda item: (item.path or "", item.code, item.message)))


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _resolve_inside(root: Path, path: Path) -> Path | None:
    try:
        resolved = path.resolve()
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    return resolved


def _read_json(path: Path, label: str) -> tuple[object | None, AgentPluginDiagnostic | None]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None, _diagnostic("json_unreadable", f"{label} could not be read safely", label)
    try:
        return json.loads(text), None
    except json.JSONDecodeError:
        return None, _diagnostic("json_invalid", f"{label} is not valid JSON", label)


def _validate_name(value: object) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return False
    return bool(re.fullmatch(r"(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value))


def _validate_manifest(
    data: dict[str, object],
) -> tuple[AgentPluginManifest, list[AgentPluginDiagnostic]]:
    diagnostics: list[AgentPluginDiagnostic] = []
    schema = data.get("$schema")
    name = data.get("name")
    version = data.get("version") if isinstance(data.get("version"), str) else None

    for field in sorted(set(data) - _MANIFEST_FIELDS):
        diagnostics.append(
            _diagnostic(
                "manifest_unknown_field",
                "unknown top-level manifest field is ignored",
                f"plugin.json.{field}",
            )
        )

    fatal = False
    if schema != PLUGIN_SCHEMA:
        fatal = True
        code = "manifest_missing_schema" if "$schema" not in data else "manifest_unsupported_schema"
        diagnostics.append(
            _diagnostic(
                code,
                "plugin.json must declare the supported Agent Plugins 1.0 schema",
                "plugin.json.$schema",
            )
        )
    if not _validate_name(name):
        fatal = True
        diagnostics.append(
            _diagnostic(
                "manifest_invalid_name",
                "plugin.json.name must satisfy the Agent Plugins plugin-name constraints",
                "plugin.json.name",
            )
        )

    string_fields = ("version", "description", "homepage", "repository", "license")
    for field in string_fields:
        if field in data and not isinstance(data[field], str):
            fatal = True
            diagnostics.append(
                _diagnostic(
                    "manifest_invalid_field",
                    f"plugin.json.{field} must be a string",
                    f"plugin.json.{field}",
                )
            )

    author = data.get("author")
    if "author" in data:
        if not isinstance(author, dict):
            fatal = True
            diagnostics.append(
                _diagnostic(
                    "manifest_invalid_field",
                    "plugin.json.author must be an object",
                    "plugin.json.author",
                )
            )
        else:
            for field in sorted(set(author) - {"name", "email", "url"}):
                fatal = True
                diagnostics.append(
                    _diagnostic(
                        "manifest_invalid_field",
                        "plugin.json.author contains an unsupported field",
                        f"plugin.json.author.{field}",
                    )
                )
            for field in ("name", "email", "url"):
                if field in author and not isinstance(author[field], str):
                    fatal = True
                    diagnostics.append(
                        _diagnostic(
                            "manifest_invalid_field",
                            f"plugin.json.author.{field} must be a string",
                            f"plugin.json.author.{field}",
                        )
                    )

    keywords = data.get("keywords")
    if keywords is not None and (
        not isinstance(keywords, list) or not all(isinstance(item, str) for item in keywords)
    ):
        fatal = True
        diagnostics.append(
            _diagnostic(
                "manifest_invalid_field",
                "plugin.json.keywords must be an array of strings",
                "plugin.json.keywords",
            )
        )

    extensions = data.get("extensions")
    if extensions is not None and not isinstance(extensions, dict):
        diagnostics.append(
            _diagnostic(
                "manifest_extensions_ignored",
                "non-object plugin.json.extensions is ignored by the Agent Plugins contract",
                "plugin.json.extensions",
            )
        )
    elif isinstance(extensions, dict):
        for namespace in sorted(extensions):
            if not isinstance(extensions[namespace], dict):
                fatal = True
                diagnostics.append(
                    _diagnostic(
                        "manifest_invalid_field",
                        "extension manifest data must be an object",
                        f"plugin.json.extensions.{namespace}",
                    )
                )

    manifest = AgentPluginManifest(
        status="invalid" if fatal else "valid",
        schema=schema if isinstance(schema, str) else None,
        name=name if isinstance(name, str) else None,
        version=version,
        path="plugin.json",
        diagnostics=_sorted_diagnostics(diagnostics),
    )
    return manifest, diagnostics


def _empty_mcp(status: str = "not_applicable") -> AgentPluginMcp:
    return AgentPluginMcp(status=status, path="mcp.json")


def _invalid_skill(path: str, diagnostics: list[AgentPluginDiagnostic]) -> AgentPluginSkill:
    return AgentPluginSkill(
        name=None,
        path=path,
        status="skipped"
        if any(item.code == "skill_path_outside_plugin_root" for item in diagnostics)
        else "invalid",
        diagnostics=_sorted_diagnostics(diagnostics),
    )


def _load_skills(root: Path) -> tuple[list[AgentPluginSkill], str, list[AgentPluginDiagnostic]]:
    location = root / "skills"
    if not location.exists() and not location.is_symlink():
        return [], "absent", []

    relative_location = "skills"
    resolved_location = _resolve_inside(root, location)
    if resolved_location is None:
        return (
            [],
            "invalid",
            [
                _diagnostic(
                    "skills_path_outside_plugin_root",
                    "skills/ resolves outside the plugin root",
                    relative_location,
                )
            ],
        )
    if not resolved_location.is_dir():
        return (
            [],
            "invalid",
            [
                _diagnostic(
                    "skills_location_invalid",
                    "skills/ must resolve to a directory",
                    relative_location,
                )
            ],
        )

    skills: list[AgentPluginSkill] = []
    diagnostics: list[AgentPluginDiagnostic] = []
    try:
        children = sorted(resolved_location.iterdir(), key=lambda item: item.name)
    except OSError:
        return (
            [],
            "invalid",
            [
                _diagnostic(
                    "skills_unreadable", "skills/ could not be listed safely", relative_location
                )
            ],
        )

    for child in children:
        skill_candidate = child / SKILL_FILE
        if not child.is_dir() and not child.is_symlink():
            continue
        if not skill_candidate.exists() and not skill_candidate.is_symlink():
            continue
        skill_path = _relative(root, skill_candidate)
        resolved_skill = _resolve_inside(root, skill_candidate)
        if resolved_skill is None:
            skill_diagnostics = [
                _diagnostic(
                    "skill_path_outside_plugin_root",
                    "discovered SKILL.md resolves outside the plugin root",
                    skill_path,
                )
            ]
            skill = _invalid_skill(skill_path, skill_diagnostics)
            skills.append(skill)
            diagnostics.extend(skill_diagnostics)
            continue
        if not resolved_skill.is_file():
            skill_diagnostics = [
                _diagnostic(
                    "skill_not_regular_file",
                    "discovered SKILL.md must resolve to a regular file",
                    skill_path,
                )
            ]
            skill = _invalid_skill(skill_path, skill_diagnostics)
            skills.append(skill)
            diagnostics.extend(skill_diagnostics)
            continue

        try:
            skill_data, findings = validate_skill_file(resolved_skill, root)
        except (OSError, SkillsValidationError):
            skill_diagnostics = [
                _diagnostic(
                    "skill_unreadable", "discovered skill could not be validated safely", skill_path
                )
            ]
            skill = _invalid_skill(skill_path, skill_diagnostics)
            skills.append(skill)
            diagnostics.extend(skill_diagnostics)
            continue

        skill_diagnostics = [
            _diagnostic(
                str(finding.get("code", "skill_validation")),
                str(finding.get("description", "Agent Skill validation finding")),
                f"{skill_path}:{finding.get('line_number', 1)}",
            )
            for finding in findings
        ]
        status = (
            "invalid"
            if any(str(finding.get("code")) in _FATAL_SKILL_FINDINGS for finding in findings)
            else "valid"
        )
        skill = AgentPluginSkill(
            name=skill_data.get("name") if isinstance(skill_data.get("name"), str) else None,
            path=skill_data.get("path", skill_path),
            status=status,
            diagnostics=_sorted_diagnostics(skill_diagnostics),
        )
        skills.append(skill)
        diagnostics.extend(skill_diagnostics)

    skills.sort(key=lambda item: item.path)
    status = "partial" if any(item.status in {"invalid", "skipped"} for item in skills) else "valid"
    return skills, status, diagnostics


def _path_inside_root(root: Path, value: str) -> bool:
    return _resolve_inside(root, root / value[2:]) is not None


def _data_path_is_contained(value: str) -> bool:
    suffix = value[len("${PLUGIN_DATA}") :]
    if suffix and not suffix.startswith("/"):
        return False
    parts = [part for part in suffix.replace("\\", "/").split("/") if part not in {"", "."}]
    depth = 0
    for part in parts:
        if part == "..":
            depth -= 1
            if depth < 0:
                return False
        else:
            depth += 1
    return True


def _validate_cwd(root: Path, value: object, path: str) -> list[AgentPluginDiagnostic]:
    if not isinstance(value, str):
        return [_diagnostic("mcp_invalid_cwd", "stdio cwd must be a string", path)]
    if value.startswith("./"):
        if not _path_inside_root(root, value):
            return [
                _diagnostic(
                    "mcp_cwd_outside_plugin_root", "stdio cwd escapes the plugin root", path
                )
            ]
        return []
    if value == "${PLUGIN_ROOT}" or value.startswith("${PLUGIN_ROOT}/"):
        root_value = "./" + value[len("${PLUGIN_ROOT}") :].lstrip("/")
        if not _path_inside_root(root, root_value):
            return [
                _diagnostic(
                    "mcp_cwd_outside_plugin_root", "stdio cwd escapes the plugin root", path
                )
            ]
        return []
    if value == "${PLUGIN_DATA}" or value.startswith("${PLUGIN_DATA}/"):
        if not _data_path_is_contained(value):
            return [
                _diagnostic("mcp_cwd_outside_plugin_data", "stdio cwd escapes PLUGIN_DATA", path)
            ]
        return []
    return [
        _diagnostic(
            "mcp_invalid_cwd",
            "stdio cwd must use ./, ${PLUGIN_ROOT}, or ${PLUGIN_DATA}",
            path,
        )
    ]


def _validate_command(root: Path, value: object, path: str) -> list[AgentPluginDiagnostic]:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(char.isspace() for char in value)
    ):
        return [
            _diagnostic("mcp_invalid_command", "stdio command must be one executable token", path)
        ]
    if value.startswith("./"):
        if not _path_inside_root(root, value):
            return [
                _diagnostic(
                    "mcp_command_outside_plugin_root", "stdio command escapes the plugin root", path
                )
            ]
        return []
    if "/" in value or "\\" in value or value.startswith(".") or value.startswith("$"):
        return [
            _diagnostic("mcp_invalid_command", "stdio command must be bare or begin with ./", path)
        ]
    return []


def _validate_headers(value: object, path: str) -> list[AgentPluginDiagnostic]:
    if not isinstance(value, dict):
        return [
            _diagnostic("mcp_invalid_headers", "HTTP headers must be an object of strings", path)
        ]
    diagnostics: list[AgentPluginDiagnostic] = []
    seen: set[str] = set()
    for name, header_value in sorted(value.items()):
        header_path = f"{path}.{name}"
        if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
            diagnostics.append(
                _diagnostic("mcp_invalid_header_name", "HTTP header name is invalid", header_path)
            )
        elif name.casefold() in seen:
            diagnostics.append(
                _diagnostic(
                    "mcp_duplicate_header",
                    "HTTP header names must be unique ignoring case",
                    header_path,
                )
            )
        else:
            seen.add(name.casefold())
        if not isinstance(header_value, str) or "\r" in header_value or "\n" in header_value:
            diagnostics.append(
                _diagnostic("mcp_invalid_header_value", "HTTP header value is invalid", header_path)
            )
    return diagnostics


def _validate_url(value: object, path: str) -> list[AgentPluginDiagnostic]:
    if not isinstance(value, str) or not value:
        return [_diagnostic("mcp_invalid_url", "HTTP MCP url must be a non-empty string", path)]
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _port = parsed.port
    except ValueError:
        hostname = None
        parsed = None
    if (
        parsed is None
        or parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not hostname
    ):
        return [
            _diagnostic("mcp_invalid_url", "HTTP MCP url must be an absolute HTTP(S) URL", path)
        ]
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        return [
            _diagnostic(
                "mcp_invalid_url", "HTTP MCP url must not contain userinfo or a fragment", path
            )
        ]
    if parsed.scheme == "http":
        loopback = hostname.lower() == "localhost"
        if not loopback:
            try:
                loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                loopback = False
        if not loopback:
            return [
                _diagnostic("mcp_insecure_url", "non-loopback HTTP MCP urls must use HTTPS", path)
            ]
    return []


def _validate_server(
    root: Path,
    name: str,
    config: object,
) -> AgentPluginMcpServer:
    declaration_path = f"mcp.json.mcpServers.{name}"
    diagnostics: list[AgentPluginDiagnostic] = []
    if not isinstance(config, dict):
        diagnostics.append(
            _diagnostic(
                "mcp_server_not_object", "MCP server entry must be an object", declaration_path
            )
        )
        return AgentPluginMcpServer(
            name, None, declaration_path, "invalid", _sorted_diagnostics(diagnostics)
        )

    declared_fields = tuple(sorted(str(field) for field in config))
    transport = config.get("type") if isinstance(config.get("type"), str) else None
    if transport not in _TRANSPORTS:
        diagnostics.append(
            _diagnostic(
                "mcp_invalid_transport",
                "MCP server type is unsupported",
                f"{declaration_path}.type",
            )
        )
        return AgentPluginMcpServer(
            name,
            transport,
            declaration_path,
            "invalid",
            _sorted_diagnostics(diagnostics),
            declared_fields,
        )

    allowed_fields = _STDIO_FIELDS if transport == "stdio" else _HTTP_FIELDS
    for field in sorted(set(config) - allowed_fields):
        diagnostics.append(
            _diagnostic(
                "mcp_server_unknown_field",
                "MCP server field is not allowed for this transport",
                f"{declaration_path}.{field}",
            )
        )

    if transport == "stdio":
        diagnostics.extend(
            _validate_command(root, config.get("command"), f"{declaration_path}.command")
        )
        if "args" in config and (
            not isinstance(config["args"], list)
            or not all(isinstance(item, str) for item in config["args"])
        ):
            diagnostics.append(
                _diagnostic(
                    "mcp_invalid_args",
                    "stdio args must be an array of strings",
                    f"{declaration_path}.args",
                )
            )
        if "env" in config:
            env = config["env"]
            if not isinstance(env, dict) or not all(isinstance(item, str) for item in env.values()):
                diagnostics.append(
                    _diagnostic(
                        "mcp_invalid_env",
                        "stdio env must be an object of strings",
                        f"{declaration_path}.env",
                    )
                )
            elif "PLUGIN_ROOT" in env or "PLUGIN_DATA" in env:
                diagnostics.append(
                    _diagnostic(
                        "mcp_reserved_env",
                        "stdio env must not override reserved plugin variables",
                        f"{declaration_path}.env",
                    )
                )
        if "cwd" in config:
            diagnostics.extend(_validate_cwd(root, config["cwd"], f"{declaration_path}.cwd"))
    else:
        diagnostics.extend(_validate_url(config.get("url"), f"{declaration_path}.url"))
        if "headers" in config:
            diagnostics.extend(_validate_headers(config["headers"], f"{declaration_path}.headers"))

    return AgentPluginMcpServer(
        name,
        transport,
        declaration_path,
        "valid" if not diagnostics else "invalid",
        _sorted_diagnostics(diagnostics),
        declared_fields,
    )


def _load_mcp(root: Path, plugin_schema: str) -> AgentPluginMcp:
    path = root / "mcp.json"
    if not path.exists() and not path.is_symlink():
        return _empty_mcp("absent")
    resolved = _resolve_inside(root, path)
    if resolved is None:
        return AgentPluginMcp(
            "invalid",
            "mcp.json",
            diagnostics=(
                _diagnostic(
                    "mcp_path_outside_plugin_root",
                    "mcp.json resolves outside the plugin root",
                    "mcp.json",
                ),
            ),
        )
    if not resolved.is_file():
        return AgentPluginMcp(
            "invalid",
            "mcp.json",
            diagnostics=(
                _diagnostic(
                    "mcp_location_invalid", "mcp.json must resolve to a regular file", "mcp.json"
                ),
            ),
        )

    data, read_diagnostic = _read_json(resolved, "mcp.json")
    if read_diagnostic is not None:
        return AgentPluginMcp("invalid", "mcp.json", diagnostics=(read_diagnostic,))
    if not isinstance(data, dict):
        return AgentPluginMcp(
            "invalid",
            "mcp.json",
            diagnostics=(
                _diagnostic(
                    "mcp_not_object", "mcp.json must contain a top-level object", "mcp.json"
                ),
            ),
        )

    diagnostics: list[AgentPluginDiagnostic] = []
    if data.get("$schema") != MCP_SCHEMA:
        diagnostics.append(
            _diagnostic(
                "mcp_unsupported_schema",
                "mcp.json must declare the supported Agent Plugins 1.0 MCP schema",
                "mcp.json.$schema",
            )
        )
    if data.get("$schema") != plugin_schema.replace("plugin.schema", "mcp.schema"):
        diagnostics.append(
            _diagnostic(
                "mcp_schema_mismatch",
                "mcp.json schema version must match plugin.json",
                "mcp.json.$schema",
            )
        )
    for field in sorted(set(data) - _MCP_FIELDS):
        diagnostics.append(
            _diagnostic(
                "mcp_unknown_field",
                "mcp.json contains an unsupported top-level field",
                f"mcp.json.{field}",
            )
        )
    servers_value = data.get("mcpServers")
    if not isinstance(servers_value, dict):
        diagnostics.append(
            _diagnostic(
                "mcp_servers_invalid",
                "mcp.json.mcpServers must be an object",
                "mcp.json.mcpServers",
            )
        )
    if diagnostics:
        return AgentPluginMcp("invalid", "mcp.json", diagnostics=_sorted_diagnostics(diagnostics))

    servers = tuple(
        _validate_server(root, str(name), servers_value[name]) for name in sorted(servers_value)
    )
    for server in servers:
        diagnostics.extend(server.diagnostics)
    return AgentPluginMcp(
        "valid",
        "mcp.json",
        servers=servers,
        diagnostics=_sorted_diagnostics(diagnostics),
    )


def _extension_is_namespace(name: str) -> bool:
    return bool(_EXTENSION_NAMESPACE_RE.fullmatch(name))


def _load_extensions(
    root: Path,
    manifest_data: dict[str, object],
) -> tuple[list[AgentPluginExtension], list[str], list[AgentPluginDiagnostic]]:
    declared = manifest_data.get("extensions")
    declared_names = sorted(declared) if isinstance(declared, dict) else []
    extensions: dict[str, AgentPluginExtension] = {
        namespace: AgentPluginExtension(namespace, True, False) for namespace in declared_names
    }
    unknown_surfaces: set[str] = set(declared_names)
    diagnostics: list[AgentPluginDiagnostic] = []

    for namespace in declared_names:
        candidate = root / namespace
        if len(Path(namespace).parts) != 1 or namespace in {".", ".."}:
            continue
        extension_diagnostics: list[AgentPluginDiagnostic] = []
        resolved = _resolve_inside(root, candidate)
        if resolved is None:
            extension_diagnostics.append(
                _diagnostic(
                    "extension_path_outside_plugin_root",
                    "extension directory resolves outside the plugin root",
                    namespace,
                )
            )
        elif candidate.exists() or candidate.is_symlink():
            if resolved.is_dir():
                extensions[namespace] = AgentPluginExtension(namespace, True, True)
            else:
                extension_diagnostics.append(
                    _diagnostic(
                        "extension_directory_invalid",
                        "extension path is not a directory",
                        namespace,
                    )
                )
        if extension_diagnostics:
            diagnostics.extend(extension_diagnostics)
            extensions[namespace] = AgentPluginExtension(
                namespace,
                True,
                False,
                diagnostics=_sorted_diagnostics(extension_diagnostics),
            )

    try:
        top_level = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        return (
            sorted(extensions.values(), key=lambda item: item.namespace),
            sorted(unknown_surfaces),
            [_diagnostic("package_listing_failed", "plugin root could not be listed safely", ".")],
        )

    for child in top_level:
        if child.name in {"plugin.json", "mcp.json", "skills"}:
            continue
        if not child.is_dir() and not child.is_symlink():
            continue
        if child.name in extensions:
            continue
        if _extension_is_namespace(child.name):
            resolved = _resolve_inside(root, child)
            if resolved is None or not resolved.is_dir():
                extension_diagnostic = _diagnostic(
                    "extension_path_invalid",
                    "extension directory could not be safely inspected",
                    child.name,
                )
                diagnostics.append(extension_diagnostic)
                extensions[child.name] = AgentPluginExtension(
                    child.name,
                    False,
                    False,
                    diagnostics=(extension_diagnostic,),
                )
                continue
            extensions[child.name] = AgentPluginExtension(child.name, False, True)
            unknown_surfaces.add(child.name)
        else:
            unknown_surfaces.add(_relative(root, child))
            diagnostics.append(
                _diagnostic(
                    "unknown_package_surface",
                    "top-level directory is not a portable component",
                    _relative(root, child),
                )
            )

    return (
        sorted(extensions.values(), key=lambda item: item.namespace),
        sorted(unknown_surfaces),
        diagnostics,
    )


def _counts_for_portable_core(
    manifest: AgentPluginManifest,
    skills_status: str,
    skills: list[AgentPluginSkill],
    mcp: AgentPluginMcp,
) -> AgentPluginCoverageCounts:
    discovered = reviewed = invalid = skipped = 0
    if manifest.status == "valid":
        discovered += 1
        reviewed += 1
    else:
        discovered += 1
        invalid += 1
    if skills_status != "absent":
        discovered += 1
        if skills_status == "invalid":
            invalid += 1
        else:
            reviewed += 1
        for skill in skills:
            discovered += 1
            if skill.status == "valid":
                reviewed += 1
            elif skill.status == "skipped":
                skipped += 1
            else:
                invalid += 1
    if mcp.status != "absent":
        discovered += 1
        if mcp.status == "invalid":
            invalid += 1
        else:
            reviewed += 1
            for server in mcp.servers:
                discovered += 1
                if server.status == "valid":
                    reviewed += 1
                elif server.status == "skipped":
                    skipped += 1
                else:
                    invalid += 1
    return AgentPluginCoverageCounts(discovered, reviewed, invalid, skipped, 0)


def _provenance(
    root: Path,
    manifest: AgentPluginManifest,
    skills_status: str,
    skills: list[AgentPluginSkill],
    mcp: AgentPluginMcp,
    extensions: list[AgentPluginExtension],
    unknown_surfaces: list[str],
) -> AgentPluginProvenance:
    entries = [AgentPluginProvenanceEntry("manifest", "plugin.json", manifest.status)]
    if skills_status != "absent":
        entries.append(AgentPluginProvenanceEntry("skills", "skills", skills_status))
    entries.extend(AgentPluginProvenanceEntry("skill", item.path, item.status) for item in skills)
    if mcp.status != "absent":
        entries.append(AgentPluginProvenanceEntry("mcp", mcp.path, mcp.status))
    entries.extend(
        AgentPluginProvenanceEntry("mcp_server", item.path, item.status) for item in mcp.servers
    )
    entries.extend(
        AgentPluginProvenanceEntry("extension", item.namespace, item.status) for item in extensions
    )
    entries.extend(
        AgentPluginProvenanceEntry("unknown", item, "unknown")
        for item in unknown_surfaces
        if item not in {entry.path for entry in entries}
    )
    return AgentPluginProvenance(
        root.as_posix(), tuple(sorted(entries, key=lambda item: (item.path, item.component)))
    )


def _rejected_inventory(
    root: Path,
    diagnostics: list[AgentPluginDiagnostic],
    manifest: AgentPluginManifest | None = None,
) -> AgentPluginInventory:
    manifest = manifest or AgentPluginManifest(
        "invalid", None, None, None, "plugin.json", _sorted_diagnostics(diagnostics)
    )
    empty_counts = AgentPluginCoverageCounts(discovered=1, invalid=1)
    coverage = AgentPluginCoverage("REJECTED", "REJECTED", empty_counts, empty_counts)
    provenance = AgentPluginProvenance(
        root.as_posix(),
        (AgentPluginProvenanceEntry("manifest", "plugin.json", "invalid"),),
    )
    return AgentPluginInventory(
        AGENT_PLUGINS_FORMAT,
        None,
        "rejected",
        manifest,
        (),
        "not_applicable",
        _empty_mcp(),
        (),
        coverage,
        (),
        _sorted_diagnostics(diagnostics),
        provenance,
    )


def load_agent_plugin(path: Path | str) -> AgentPluginInventory:
    """Load one local Agent Plugins 1.0 directory without executing anything."""
    requested = Path(path).expanduser()
    try:
        root = requested.resolve()
    except (OSError, RuntimeError):
        return _rejected_inventory(
            requested.absolute(),
            [
                _diagnostic(
                    "plugin_root_unreadable", "plugin root could not be resolved safely", "."
                )
            ],
        )
    if not root.is_dir():
        return _rejected_inventory(
            root,
            [
                _diagnostic(
                    "plugin_root_invalid", "Agent Plugin input must be a local directory", "."
                )
            ],
        )

    manifest_path = root / "plugin.json"
    resolved_manifest = _resolve_inside(root, manifest_path)
    if resolved_manifest is None:
        return _rejected_inventory(
            root,
            [
                _diagnostic(
                    "manifest_path_outside_plugin_root",
                    "plugin.json resolves outside the plugin root",
                    "plugin.json",
                )
            ],
        )
    if not resolved_manifest.exists():
        return _rejected_inventory(
            root, [_diagnostic("manifest_missing", "plugin.json is required", "plugin.json")]
        )
    if not resolved_manifest.is_file():
        return _rejected_inventory(
            root,
            [
                _diagnostic(
                    "manifest_location_invalid",
                    "plugin.json must resolve to a regular file",
                    "plugin.json",
                )
            ],
        )

    data, read_diagnostic = _read_json(resolved_manifest, "plugin.json")
    if read_diagnostic is not None:
        return _rejected_inventory(root, [read_diagnostic])
    if not isinstance(data, dict):
        return _rejected_inventory(
            root,
            [
                _diagnostic(
                    "manifest_not_object",
                    "plugin.json must contain a top-level object",
                    "plugin.json",
                )
            ],
        )

    manifest, manifest_diagnostics = _validate_manifest(data)
    if manifest.status != "valid":
        return _rejected_inventory(root, manifest_diagnostics, manifest)

    skills, skills_status, skill_diagnostics = _load_skills(root)
    mcp = _load_mcp(root, manifest.schema or PLUGIN_SCHEMA)
    extensions, unknown_surfaces, extension_diagnostics = _load_extensions(root, data)
    diagnostics = (
        manifest_diagnostics + skill_diagnostics + list(mcp.diagnostics) + extension_diagnostics
    )

    portable_counts = _counts_for_portable_core(manifest, skills_status, skills, mcp)
    portable_incomplete = bool(portable_counts.invalid or portable_counts.skipped)
    portable_status = "INCOMPLETE" if portable_incomplete else "COMPLETE"
    overall_counts = AgentPluginCoverageCounts(
        discovered=portable_counts.discovered + len(unknown_surfaces),
        reviewed=portable_counts.reviewed,
        invalid=portable_counts.invalid,
        skipped=portable_counts.skipped,
        unknown=len(unknown_surfaces),
    )
    overall_status = "INCOMPLETE" if portable_incomplete or unknown_surfaces else "COMPLETE"
    coverage = AgentPluginCoverage(portable_status, overall_status, portable_counts, overall_counts)
    provenance = _provenance(
        root, manifest, skills_status, skills, mcp, extensions, unknown_surfaces
    )
    return AgentPluginInventory(
        AGENT_PLUGINS_FORMAT,
        AGENT_PLUGINS_SPEC_VERSION,
        "loaded",
        manifest,
        tuple(skills),
        skills_status,
        mcp,
        tuple(extensions),
        coverage,
        tuple(unknown_surfaces),
        _sorted_diagnostics(diagnostics),
        provenance,
    )


def inspect_agent_plugin(path: Path | str) -> AgentPluginInventory:
    """Compatibility alias for callers that prefer inspection terminology."""
    return load_agent_plugin(path)


def agent_plugin_to_data(inventory: AgentPluginInventory) -> dict[str, object]:
    """Return deterministic internal data for tests and future adapters."""
    return inventory.to_data()
