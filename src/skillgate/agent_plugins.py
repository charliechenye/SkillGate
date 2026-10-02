"""Static Agent Plugins 1.0 local-directory inventory.

This module intentionally stops at package structure, component status,
provenance context, and coverage. It does not scan aggregate capabilities,
evaluate policy, compute drift, execute commands, contact MCP servers, fetch
schemas, or interpret client extensions.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from skillgate.skills import (
    SKILL_FILE,
    SkillsValidationError,
    SkillValidationResult,
    validate_skill_file_result,
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
_EXTENSION_NAMESPACE_RE = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9-]+)+$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_KNOWN_PACKAGE_METADATA_FILES = frozenset(
    {
        "CHANGELOG",
        "CHANGELOG.md",
        "LICENSE",
        "LICENSE.md",
        "LICENSE.txt",
        "README",
        "README.md",
        "README.txt",
    }
)


@dataclass(frozen=True)
class AgentPluginLimits:
    """Safety limits for inspecting an untrusted local plugin directory."""

    max_manifest_bytes: int = 1_048_576
    max_mcp_bytes: int = 1_048_576
    max_skill_bytes: int = 1_048_576
    max_package_file_bytes: int = 1_048_576
    max_skill_components: int = 128
    max_top_level_entries: int = 256


DEFAULT_AGENT_PLUGIN_LIMITS = AgentPluginLimits()


@dataclass(frozen=True)
class _FileIdentity:
    sha256: str | None = None
    size_bytes: int | None = None
    identity_skipped_reason: str | None = None


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
    conformant: bool = False
    conformance_diagnostics: tuple[AgentPluginDiagnostic, ...] = ()
    advisory_findings: tuple[dict[str, object], ...] = ()

    @property
    def identity(self) -> str:
        return self.name or self.path

    def to_data(self) -> dict[str, object]:
        return {
            "identity": self.identity,
            "name": self.name,
            "path": self.path,
            "status": self.status,
            "conformant": self.conformant,
            "diagnostics": [item.to_data() for item in self.diagnostics],
            "conformance_diagnostics": [item.to_data() for item in self.conformance_diagnostics],
            "advisory_findings": [dict(item) for item in self.advisory_findings],
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
    sha256: str | None = None
    size_bytes: int | None = None
    identity_skipped_reason: str | None = None

    def to_data(self) -> dict[str, object]:
        return {
            "component": self.component,
            "path": self.path,
            "status": self.status,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "identity_skipped_reason": self.identity_skipped_reason,
        }


@dataclass(frozen=True)
class AgentPluginPackageSurface:
    path: str
    kind: str
    status: str

    def to_data(self) -> dict[str, str]:
        return {"path": self.path, "kind": self.kind, "status": self.status}


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
    package_surfaces: tuple[AgentPluginPackageSurface, ...]
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
            "package_surfaces": [item.to_data() for item in self.package_surfaces],
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


def _bounded_entries(path: Path, limit: int) -> tuple[list[Path], bool]:
    """List at most ``limit`` entries, reporting overflow without sampling."""
    entries: list[Path] = []
    with os.scandir(path) as iterator:
        for entry in iterator:
            if len(entries) >= max(limit, 0):
                return [], True
            entries.append(Path(entry.path))
    return sorted(entries, key=lambda item: item.name), False


def _read_json(
    path: Path,
    label: str,
    *,
    max_bytes: int,
) -> tuple[object | None, AgentPluginDiagnostic | None]:
    limit = max(max_bytes, 0)
    try:
        with path.open("rb", buffering=0) as stream:
            raw = stream.read(limit + 1)
    except OSError:
        return None, _diagnostic("json_unreadable", f"{label} could not be read safely", label)
    if len(raw) > limit:
        return None, _diagnostic(
            "json_too_large",
            f"{label} exceeds the bounded JSON read limit",
            label,
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, _diagnostic("json_invalid_utf8", f"{label} is not valid UTF-8", label)
    try:
        return json.loads(text), None
    except json.JSONDecodeError:
        return None, _diagnostic("json_invalid", f"{label} is not valid JSON", label)


def _file_identity(
    root: Path,
    relative_path: str,
    *,
    max_bytes: int,
) -> _FileIdentity:
    """Hash only a regular file that resolves safely within the plugin root."""
    candidate = _resolve_inside(root, root / relative_path)
    if candidate is None:
        return _FileIdentity(identity_skipped_reason="path_unavailable")
    try:
        if not candidate.is_file():
            return _FileIdentity(identity_skipped_reason="not_regular_file")
        limit = max(max_bytes, 0)
        digest = hashlib.sha256()
        total = 0
        with candidate.open("rb", buffering=0) as stream:
            while True:
                chunk = stream.read(min(65_536, limit - total + 1))
                if not chunk:
                    return _FileIdentity(digest.hexdigest(), total)
                total += len(chunk)
                if total > limit:
                    return _FileIdentity(identity_skipped_reason="file_too_large")
                digest.update(chunk)
    except OSError:
        return _FileIdentity(identity_skipped_reason="read_error")


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
    if "keywords" in data and (
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
    if "extensions" in data and not isinstance(extensions, dict):
        diagnostics.append(
            _diagnostic(
                "manifest_extensions_ignored",
                "non-object plugin.json.extensions is ignored by the Agent Plugins contract",
                "plugin.json.extensions",
            )
        )
    # SkillGate implements no client extension namespaces. Preserve the keys
    # for inventory, but leave every unknown namespace value opaque.

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
    sorted_diagnostics = _sorted_diagnostics(diagnostics)
    return AgentPluginSkill(
        name=None,
        path=path,
        status="skipped"
        if any(item.code == "skill_path_outside_plugin_root" for item in diagnostics)
        else "invalid",
        diagnostics=sorted_diagnostics,
        conformant=False,
        conformance_diagnostics=sorted_diagnostics,
    )


def _skill_result_diagnostics(
    skill_path: str,
    result: SkillValidationResult,
) -> tuple[AgentPluginDiagnostic, ...]:
    diagnostics = []
    for item in result.conformance_diagnostics:
        line = item.get("line_number")
        path = f"{skill_path}:{line}" if isinstance(line, int) else skill_path
        diagnostics.append(
            _diagnostic(
                str(item.get("code", "skill_conformance")),
                str(item.get("message", "Agent Skill conformance error")),
                path,
            )
        )
    return _sorted_diagnostics(diagnostics)


def _load_skills(
    root: Path,
    limits: AgentPluginLimits,
) -> tuple[list[AgentPluginSkill], str, list[AgentPluginDiagnostic]]:
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
        children, discovery_limited = _bounded_entries(
            resolved_location,
            limits.max_skill_components,
        )
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

    if discovery_limited:
        diagnostics.append(
            _diagnostic(
                "skill_discovery_limit",
                "skills/ contains more immediate child entries than the bounded discovery limit",
                relative_location,
            )
        )

    for child in children[: limits.max_skill_components]:
        # Keep the fixed-location identity stable even when skills/ is a
        # symlink to another directory inside the plugin root.
        skill_candidate = location / child.name / SKILL_FILE
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
            if resolved_skill.stat().st_size > limits.max_skill_bytes:
                skill_diagnostics = [
                    _diagnostic(
                        "skill_too_large",
                        "discovered SKILL.md exceeds the bounded skill read limit",
                        skill_path,
                    )
                ]
                skill = _invalid_skill(skill_path, skill_diagnostics)
                skills.append(skill)
                diagnostics.extend(skill_diagnostics)
                continue
            result = validate_skill_file_result(
                resolved_skill,
                root,
                directory_name=Path(skill_path).parent.name,
                max_bytes=limits.max_skill_bytes,
                scan_advisories=False,
            )
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

        skill_diagnostics = list(_skill_result_diagnostics(skill_path, result))
        status = "valid" if result.conformant else "invalid"
        skill = AgentPluginSkill(
            name=result.skill.get("name") if isinstance(result.skill.get("name"), str) else None,
            path=skill_path,
            status=status,
            diagnostics=_sorted_diagnostics(skill_diagnostics),
            conformant=result.conformant,
            conformance_diagnostics=_sorted_diagnostics(skill_diagnostics),
            advisory_findings=tuple(dict(item) for item in result.advisory_findings),
        )
        skills.append(skill)
        diagnostics.extend(skill_diagnostics)

    skills.sort(key=lambda item: item.path)
    status = (
        "partial"
        if discovery_limited or any(item.status in {"invalid", "skipped"} for item in skills)
        else "valid"
    )
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
    if not isinstance(value, str) or not value:
        return [
            _diagnostic("mcp_invalid_command", "stdio command must be one executable token", path)
        ]
    if value.startswith("./"):
        # The schema constrains command to a non-empty string. Keep the JSON
        # value as one token; do not shell-parse or infer runtime intent.
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


def _load_mcp(
    root: Path,
    plugin_schema: str,
    limits: AgentPluginLimits,
) -> AgentPluginMcp:
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

    data, read_diagnostic = _read_json(
        resolved,
        "mcp.json",
        max_bytes=limits.max_mcp_bytes,
    )
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
) -> tuple[
    list[AgentPluginExtension],
    list[str],
    list[AgentPluginDiagnostic],
    list[AgentPluginPackageSurface],
]:
    return _load_extensions_with_limits(root, manifest_data, DEFAULT_AGENT_PLUGIN_LIMITS)


def _load_extensions_with_limits(
    root: Path,
    manifest_data: dict[str, object],
    limits: AgentPluginLimits,
) -> tuple[
    list[AgentPluginExtension],
    list[str],
    list[AgentPluginDiagnostic],
    list[AgentPluginPackageSurface],
]:
    declared = manifest_data.get("extensions")
    declared_names = sorted(declared) if isinstance(declared, dict) else []
    extensions: dict[str, AgentPluginExtension] = {
        namespace: AgentPluginExtension(namespace, True, False) for namespace in declared_names
    }
    unknown_surfaces: set[str] = set(declared_names)
    diagnostics: list[AgentPluginDiagnostic] = []
    package_surfaces: list[AgentPluginPackageSurface] = []

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
        top_level, discovery_limited = _bounded_entries(root, limits.max_top_level_entries)
    except OSError:
        return (
            sorted(extensions.values(), key=lambda item: item.namespace),
            sorted(unknown_surfaces),
            [_diagnostic("package_listing_failed", "plugin root could not be listed safely", ".")],
            package_surfaces,
        )

    if discovery_limited:
        overflow_path = "<top-level-entry-limit-exceeded>"
        unknown_surfaces.add(overflow_path)
        package_surfaces.append(
            AgentPluginPackageSurface(overflow_path, "discovery_limit", "unknown")
        )
        diagnostics.append(
            _diagnostic(
                "package_listing_limit",
                "plugin root contains more top-level entries than the bounded discovery limit",
                ".",
            )
        )

    for child in top_level:
        relative = _relative(root, child)
        if child.name in {"plugin.json", "mcp.json", "skills"}:
            resolved = _resolve_inside(root, child)
            expected_directory = child.name == "skills"
            is_expected_kind = (
                resolved is not None
                and resolved.is_dir() == expected_directory
                and resolved.is_file() == (not expected_directory)
            )
            package_surfaces.append(
                AgentPluginPackageSurface(
                    relative,
                    "portable_component",
                    "present" if is_expected_kind else "invalid",
                )
            )
            continue
        if child.name in _KNOWN_PACKAGE_METADATA_FILES and not child.is_dir():
            resolved = _resolve_inside(root, child)
            status = "known" if resolved is not None and resolved.is_file() else "invalid"
            package_surfaces.append(AgentPluginPackageSurface(relative, "package_metadata", status))
            if status == "invalid":
                unknown_surfaces.add(relative)
                diagnostics.append(
                    _diagnostic(
                        "package_metadata_invalid",
                        "known package metadata file could not be safely inspected",
                        relative,
                    )
                )
            continue
        if child.name in extensions:
            resolved = _resolve_inside(root, child)
            status = "unknown"
            if resolved is None:
                status = "invalid"
                diagnostics.append(
                    _diagnostic(
                        "extension_path_outside_plugin_root",
                        "extension directory resolves outside the plugin root",
                        relative,
                    )
                )
            elif not resolved.is_dir():
                status = "invalid"
            package_surfaces.append(AgentPluginPackageSurface(relative, "client_extension", status))
            continue
        if _extension_is_namespace(child.name) and (child.is_dir() or child.is_symlink()):
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
                package_surfaces.append(
                    AgentPluginPackageSurface(relative, "client_extension", "invalid")
                )
                unknown_surfaces.add(relative)
                continue
            extensions[child.name] = AgentPluginExtension(child.name, False, True)
            unknown_surfaces.add(child.name)
            package_surfaces.append(
                AgentPluginPackageSurface(relative, "client_extension", "unknown")
            )
        else:
            kind = "unknown_package_directory" if child.is_dir() else "unknown_package_file"
            package_surfaces.append(AgentPluginPackageSurface(relative, kind, "unknown"))
            unknown_surfaces.add(relative)
            diagnostics.append(
                _diagnostic(
                    "unknown_package_surface",
                    "top-level package entry is not a portable component or known metadata file",
                    relative,
                )
            )

    return (
        sorted(extensions.values(), key=lambda item: item.namespace),
        sorted(unknown_surfaces),
        diagnostics,
        sorted(package_surfaces, key=lambda item: (item.path, item.kind)),
    )


def _counts_for_portable_core(
    manifest: AgentPluginManifest,
    skills_status: str,
    skills: list[AgentPluginSkill],
    mcp: AgentPluginMcp,
) -> AgentPluginCoverageCounts:
    discovered = reviewed = invalid = skipped = unknown = 0
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
        elif skills_status == "partial":
            unknown = 1
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
    return AgentPluginCoverageCounts(discovered, reviewed, invalid, skipped, unknown)


def _counts_for_overall_artifact(
    portable_counts: AgentPluginCoverageCounts,
    package_surfaces: list[AgentPluginPackageSurface],
    unknown_surfaces: list[str],
) -> AgentPluginCoverageCounts:
    """Add every non-core package surface without double-counting fixed locations."""
    extras = [item for item in package_surfaces if item.kind != "portable_component"]
    represented_paths = {item.path for item in extras}
    unrepresented_unknown = [item for item in unknown_surfaces if item not in represented_paths]
    reviewed = sum(item.status == "known" for item in extras)
    invalid = sum(item.status == "invalid" for item in extras)
    unknown = sum(item.status == "unknown" for item in extras) + len(unrepresented_unknown)
    return AgentPluginCoverageCounts(
        discovered=portable_counts.discovered + len(extras) + len(unrepresented_unknown),
        reviewed=portable_counts.reviewed + reviewed,
        invalid=portable_counts.invalid + invalid,
        skipped=portable_counts.skipped,
        unknown=portable_counts.unknown + unknown,
    )


def _provenance_file_entry(
    root: Path,
    component: str,
    path: str,
    status: str,
    *,
    max_bytes: int,
) -> AgentPluginProvenanceEntry:
    identity = _file_identity(root, path, max_bytes=max_bytes)
    return AgentPluginProvenanceEntry(
        component,
        path,
        status,
        identity.sha256,
        identity.size_bytes,
        identity.identity_skipped_reason,
    )


def _provenance(
    root: Path,
    manifest: AgentPluginManifest,
    skills_status: str,
    skills: list[AgentPluginSkill],
    mcp: AgentPluginMcp,
    extensions: list[AgentPluginExtension],
    package_surfaces: list[AgentPluginPackageSurface],
    unknown_surfaces: list[str],
    limits: AgentPluginLimits,
) -> AgentPluginProvenance:
    entries = [
        _provenance_file_entry(
            root,
            "manifest",
            "plugin.json",
            manifest.status,
            max_bytes=limits.max_manifest_bytes,
        )
    ]
    if skills_status != "absent":
        entries.append(AgentPluginProvenanceEntry("skills", "skills", skills_status))
    entries.extend(
        _provenance_file_entry(
            root,
            "skill",
            item.path,
            item.status,
            max_bytes=limits.max_skill_bytes,
        )
        for item in skills
    )
    if mcp.status != "absent":
        entries.append(
            _provenance_file_entry(
                root,
                "mcp",
                mcp.path,
                mcp.status,
                max_bytes=limits.max_mcp_bytes,
            )
        )
    entries.extend(
        AgentPluginProvenanceEntry("mcp_server", item.path, item.status) for item in mcp.servers
    )
    entries.extend(
        AgentPluginProvenanceEntry("extension", item.namespace, item.status) for item in extensions
    )
    package_paths = {item.path for item in package_surfaces}
    entries.extend(
        _provenance_file_entry(
            root,
            "package_surface",
            item.path,
            item.status,
            max_bytes=limits.max_package_file_bytes,
        )
        for item in package_surfaces
    )
    entries.extend(
        AgentPluginProvenanceEntry("unknown", item, "unknown")
        for item in unknown_surfaces
        if item not in package_paths and item not in {entry.path for entry in entries}
    )
    return AgentPluginProvenance(
        ".", tuple(sorted(entries, key=lambda item: (item.path, item.component)))
    )


def _rejected_inventory(
    root: Path,
    diagnostics: list[AgentPluginDiagnostic],
    manifest: AgentPluginManifest | None = None,
    limits: AgentPluginLimits = DEFAULT_AGENT_PLUGIN_LIMITS,
) -> AgentPluginInventory:
    manifest = manifest or AgentPluginManifest(
        "invalid", None, None, None, "plugin.json", _sorted_diagnostics(diagnostics)
    )
    empty_counts = AgentPluginCoverageCounts(discovered=1, invalid=1)
    coverage = AgentPluginCoverage("REJECTED", "REJECTED", empty_counts, empty_counts)
    provenance = AgentPluginProvenance(
        ".",
        (
            _provenance_file_entry(
                root,
                "manifest",
                "plugin.json",
                "invalid",
                max_bytes=limits.max_manifest_bytes,
            ),
        ),
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
        (),
        coverage,
        (),
        _sorted_diagnostics(diagnostics),
        provenance,
    )


def load_agent_plugin(
    path: Path | str,
    *,
    limits: AgentPluginLimits = DEFAULT_AGENT_PLUGIN_LIMITS,
) -> AgentPluginInventory:
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
            limits=limits,
        )
    if not root.is_dir():
        return _rejected_inventory(
            root,
            [
                _diagnostic(
                    "plugin_root_invalid", "Agent Plugin input must be a local directory", "."
                )
            ],
            limits=limits,
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
            limits=limits,
        )
    if not resolved_manifest.exists():
        return _rejected_inventory(
            root,
            [_diagnostic("manifest_missing", "plugin.json is required", "plugin.json")],
            limits=limits,
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
            limits=limits,
        )

    data, read_diagnostic = _read_json(
        resolved_manifest,
        "plugin.json",
        max_bytes=limits.max_manifest_bytes,
    )
    if read_diagnostic is not None:
        return _rejected_inventory(root, [read_diagnostic], limits=limits)
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
            limits=limits,
        )

    manifest, manifest_diagnostics = _validate_manifest(data)
    if manifest.status != "valid":
        return _rejected_inventory(root, manifest_diagnostics, manifest, limits)

    skills, skills_status, skill_diagnostics = _load_skills(root, limits)
    mcp = _load_mcp(root, manifest.schema or PLUGIN_SCHEMA, limits)
    extensions, unknown_surfaces, extension_diagnostics, package_surfaces = (
        _load_extensions_with_limits(root, data, limits)
    )
    diagnostics = (
        manifest_diagnostics + skill_diagnostics + list(mcp.diagnostics) + extension_diagnostics
    )

    portable_counts = _counts_for_portable_core(manifest, skills_status, skills, mcp)
    portable_incomplete = bool(
        portable_counts.invalid or portable_counts.skipped or portable_counts.unknown
    )
    portable_status = "INCOMPLETE" if portable_incomplete else "COMPLETE"
    overall_counts = _counts_for_overall_artifact(
        portable_counts,
        package_surfaces,
        unknown_surfaces,
    )
    overall_status = "INCOMPLETE" if portable_incomplete or unknown_surfaces else "COMPLETE"
    coverage = AgentPluginCoverage(portable_status, overall_status, portable_counts, overall_counts)
    provenance = _provenance(
        root,
        manifest,
        skills_status,
        skills,
        mcp,
        extensions,
        package_surfaces,
        unknown_surfaces,
        limits,
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
        tuple(package_surfaces),
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
