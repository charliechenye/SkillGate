"""Static MCP protocol and extension declaration inventory.

The helpers in this module only inspect explicitly declared compatibility
metadata. They never negotiate with, start, or otherwise contact an MCP
server, and they do not infer runtime behavior from extension settings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from skillgate.models import Capability

_PROTOCOL_FIELDS = ("protocolVersion", "protocolVersions", "supportedVersions")
_META_PROTOCOL_KEY = "io.modelcontextprotocol/protocolVersion"
_PROTOCOL_HEADER = "mcp-protocol-version"
_PROTOCOL_VERSION_RE = re.compile(r"^(?:\d{4}-\d{2}-\d{2}|DRAFT-[A-Za-z0-9._-]+)$")
_EXTENSION_ID_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+/[A-Za-z0-9][A-Za-z0-9._-]*$"
)
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
TASKS_EXTENSION_ID = "io.modelcontextprotocol/tasks"
TASK_METHODS = frozenset({"tasks/get", "tasks/update", "tasks/cancel"})
_TASK_METHOD_FIELDS = ("methods", "supportedMethods", "supported_methods", "operations")

# These are compatibility labels, not an allow-list. A declared date-form
# revision is still retained even when it is newer than this table. The two
# families deliberately coexist while the ecosystem migrates.
_LEGACY_PROTOCOL_REVISIONS = frozenset(
    {
        "2024-10-07",
        "2024-11-05",
        "2025-03-26",
        "2025-06-18",
        "2025-11-25",
    }
)
_MODERN_PROTOCOL_REVISIONS = frozenset({"2026-07-28"})


@dataclass(frozen=True)
class McpProtocolDeclaration:
    version: str
    era: str
    declaration_path: str
    scope: str


@dataclass(frozen=True)
class McpExtensionDeclaration:
    identifier: str
    version: str | None
    declaration_path: str
    scope: str


@dataclass(frozen=True)
class McpUnknownCompatibilityDeclaration:
    declaration_path: str
    reason: str
    scope: str


@dataclass(frozen=True)
class McpTaskMethodDeclaration:
    method: str
    declaration_path: str
    scope: str


@dataclass(frozen=True)
class McpCompatibilityInventory:
    protocol_versions: tuple[McpProtocolDeclaration, ...]
    extensions: tuple[McpExtensionDeclaration, ...]
    unknown_declarations: tuple[McpUnknownCompatibilityDeclaration, ...]
    task_methods: tuple[McpTaskMethodDeclaration, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (
            self.protocol_versions
            or self.extensions
            or self.unknown_declarations
            or self.task_methods
        )


def _path(parent: str, child: str) -> str:
    return f"{parent}.{child}" if parent else child


def _safe_protocol_versions(value: object) -> tuple[list[str], bool]:
    values = value if isinstance(value, list) else [value]
    valid_values = [
        item.strip()
        for item in values
        if isinstance(item, str) and _PROTOCOL_VERSION_RE.fullmatch(item.strip())
    ]
    return sorted(set(valid_values)), len(valid_values) != len(values)


def _protocol_era(version: str) -> str:
    """Classify known MCP wire-era revisions without rejecting other values."""
    if version in _LEGACY_PROTOCOL_REVISIONS:
        return "legacy"
    if version in _MODERN_PROTOCOL_REVISIONS:
        return "modern"
    if version.startswith("DRAFT-"):
        return "draft"
    return "unclassified"


def _extension_version(settings: dict[str, Any]) -> tuple[str | None, bool]:
    for key in ("version", "specVersion", "spec_version"):
        value = settings.get(key)
        if value is None:
            continue
        if isinstance(value, str) and _VERSION_RE.fullmatch(value.strip()):
            return value.strip(), True
        return None, False
    return None, True


def _extensions_from_value(
    value: object,
    *,
    declaration_path: str,
    scope: str,
) -> tuple[list[McpExtensionDeclaration], list[McpUnknownCompatibilityDeclaration]]:
    extensions: list[McpExtensionDeclaration] = []
    unknown: list[McpUnknownCompatibilityDeclaration] = []
    if not isinstance(value, dict):
        return [], [
            McpUnknownCompatibilityDeclaration(
                declaration_path=declaration_path,
                reason="extensions_not_object",
                scope=scope,
            )
        ]
    for identifier, settings in sorted(value.items(), key=lambda item: str(item[0])):
        entry_path = _path(declaration_path, str(identifier))
        if not isinstance(identifier, str) or not _EXTENSION_ID_RE.fullmatch(identifier):
            unknown.append(
                McpUnknownCompatibilityDeclaration(
                    declaration_path=entry_path,
                    reason="invalid_extension_id",
                    scope=scope,
                )
            )
            continue
        if not isinstance(settings, dict):
            unknown.append(
                McpUnknownCompatibilityDeclaration(
                    declaration_path=entry_path,
                    reason="extension_settings_not_object",
                    scope=scope,
                )
            )
            continue
        version, valid_version = _extension_version(settings)
        extensions.append(
            McpExtensionDeclaration(
                identifier=identifier,
                version=version,
                declaration_path=entry_path,
                scope=scope,
            )
        )
        if not valid_version:
            unknown.append(
                McpUnknownCompatibilityDeclaration(
                    declaration_path=entry_path,
                    reason="invalid_extension_version",
                    scope=scope,
                )
            )
    return extensions, unknown


def _task_method_declarations_from_mapping(
    value: object,
    *,
    declaration_path: str,
    scope: str,
) -> tuple[list[McpTaskMethodDeclaration], list[McpUnknownCompatibilityDeclaration]]:
    methods: list[McpTaskMethodDeclaration] = []
    unknown: list[McpUnknownCompatibilityDeclaration] = []
    if not isinstance(value, dict):
        return methods, unknown

    for field in _TASK_METHOD_FIELDS:
        if field not in value:
            continue
        field_path = _path(declaration_path, field)
        raw = value[field]
        if isinstance(raw, str):
            candidates = [(raw, field_path)]
        elif isinstance(raw, list):
            candidates = [(item, f"{field_path}[{index}]") for index, item in enumerate(raw)]
            if not all(isinstance(item, str) for item in raw):
                unknown.append(
                    McpUnknownCompatibilityDeclaration(
                        declaration_path=field_path,
                        reason="invalid_task_method_declaration",
                        scope=scope,
                    )
                )
        else:
            unknown.append(
                McpUnknownCompatibilityDeclaration(
                    declaration_path=field_path,
                    reason="invalid_task_method_declaration",
                    scope=scope,
                )
            )
            continue
        methods.extend(
            McpTaskMethodDeclaration(
                method=item,
                declaration_path=item_path,
                scope=scope,
            )
            for item, item_path in candidates
            if isinstance(item, str) and item in TASK_METHODS
        )
    return methods, unknown


def _task_method_declarations_from_tools(
    value: object,
    *,
    declaration_path: str,
    scope: str,
) -> list[McpTaskMethodDeclaration]:
    if not isinstance(value, dict) or "tools" not in value:
        return []
    tools = value["tools"]
    tools_path = _path(declaration_path, "tools")
    declarations: list[McpTaskMethodDeclaration] = []
    if isinstance(tools, list):
        entries = ((f"{tools_path}[{index}]", item) for index, item in enumerate(tools))
    elif isinstance(tools, dict):
        entries = ((_path(tools_path, str(name)), item) for name, item in sorted(tools.items()))
    else:
        return []

    for entry_path, entry in entries:
        if isinstance(entry, str):
            candidates = [(entry, entry_path)]
        elif isinstance(entry, dict):
            candidates = [
                (entry[key], _path(entry_path, key))
                for key in ("name", "method", "id")
                if isinstance(entry.get(key), str)
            ]
        else:
            candidates = []
        declarations.extend(
            McpTaskMethodDeclaration(
                method=item,
                declaration_path=item_path,
                scope=scope,
            )
            for item, item_path in candidates
            if item in TASK_METHODS
        )
    return declarations


def inventory_mcp_compatibility(
    data: object,
    *,
    declaration_path: str = "",
    scope: str = "mcp",
) -> McpCompatibilityInventory:
    """Return a stable inventory from one explicit MCP declaration object.

    Supported protocol locations are direct `protocolVersion`,
    `protocolVersions`, and `supportedVersions` fields, the 2026 per-request
    `_meta.io.modelcontextprotocol/protocolVersion` field, and an
    `MCP-Protocol-Version` header. Extension declarations are read only from
    `extensions`, `capabilities.extensions`, or the 2026 client-capabilities
    metadata object. Generic software `version` fields are deliberately ignored.
    """
    if not isinstance(data, dict):
        return McpCompatibilityInventory((), (), ())

    protocol_versions: list[McpProtocolDeclaration] = []
    extensions: list[McpExtensionDeclaration] = []
    unknown_declarations: list[McpUnknownCompatibilityDeclaration] = []
    task_methods: list[McpTaskMethodDeclaration] = []

    def add_protocols(value: object, path: str) -> None:
        versions, invalid = _safe_protocol_versions(value)
        protocol_versions.extend(
            McpProtocolDeclaration(
                version=version,
                era=_protocol_era(version),
                declaration_path=path,
                scope=scope,
            )
            for version in versions
        )
        if invalid:
            unknown_declarations.append(
                McpUnknownCompatibilityDeclaration(
                    declaration_path=path,
                    reason="invalid_protocol_version",
                    scope=scope,
                )
            )

    for key in _PROTOCOL_FIELDS:
        if key in data:
            add_protocols(data[key], _path(declaration_path, key))

    metadata = data.get("_meta")
    if isinstance(metadata, dict) and _META_PROTOCOL_KEY in metadata:
        add_protocols(
            metadata[_META_PROTOCOL_KEY], _path(declaration_path, f"_meta.{_META_PROTOCOL_KEY}")
        )
    headers = data.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if isinstance(key, str) and key.lower() == _PROTOCOL_HEADER:
                add_protocols(value, _path(declaration_path, f"headers.{key}"))

    extension_sources: list[tuple[object, str]] = []
    if "extensions" in data:
        extension_sources.append((data["extensions"], _path(declaration_path, "extensions")))
    capabilities = data.get("capabilities")
    if isinstance(capabilities, dict) and "extensions" in capabilities:
        extension_sources.append(
            (capabilities["extensions"], _path(declaration_path, "capabilities.extensions"))
        )
    if isinstance(metadata, dict):
        client_capabilities = metadata.get("io.modelcontextprotocol/clientCapabilities")
        if isinstance(client_capabilities, dict) and "extensions" in client_capabilities:
            extension_sources.append(
                (
                    client_capabilities["extensions"],
                    _path(
                        declaration_path,
                        "_meta.io.modelcontextprotocol/clientCapabilities.extensions",
                    ),
                )
            )

    for value, path in extension_sources:
        found_extensions, found_unknown = _extensions_from_value(
            value, declaration_path=path, scope=scope
        )
        extensions.extend(found_extensions)
        unknown_declarations.extend(found_unknown)

    task_sources: list[tuple[object, str]] = [(data, declaration_path)]
    if isinstance(capabilities, dict):
        task_sources.append((capabilities, _path(declaration_path, "capabilities")))
    if isinstance(metadata, dict):
        client_capabilities = metadata.get("io.modelcontextprotocol/clientCapabilities")
        if isinstance(client_capabilities, dict):
            task_sources.append(
                (
                    client_capabilities,
                    _path(
                        declaration_path,
                        "_meta.io.modelcontextprotocol/clientCapabilities",
                    ),
                )
            )
    for value, path in extension_sources:
        if not isinstance(value, dict):
            continue
        task_settings = value.get(TASKS_EXTENSION_ID)
        if isinstance(task_settings, dict):
            task_sources.append((task_settings, _path(path, TASKS_EXTENSION_ID)))
    for value, path in task_sources:
        found_methods, found_unknown = _task_method_declarations_from_mapping(
            value,
            declaration_path=path,
            scope=scope,
        )
        task_methods.extend(found_methods)
        unknown_declarations.extend(found_unknown)
        task_methods.extend(
            _task_method_declarations_from_tools(
                value,
                declaration_path=path,
                scope=scope,
            )
        )

    return McpCompatibilityInventory(
        protocol_versions=tuple(
            sorted(
                set(protocol_versions),
                key=lambda item: (item.version, item.era, item.declaration_path, item.scope),
            )
        ),
        extensions=tuple(
            sorted(
                set(extensions),
                key=lambda item: (
                    item.identifier,
                    item.version or "",
                    item.declaration_path,
                    item.scope,
                ),
            )
        ),
        unknown_declarations=tuple(
            sorted(
                set(unknown_declarations),
                key=lambda item: (item.declaration_path, item.reason, item.scope),
            )
        ),
        task_methods=tuple(
            sorted(
                set(task_methods),
                key=lambda item: (item.method, item.declaration_path, item.scope),
            )
        ),
    )


def compatibility_details(inventory: McpCompatibilityInventory) -> dict[str, object]:
    """Return redaction-safe, JSON-stable details for an MCP server capability."""
    details: dict[str, object] = {
        "protocol_versions": sorted({item.version for item in inventory.protocol_versions}),
        "protocol_version_eras": [
            {"version": version, "era": era}
            for version, era in sorted(
                {(item.version, item.era) for item in inventory.protocol_versions}
            )
        ],
        "extensions": [
            {"id": identifier, "version": version}
            for identifier, version in sorted(
                {(item.identifier, item.version) for item in inventory.extensions},
                key=lambda item: (item[0], item[1] or ""),
            )
        ],
        "unknown_declarations": [
            {"path": path, "reason": reason}
            for path, reason in sorted(
                {(item.declaration_path, item.reason) for item in inventory.unknown_declarations}
            )
        ],
    }
    if inventory.task_methods:
        details["task_methods"] = sorted({item.method for item in inventory.task_methods})
    return details


def compatibility_capabilities(
    inventory: McpCompatibilityInventory,
    *,
    source_file: str,
) -> list[Capability]:
    """Convert a normalized inventory into existing capability records."""
    from skillgate.rules.base import make_capability

    capabilities: list[Capability] = []
    for item in inventory.protocol_versions:
        capabilities.append(
            make_capability(
                "mcp_protocol_version",
                source_file,
                None,
                resource=item.version,
                declaration_path=item.declaration_path,
                scope=item.scope,
                era=item.era,
            )
        )
    for item in inventory.extensions:
        capabilities.append(
            make_capability(
                "mcp_extension",
                source_file,
                None,
                resource=item.identifier,
                declaration_path=item.declaration_path,
                scope=item.scope,
                version=item.version,
            )
        )
        if item.identifier == TASKS_EXTENSION_ID:
            capabilities.append(
                make_capability(
                    "mcp_task_capability",
                    source_file,
                    None,
                    resource=item.identifier,
                    declaration_path=item.declaration_path,
                    scope=item.scope,
                    task_surface="extension",
                    version=item.version,
                )
            )
    for item in inventory.task_methods:
        capabilities.append(
            make_capability(
                "mcp_task_capability",
                source_file,
                None,
                resource=item.method,
                declaration_path=item.declaration_path,
                scope=item.scope,
                task_surface="method",
            )
        )
    for item in inventory.unknown_declarations:
        capabilities.append(
            make_capability(
                "mcp_unknown_declaration",
                source_file,
                None,
                resource=item.declaration_path or "<root>",
                declaration_path=item.declaration_path,
                reason=item.reason,
                scope=item.scope,
            )
        )
    return capabilities


def compatibility_evidence(capabilities: list[dict[str, Any]]) -> dict[str, object] | None:
    """Build packet-safe evidence from serialized scan capabilities."""
    protocol_versions = []
    extensions = []
    unknown_declarations = []
    task_capabilities = []
    for capability in capabilities:
        details = capability.get("details")
        if not isinstance(details, dict):
            continue
        record = {
            "source_file": capability.get("source_file"),
            "declaration_path": details.get("declaration_path"),
            "scope": details.get("scope"),
        }
        if capability.get("type") == "mcp_protocol_version":
            protocol_versions.append(
                {
                    "version": capability.get("resource"),
                    "era": details.get("era"),
                    **record,
                }
            )
        elif capability.get("type") == "mcp_extension":
            extensions.append(
                {
                    "id": capability.get("resource"),
                    "version": details.get("version"),
                    **record,
                }
            )
        elif capability.get("type") == "mcp_unknown_declaration":
            unknown_declarations.append({"reason": details.get("reason"), **record})
        elif capability.get("type") == "mcp_task_capability":
            task_capabilities.append(
                {
                    "surface": details.get("task_surface"),
                    "resource": capability.get("resource"),
                    **record,
                }
            )
    if not (protocol_versions or extensions or unknown_declarations or task_capabilities):
        return None
    evidence: dict[str, object] = {
        "protocol_versions": sorted(protocol_versions, key=lambda item: str(item)),
        "extensions": sorted(extensions, key=lambda item: str(item)),
        "unknown_declarations": sorted(unknown_declarations, key=lambda item: str(item)),
    }
    if task_capabilities:
        evidence["task_capabilities"] = sorted(task_capabilities, key=lambda item: str(item))
    return evidence
