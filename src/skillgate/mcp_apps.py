"""Static MCP Apps declaration inventory.

This module intentionally has no filesystem, network, subprocess, browser, or
reporting dependencies. Callers provide already-materialized objects or bytes;
the parser returns normalized review records.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from skillgate.models import Capability, Finding

INLINE_RESOURCE_MAX_BYTES = 1_048_576
INLINE_RESOURCE_TOTAL_MAX_BYTES = 5_242_880
MCP_APP_CAPABILITY_TYPES = (
    "mcp_app_resource",
    "mcp_app_asset",
    "mcp_app_origin",
    "mcp_app_permission",
    "mcp_app_tool_surface",
    "mcp_app_host_bridge",
    "mcp_app_unknown_declaration",
)
MCP_APP_PERMISSION_NAMES = frozenset(
    {"camera", "mic", "microphone", "geolocation", "clipboardWrite"}
)
MCP_APP_UI_MIME_PREFIX = "text/html;profile=mcp-app"
MCP_APP_UI_MIME_VALUES = frozenset({MCP_APP_UI_MIME_PREFIX, "text/html+skybridge"})
SECRET_VALUE_RE = re.compile(
    r"(?i)(token|secret|password|credential|api[_-]?key|access[_-]?key|private[_-]?key)"
)
BRIDGE_MARKERS = (
    "registerAppTool",
    "registerAppResource",
    "callServerTool",
    "tools/call",
    "resources/read",
    "ui/initialize",
)


@dataclass(frozen=True)
class McpAppOriginDeclaration:
    origin: str
    kind: str
    declaration_path: str
    scope: str


@dataclass(frozen=True)
class McpAppPermissionDeclaration:
    name: str
    declaration_path: str
    scope: str


@dataclass(frozen=True)
class McpAppToolSurface:
    name: str
    surface: str
    declaration_path: str
    scope: str
    privileged: bool


@dataclass(frozen=True)
class McpAppResourceDeclaration:
    resource_uri: str
    mime_type: str | None
    declaration_path: str
    scope: str
    declared_visibility: tuple[str, ...] | None
    effective_visibility: tuple[str, ...]
    visibility_source: str
    origins: tuple[McpAppOriginDeclaration, ...]
    permissions: tuple[McpAppPermissionDeclaration, ...]
    app_capabilities: tuple[str, ...]
    tool_surfaces: tuple[McpAppToolSurface, ...]


@dataclass(frozen=True)
class McpAppInlineResource:
    resource_uri: str
    declaration_path: str
    scope: str
    kind: str
    text: str | None
    sha256: str | None
    size_bytes: int
    skipped_reason: str | None = None


@dataclass(frozen=True)
class McpAppUnknownDeclaration:
    declaration_path: str
    reason: str
    scope: str


@dataclass(frozen=True)
class McpAppInventory:
    resources: tuple[McpAppResourceDeclaration, ...]
    inline_resources: tuple[McpAppInlineResource, ...]
    unknown_declarations: tuple[McpAppUnknownDeclaration, ...]

    @property
    def is_empty(self) -> bool:
        return not (self.resources or self.inline_resources or self.unknown_declarations)


def _path(parent: str, child: str) -> str:
    return f"{parent}.{child}" if parent else child


def _redact_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
        username = parsed.username
        password = parsed.password
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not username and not password:
        return value
    host = host or ""
    if port:
        host = f"{host}:{port}"
    return urlunsplit(
        (parsed.scheme, "[REDACTED]@" + host, parsed.path, parsed.query, parsed.fragment)
    )


def _safe_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if SECRET_VALUE_RE.search(stripped):
        return None
    return _redact_url(stripped)


def _mime_is_mcp_app(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower()
    return normalized in MCP_APP_UI_MIME_VALUES or normalized.startswith(MCP_APP_UI_MIME_PREFIX)


def _resource_uri(value: object) -> str | None:
    uri = _safe_string(value)
    if uri is None:
        return None
    if uri.startswith("ui://") or uri.startswith("file://") or uri.startswith("./"):
        return uri
    if "/" in uri and "://" not in uri:
        return uri
    return None


def _unknown(declaration_path: str, reason: str, scope: str) -> McpAppUnknownDeclaration:
    return McpAppUnknownDeclaration(
        declaration_path=declaration_path,
        reason=reason,
        scope=scope,
    )


def _visibility(
    value: object, *, modern: bool, present: bool
) -> tuple[tuple[str, ...] | None, tuple[str, ...], str, bool]:
    if not present:
        if modern:
            return None, ("app", "model"), "spec_default", True
        return None, (), "unknown", True
    if isinstance(value, list) and all(isinstance(item, str) and item for item in value):
        declared = tuple(sorted(set(value)))
        return declared, declared, "declared", True
    if isinstance(value, str) and value:
        declared = (value,)
        return declared, declared, "declared", True
    return None, (), "unknown", False


def _origin_values(
    value: object, kind: str, declaration_path: str, scope: str
) -> tuple[list[McpAppOriginDeclaration], list[McpAppUnknownDeclaration]]:
    if isinstance(value, str):
        values = [(value, declaration_path)]
    elif isinstance(value, list):
        values = [(item, _path(declaration_path, str(index))) for index, item in enumerate(value)]
    else:
        return [], [_unknown(declaration_path, "invalid_csp_origin", scope)]
    origins: list[McpAppOriginDeclaration] = []
    unknown: list[McpAppUnknownDeclaration] = []
    for item, item_path in values:
        safe = _safe_string(item)
        if safe is not None:
            origins.append(
                McpAppOriginDeclaration(
                    origin=safe,
                    kind=kind,
                    declaration_path=item_path,
                    scope=scope,
                )
            )
        else:
            unknown.append(_unknown(item_path, "invalid_or_redacted_csp_origin", scope))
    return origins, unknown


def _csp_origins(
    value: object, declaration_path: str, scope: str
) -> tuple[list[McpAppOriginDeclaration], list[McpAppUnknownDeclaration]]:
    origins: list[McpAppOriginDeclaration] = []
    unknown: list[McpAppUnknownDeclaration] = []
    if not isinstance(value, dict):
        return origins, [_unknown(declaration_path, "invalid_csp", scope)]
    key_kinds = {
        "connect": "connect",
        "connect_domains": "connect",
        "connect-src": "connect",
        "resource": "resource",
        "resource_domains": "resource",
        "img-src": "resource",
        "media-src": "resource",
        "script-src": "resource",
        "style-src": "resource",
        "frame": "frame",
        "frame_domains": "frame",
        "frame-src": "frame",
        "base_uri": "base_uri",
        "base-uri": "base_uri",
    }
    for key, kind in sorted(key_kinds.items()):
        if key in value:
            field_origins, field_unknown = _origin_values(
                value[key], kind, _path(declaration_path, key), scope
            )
            origins.extend(field_origins)
            unknown.extend(field_unknown)
    return origins, unknown


def _permission_values(
    value: object, declaration_path: str, scope: str
) -> tuple[list[McpAppPermissionDeclaration], list[McpAppUnknownDeclaration]]:
    raw = value if isinstance(value, list) else [value]
    permissions: list[McpAppPermissionDeclaration] = []
    unknown: list[McpAppUnknownDeclaration] = []
    for index, item in enumerate(raw):
        item_path = (
            _path(declaration_path, str(index)) if isinstance(value, list) else declaration_path
        )
        name = item.get("name") if isinstance(item, dict) else item
        safe = _safe_string(name)
        if safe is not None:
            permissions.append(
                McpAppPermissionDeclaration(
                    name=safe,
                    declaration_path=item_path,
                    scope=scope,
                )
            )
        else:
            unknown.append(_unknown(item_path, "invalid_or_redacted_permission", scope))
    return permissions, unknown


def _string_list(
    value: object, declaration_path: str, scope: str
) -> tuple[tuple[str, ...], list[McpAppUnknownDeclaration]]:
    if isinstance(value, str):
        safe = _safe_string(value)
        if safe is not None:
            return (safe,), []
        return (), [_unknown(declaration_path, "invalid_or_redacted_app_capability", scope)]
    if isinstance(value, list):
        values = []
        unknown = []
        for index, item in enumerate(value):
            safe = _safe_string(item)
            if safe is not None:
                values.append(safe)
            else:
                unknown.append(
                    _unknown(
                        _path(declaration_path, str(index)),
                        "invalid_or_redacted_app_capability",
                        scope,
                    )
                )
        return tuple(sorted(set(values))), unknown
    return (), [_unknown(declaration_path, "invalid_app_capabilities", scope)]


def _tool_surfaces(
    value: object, declaration_path: str, scope: str
) -> tuple[list[McpAppToolSurface], list[McpAppUnknownDeclaration]]:
    surfaces: list[McpAppToolSurface] = []
    unknown: list[McpAppUnknownDeclaration] = []
    if isinstance(value, str):
        safe = _safe_string(value)
        if safe is not None:
            surfaces.append(
                McpAppToolSurface(
                    name=safe,
                    surface="app_callable_tool",
                    declaration_path=declaration_path,
                    scope=scope,
                    privileged=True,
                )
            )
        else:
            unknown.append(_unknown(declaration_path, "invalid_or_redacted_tool_surface", scope))
        return surfaces, unknown
    if not isinstance(value, list):
        return surfaces, [_unknown(declaration_path, "invalid_tool_surfaces", scope)]
    for index, item in enumerate(value):
        item_path = _path(declaration_path, str(index))
        if isinstance(item, str):
            safe = _safe_string(item)
            if safe is not None:
                surfaces.append(
                    McpAppToolSurface(
                        name=safe,
                        surface="app_callable_tool",
                        declaration_path=item_path,
                        scope=scope,
                        privileged=True,
                    )
                )
            else:
                unknown.append(_unknown(item_path, "invalid_or_redacted_tool_surface", scope))
            continue
        if not isinstance(item, dict):
            unknown.append(_unknown(item_path, "invalid_tool_surface", scope))
            continue
        name = _safe_string(item.get("name") or item.get("id") or item.get("tool"))
        if name is None:
            unknown.append(_unknown(item_path, "invalid_or_redacted_tool_surface", scope))
            continue
        if any(
            key in item and not isinstance(item[key], bool)
            for key in ("appCallable", "app_callable", "dynamic", "registersTools")
        ):
            unknown.append(_unknown(item_path, "invalid_tool_surface_flags", scope))
            continue
        app_callable = item.get("appCallable") is True or item.get("app_callable") is True
        dynamic = item.get("dynamic") is True or item.get("registersTools") is True
        surface = "dynamic_tool_surface" if dynamic else "app_callable_tool"
        surfaces.append(
            McpAppToolSurface(
                name=name,
                surface=surface,
                declaration_path=item_path,
                scope=scope,
                privileged=app_callable or dynamic,
            )
        )
    return surfaces, unknown


def _decode_inline(
    value: object,
    *,
    kind: str,
    resource_uri: str,
    declaration_path: str,
    scope: str,
    remaining_bytes: int,
) -> tuple[McpAppInlineResource | None, int, McpAppUnknownDeclaration | None]:
    if not isinstance(value, str):
        return None, 0, None
    if kind == "blob":
        try:
            data = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return (
                None,
                0,
                McpAppUnknownDeclaration(
                    declaration_path=declaration_path,
                    reason="invalid_inline_base64",
                    scope=scope,
                ),
            )
    else:
        data = value.encode("utf-8", errors="replace")
    size = len(data)
    if size > INLINE_RESOURCE_MAX_BYTES:
        return (
            McpAppInlineResource(
                resource_uri=resource_uri,
                declaration_path=declaration_path,
                scope=scope,
                kind=kind,
                text=None,
                sha256=hashlib.sha256(data).hexdigest(),
                size_bytes=size,
                skipped_reason="inline_resource_too_large",
            ),
            0,
            None,
        )
    if size > remaining_bytes:
        return (
            McpAppInlineResource(
                resource_uri=resource_uri,
                declaration_path=declaration_path,
                scope=scope,
                kind=kind,
                text=None,
                sha256=hashlib.sha256(data).hexdigest(),
                size_bytes=size,
                skipped_reason="inline_resource_total_limit_exceeded",
            ),
            0,
            None,
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
        skipped = "inline_resource_not_utf8"
    else:
        skipped = None
    return (
        McpAppInlineResource(
            resource_uri=resource_uri,
            declaration_path=declaration_path,
            scope=scope,
            kind=kind,
            text=text,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=size,
            skipped_reason=skipped,
        ),
        size,
        None,
    )


def _metadata_candidates(
    data: object, *, excluded_declaration_paths: tuple[str, ...] = ()
) -> list[tuple[dict[str, Any], str, bool]]:
    candidates: list[tuple[dict[str, Any], str, bool]] = []
    excluded_paths = set(excluded_declaration_paths)

    def walk(value: object, path: str) -> None:
        if path in excluded_paths:
            return
        if isinstance(value, dict):
            metadata = value.get("_meta")
            if isinstance(metadata, dict):
                ui = metadata.get("ui")
                if isinstance(ui, dict):
                    candidates.append((ui, _path(path, "_meta.ui"), True))
                legacy = metadata.get("ui/resourceUri")
                if legacy is not None:
                    legacy_candidate: dict[str, Any] = {"resourceUri": legacy}
                    if "mimeType" in value:
                        legacy_candidate["mimeType"] = value["mimeType"]
                    elif "mimeType" in metadata:
                        legacy_candidate["mimeType"] = metadata["mimeType"]
                    if "ui/visibility" in metadata:
                        legacy_candidate["visibility"] = metadata["ui/visibility"]
                    candidates.append(
                        (legacy_candidate, _path(path, "_meta.ui/resourceUri"), False)
                    )
            for key, child in value.items():
                walk(child, _path(path, str(key)))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, _path(path, str(index)))

    walk(data, "")
    return candidates


def inventory_mcp_apps(
    data: object,
    *,
    declaration_path: str = "",
    scope: str = "mcp",
    excluded_declaration_paths: tuple[str, ...] = (),
) -> McpAppInventory:
    """Return a stable MCP Apps inventory from explicit declarations."""
    resources: list[McpAppResourceDeclaration] = []
    inline_resources: list[McpAppInlineResource] = []
    unknown: list[McpAppUnknownDeclaration] = []
    remaining_inline_bytes = INLINE_RESOURCE_TOTAL_MAX_BYTES

    for candidate, candidate_path, modern in _metadata_candidates(
        data, excluded_declaration_paths=excluded_declaration_paths
    ):
        path = _path(declaration_path, candidate_path)
        uri_value = candidate.get("resourceUri") or candidate.get("resource_uri")
        mime_value = candidate.get("mimeType") or candidate.get("mime_type")
        mime_type = _safe_string(mime_value)
        if mime_value is not None and mime_type is None:
            unknown.append(
                _unknown(_path(path, "mimeType"), "invalid_or_redacted_mime_type", scope)
            )
        uri = _resource_uri(uri_value)
        if uri is None:
            if uri_value is not None or _mime_is_mcp_app(mime_type):
                unknown.append(
                    _unknown(_path(path, "resourceUri"), "invalid_or_redacted_resource_uri", scope)
                )
            continue
        if not (uri.startswith("ui://") or _mime_is_mcp_app(mime_type)):
            continue
        (
            declared_visibility,
            effective_visibility,
            visibility_source,
            visibility_valid,
        ) = _visibility(
            candidate.get("visibility"), modern=modern, present="visibility" in candidate
        )
        if not visibility_valid:
            unknown.append(_unknown(_path(path, "visibility"), "invalid_visibility", scope))
        origins: list[McpAppOriginDeclaration] = []
        permissions: list[McpAppPermissionDeclaration] = []
        app_capabilities: tuple[str, ...] = ()
        tool_surfaces: list[McpAppToolSurface] = []
        for key in ("csp", "CSP"):
            if key not in candidate:
                continue
            field_origins, field_unknown = _csp_origins(candidate[key], _path(path, key), scope)
            origins.extend(field_origins)
            unknown.extend(field_unknown)
        if "permissions" in candidate:
            permissions, field_unknown = _permission_values(
                candidate["permissions"], _path(path, "permissions"), scope
            )
            unknown.extend(field_unknown)
        if "capabilities" in candidate:
            app_capabilities, field_unknown = _string_list(
                candidate["capabilities"], _path(path, "capabilities"), scope
            )
            unknown.extend(field_unknown)
        for key in ("tools", "toolSurfaces", "appCallableTools"):
            if key not in candidate:
                continue
            field_surfaces, field_unknown = _tool_surfaces(candidate[key], _path(path, key), scope)
            tool_surfaces.extend(field_surfaces)
            unknown.extend(field_unknown)
        if candidate.get("resource_uri") and candidate.get("resourceUri"):
            unknown.append(
                McpAppUnknownDeclaration(
                    declaration_path=path,
                    reason="conflicting_resource_uri_keys",
                    scope=scope,
                )
            )
        resources.append(
            McpAppResourceDeclaration(
                resource_uri=uri,
                mime_type=mime_type,
                declaration_path=path,
                scope=scope,
                declared_visibility=declared_visibility,
                effective_visibility=effective_visibility,
                visibility_source=visibility_source,
                origins=tuple(
                    sorted(
                        set(origins),
                        key=lambda item: (item.kind, item.origin, item.declaration_path),
                    )
                ),
                permissions=tuple(
                    sorted(set(permissions), key=lambda item: (item.name, item.declaration_path))
                ),
                app_capabilities=app_capabilities,
                tool_surfaces=tuple(
                    sorted(
                        set(tool_surfaces),
                        key=lambda item: (item.name, item.surface, item.declaration_path),
                    )
                ),
            )
        )
        for key, kind in (("text", "text"), ("blob", "blob")):
            decoded, consumed, error = _decode_inline(
                candidate.get(key),
                kind=kind,
                resource_uri=uri,
                declaration_path=_path(path, key),
                scope=scope,
                remaining_bytes=remaining_inline_bytes,
            )
            if decoded is not None:
                inline_resources.append(decoded)
                remaining_inline_bytes -= consumed
            if error is not None:
                unknown.append(error)

    return McpAppInventory(
        resources=tuple(
            sorted(
                set(resources),
                key=lambda item: (item.resource_uri, item.declaration_path, item.scope),
            )
        ),
        inline_resources=tuple(
            sorted(
                set(inline_resources),
                key=lambda item: (item.resource_uri, item.declaration_path, item.kind),
            )
        ),
        unknown_declarations=tuple(
            sorted(
                set(unknown),
                key=lambda item: (item.declaration_path, item.reason, item.scope),
            )
        ),
    )


def detect_bridge_markers(text: str) -> tuple[str, ...]:
    markers = {marker for marker in BRIDGE_MARKERS if marker in text}
    if "postMessage" in text and any(marker in text for marker in ("mcp", "MCP", "ui://")):
        markers.add("postMessage")
    return tuple(sorted(markers))


def mcp_apps_details(inventory: McpAppInventory) -> dict[str, object]:
    return {
        "resources": [
            {
                "resource_uri": item.resource_uri,
                "mime_type": item.mime_type,
                "declared_visibility": list(item.declared_visibility)
                if item.declared_visibility is not None
                else None,
                "effective_visibility": list(item.effective_visibility),
                "visibility_source": item.visibility_source,
                "declaration_path": item.declaration_path,
                "scope": item.scope,
            }
            for item in inventory.resources
        ],
        "origins": [
            {
                "origin": origin.origin,
                "kind": origin.kind,
                "declaration_path": origin.declaration_path,
                "scope": origin.scope,
            }
            for resource in inventory.resources
            for origin in resource.origins
        ],
        "permissions": [
            {
                "name": permission.name,
                "declaration_path": permission.declaration_path,
                "scope": permission.scope,
            }
            for resource in inventory.resources
            for permission in resource.permissions
        ],
        "tools": [
            {
                "name": tool.name,
                "surface": tool.surface,
                "privileged": tool.privileged,
                "declaration_path": tool.declaration_path,
                "scope": tool.scope,
            }
            for resource in inventory.resources
            for tool in resource.tool_surfaces
        ],
        "inline_resources": [
            {
                "resource_uri": item.resource_uri,
                "kind": item.kind,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
                "skipped_reason": item.skipped_reason,
                "declaration_path": item.declaration_path,
                "scope": item.scope,
            }
            for item in inventory.inline_resources
        ],
        "unknown_declarations": [
            {
                "declaration_path": item.declaration_path,
                "reason": item.reason,
                "scope": item.scope,
            }
            for item in inventory.unknown_declarations
        ],
    }


def mcp_apps_summary(inventory: McpAppInventory) -> dict[str, object]:
    if inventory.is_empty:
        return {}
    return {"mcp_apps": mcp_apps_details(inventory)}


def mcp_apps_capabilities(
    inventory: McpAppInventory,
    *,
    source_file: str,
) -> list[Capability]:
    from skillgate.rules.base import make_capability

    capabilities: list[Capability] = []
    for resource in inventory.resources:
        resource_details = {
            "mime_type": resource.mime_type,
            "declared_visibility": list(resource.declared_visibility)
            if resource.declared_visibility is not None
            else None,
            "effective_visibility": list(resource.effective_visibility),
            "visibility_source": resource.visibility_source,
            "declaration_path": resource.declaration_path,
            "scope": resource.scope,
            "app_capabilities": list(resource.app_capabilities),
        }
        capabilities.append(
            make_capability(
                "mcp_app_resource",
                source_file,
                None,
                resource=resource.resource_uri,
                **resource_details,
            )
        )
        for origin in resource.origins:
            capabilities.append(
                make_capability(
                    "mcp_app_origin",
                    source_file,
                    None,
                    resource=origin.origin,
                    kind=origin.kind,
                    declaration_path=origin.declaration_path,
                    scope=origin.scope,
                    app_resource=resource.resource_uri,
                )
            )
        for permission in resource.permissions:
            capabilities.append(
                make_capability(
                    "mcp_app_permission",
                    source_file,
                    None,
                    resource=permission.name,
                    declaration_path=permission.declaration_path,
                    scope=permission.scope,
                    app_resource=resource.resource_uri,
                )
            )
        for tool in resource.tool_surfaces:
            capabilities.append(
                make_capability(
                    "mcp_app_tool_surface",
                    source_file,
                    None,
                    resource=tool.name,
                    surface=tool.surface,
                    privileged=tool.privileged,
                    declaration_path=tool.declaration_path,
                    scope=tool.scope,
                    app_resource=resource.resource_uri,
                )
            )
    for item in inventory.unknown_declarations:
        capabilities.append(
            make_capability(
                "mcp_app_unknown_declaration",
                source_file,
                None,
                resource=item.declaration_path or "<root>",
                declaration_path=item.declaration_path,
                reason=item.reason,
                scope=item.scope,
            )
        )
    return capabilities


def mcp_apps_findings(
    inventory: McpAppInventory,
    *,
    source_file: str,
) -> list[Finding]:
    from skillgate.rules.base import make_finding

    findings: list[Finding] = []
    for resource in inventory.resources:
        for tool in resource.tool_surfaces:
            if not tool.privileged:
                continue
            evidence = f"{resource.resource_uri}: {tool.surface} {tool.name}"
            findings.append(
                make_finding(
                    rule_id="SG011",
                    title="MCP app tool surface metadata detected",
                    description=(
                        "Declared MCP Apps metadata exposes UI-initiated or dynamic tool "
                        "surfaces that need review."
                    ),
                    severity="medium",
                    capability="mcp_app_tool_surface",
                    file_path=source_file,
                    line_number=None,
                    evidence=evidence,
                    remediation="Review app-callable tools before enabling the MCP app.",
                )
            )
        for permission in resource.permissions:
            if permission.name not in MCP_APP_PERMISSION_NAMES:
                continue
            findings.append(
                make_finding(
                    rule_id="SG011",
                    title="MCP app browser permission declared",
                    description=(
                        "Declared MCP Apps metadata requests browser-mediated permissions "
                        "that need review."
                    ),
                    severity="medium",
                    capability="mcp_app_permission",
                    file_path=source_file,
                    line_number=None,
                    evidence=f"{resource.resource_uri}: permission {permission.name}",
                    remediation="Confirm the browser permission is expected for the app UI.",
                )
            )
    return findings


def inventory_from_json_text(
    text: str,
    *,
    declaration_path: str = "",
    scope: str = "mcp",
) -> McpAppInventory:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return McpAppInventory((), (), ())
    return inventory_mcp_apps(data, declaration_path=declaration_path, scope=scope)


def mcp_apps_evidence(capabilities: list[dict[str, Any]]) -> dict[str, object] | None:
    evidence: dict[str, list[dict[str, object]]] = {
        "resources": [],
        "assets": [],
        "origins": [],
        "permissions": [],
        "tools": [],
        "bridges": [],
        "unknown_declarations": [],
    }
    for capability in capabilities:
        details = capability.get("details")
        if not isinstance(details, dict):
            continue
        capability_type = capability.get("type")
        source_file = capability.get("source_file")
        source_line = capability.get("source_line")
        resource = capability.get("resource")
        base = {
            "resource": resource,
            "source_file": source_file,
            "source_line": source_line,
            "declaration_path": details.get("declaration_path"),
            "scope": details.get("scope"),
        }
        if capability_type == "mcp_app_resource":
            evidence["resources"].append(
                {
                    **base,
                    "mime_type": details.get("mime_type"),
                    "declared_visibility": details.get("declared_visibility"),
                    "effective_visibility": details.get("effective_visibility"),
                    "visibility_source": details.get("visibility_source"),
                }
            )
        elif capability_type == "mcp_app_asset":
            evidence["assets"].append(
                {
                    **base,
                    "kind": details.get("kind"),
                    "association": details.get("association"),
                    "size_bytes": details.get("size_bytes"),
                    "sha256": details.get("sha256"),
                    "skipped_reason": details.get("skipped_reason"),
                }
            )
        elif capability_type == "mcp_app_origin":
            evidence["origins"].append(
                {
                    **base,
                    "kind": details.get("kind"),
                    "app_resource": details.get("app_resource"),
                }
            )
        elif capability_type == "mcp_app_permission":
            evidence["permissions"].append({**base, "app_resource": details.get("app_resource")})
        elif capability_type == "mcp_app_tool_surface":
            evidence["tools"].append(
                {
                    **base,
                    "surface": details.get("surface"),
                    "privileged": details.get("privileged"),
                    "app_resource": details.get("app_resource"),
                }
            )
        elif capability_type == "mcp_app_host_bridge":
            evidence["bridges"].append(
                {
                    **base,
                    "path": details.get("path"),
                    "marker": details.get("marker"),
                    "association": details.get("association"),
                }
            )
        elif capability_type == "mcp_app_unknown_declaration":
            evidence["unknown_declarations"].append({**base, "reason": details.get("reason")})
    for rows in evidence.values():
        rows.sort(key=lambda item: json.dumps(item, sort_keys=True))
    return evidence if any(evidence.values()) else None
