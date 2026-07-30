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


def _redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.username and not parsed.password:
        return value
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
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


def _visibility(
    value: object, *, modern: bool
) -> tuple[tuple[str, ...] | None, tuple[str, ...], str]:
    if isinstance(value, list) and all(isinstance(item, str) and item for item in value):
        declared = tuple(sorted(set(value)))
        return declared, declared, "declared"
    if isinstance(value, str) and value:
        declared = (value,)
        return declared, declared, "declared"
    if modern:
        return None, ("app", "model"), "spec_default"
    return None, (), "unknown"


def _origin_values(
    value: object, kind: str, declaration_path: str, scope: str
) -> list[McpAppOriginDeclaration]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = [item for item in value if isinstance(item, str)]
    else:
        values = []
    origins = []
    for item in values:
        safe = _safe_string(item)
        if safe is not None:
            origins.append(
                McpAppOriginDeclaration(
                    origin=safe,
                    kind=kind,
                    declaration_path=declaration_path,
                    scope=scope,
                )
            )
    return origins


def _csp_origins(value: object, declaration_path: str, scope: str) -> list[McpAppOriginDeclaration]:
    origins: list[McpAppOriginDeclaration] = []
    if not isinstance(value, dict):
        return origins
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
            origins.extend(_origin_values(value[key], kind, _path(declaration_path, key), scope))
    return origins


def _permission_values(
    value: object, declaration_path: str, scope: str
) -> list[McpAppPermissionDeclaration]:
    raw = value if isinstance(value, list) else [value]
    permissions = []
    for item in raw:
        name = item.get("name") if isinstance(item, dict) else item
        safe = _safe_string(name)
        if safe is not None:
            permissions.append(
                McpAppPermissionDeclaration(
                    name=safe,
                    declaration_path=declaration_path,
                    scope=scope,
                )
            )
    return permissions


def _string_list(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        safe = _safe_string(value)
        return (safe,) if safe is not None else ()
    if isinstance(value, list):
        return tuple(
            sorted(
                {
                    safe
                    for item in value
                    if (safe := _safe_string(item)) is not None
                }
            )
        )
    return ()


def _tool_surfaces(value: object, declaration_path: str, scope: str) -> list[McpAppToolSurface]:
    surfaces: list[McpAppToolSurface] = []
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
        return surfaces
    if not isinstance(value, list):
        return surfaces
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
            continue
        if not isinstance(item, dict):
            continue
        name = _safe_string(item.get("name") or item.get("id") or item.get("tool"))
        if name is None:
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
    return surfaces


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


def _metadata_candidates(data: object) -> list[tuple[dict[str, Any], str, bool]]:
    candidates: list[tuple[dict[str, Any], str, bool]] = []

    def walk(value: object, path: str) -> None:
        if isinstance(value, dict):
            metadata = value.get("_meta")
            if isinstance(metadata, dict):
                ui = metadata.get("ui")
                if isinstance(ui, dict):
                    candidates.append((ui, _path(path, "_meta.ui"), True))
                legacy = metadata.get("ui/resourceUri")
                if legacy is not None:
                    candidates.append(
                        (
                            {
                                "resourceUri": legacy,
                                "mimeType": value.get("mimeType") or metadata.get("mimeType"),
                                "visibility": metadata.get("ui/visibility"),
                            },
                            _path(path, "_meta.ui/resourceUri"),
                            False,
                        )
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
) -> McpAppInventory:
    """Return a stable MCP Apps inventory from explicit declarations."""
    resources: list[McpAppResourceDeclaration] = []
    inline_resources: list[McpAppInlineResource] = []
    unknown: list[McpAppUnknownDeclaration] = []
    remaining_inline_bytes = INLINE_RESOURCE_TOTAL_MAX_BYTES

    for candidate, candidate_path, modern in _metadata_candidates(data):
        path = _path(declaration_path, candidate_path)
        uri_value = candidate.get("resourceUri") or candidate.get("resource_uri")
        mime_type = _safe_string(candidate.get("mimeType") or candidate.get("mime_type"))
        uri = _resource_uri(uri_value)
        if uri is None:
            if uri_value is not None or _mime_is_mcp_app(mime_type):
                unknown.append(
                    McpAppUnknownDeclaration(
                        declaration_path=_path(path, "resourceUri"),
                        reason="invalid_or_redacted_resource_uri",
                        scope=scope,
                    )
                )
            continue
        if not (uri.startswith("ui://") or _mime_is_mcp_app(mime_type)):
            continue
        declared_visibility, effective_visibility, visibility_source = _visibility(
            candidate.get("visibility"), modern=modern
        )
        origins = [
            *_csp_origins(candidate.get("csp"), _path(path, "csp"), scope),
            *_csp_origins(candidate.get("CSP"), _path(path, "CSP"), scope),
        ]
        permissions = _permission_values(
            candidate.get("permissions"), _path(path, "permissions"), scope
        )
        app_capabilities = _string_list(candidate.get("capabilities"))
        tool_surfaces = [
            *_tool_surfaces(candidate.get("tools"), _path(path, "tools"), scope),
            *_tool_surfaces(candidate.get("toolSurfaces"), _path(path, "toolSurfaces"), scope),
            *_tool_surfaces(
                candidate.get("appCallableTools"), _path(path, "appCallableTools"), scope
            ),
        ]
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
