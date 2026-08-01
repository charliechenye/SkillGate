from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from skillgate.mcp_apps import (
    detect_bridge_markers,
    inventory_from_json_text,
)
from skillgate.models import Capability

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
}
MCP_APP_MAX_ASSETS = 100
MCP_APP_MAX_ASSET_BYTES = 1_048_576
MCP_APP_MAX_TOTAL_ASSET_BYTES = 5_242_880
MCP_APP_ASSET_EXTENSIONS = {".html": "html", ".css": "css", ".js": "javascript"}
HTML_REF_RE = re.compile(
    r"""(?ix)(?:src|href)\s*=\s*["'](?P<ref>[^"']+\.(?:html|css|js)(?:\?[^"']*)?)["']"""
)
CSS_REF_RE = re.compile(
    r"""(?ix)(?:@import\s+["']|url\(\s*["']?)(?P<ref>[^"')]+?\.(?:html|css|js)(?:\?[^"')]+)?)"""
)
JS_REF_RE = re.compile(
    r"""(?ix)(?:import\s+(?:[^"'()]+\s+from\s+)?|import\s*\(|new\s+URL\s*\()\s*["'](?P<ref>[^"']+\.(?:html|css|js)(?:\?[^"']*)?)["']"""
)


@dataclass(frozen=True)
class McpAppAssetRecord:
    path: str
    kind: str
    association: str
    size_bytes: int | None
    sha256: str | None
    skipped_reason: str | None


@dataclass(frozen=True)
class McpAppHostBridgeRecord:
    path: str
    markers: tuple[str, ...]
    association: str


@dataclass(frozen=True)
class McpAppAssetInventory:
    assets: tuple[McpAppAssetRecord, ...]
    bridges: tuple[McpAppHostBridgeRecord, ...]
    limit_reached: bool = False


def _safe_rel(root: Path, candidate: Path) -> str | None:
    try:
        rel = candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return rel.as_posix()


def _is_excluded_rel(rel_path: str) -> bool:
    return any(part in EXCLUDED_DIRS for part in Path(rel_path).parts)


def _strip_ref_suffix(value: str) -> str:
    return value.split("#", 1)[0].split("?", 1)[0].replace("\\", "/")


def _asset_kind(path: str) -> str | None:
    return MCP_APP_ASSET_EXTENSIONS.get(Path(path).suffix.lower())


def _resource_uri_candidates(root: Path, source: Path, uri: str) -> list[Path]:
    parsed = urlparse(uri)
    candidates: list[Path] = []
    if parsed.scheme == "ui":
        combined = "/".join(part for part in [parsed.netloc, parsed.path.lstrip("/")] if part)
        if combined:
            primary = root / combined
            candidates.append(primary)
            if primary.exists():
                return candidates
        if parsed.path:
            candidates.append(root / parsed.path.lstrip("/"))
    elif "://" not in uri and not uri.startswith("/"):
        candidates.append(source.parent / uri)
        candidates.append(root / uri)
    return candidates


def _resolve_ref(root: Path, source: Path, raw_ref: str) -> tuple[Path | None, str | None]:
    ref = _strip_ref_suffix(raw_ref)
    if "://" in ref or ref.startswith("ui://"):
        return None, "external_reference"
    if ref.startswith("/"):
        return None, "outside_scan_root"
    candidate = source.parent / ref
    rel = _safe_rel(root, candidate)
    if rel is None:
        return None, "outside_scan_root"
    if _is_excluded_rel(rel):
        return None, "excluded_path"
    if _asset_kind(rel) is None:
        return None, "unsupported_file_type"
    return candidate.resolve(), None


def _refs_from_text(path: str, text: str) -> list[str]:
    suffix = Path(path).suffix.lower()
    patterns = []
    if suffix == ".html":
        patterns = [HTML_REF_RE, CSS_REF_RE]
    elif suffix == ".css":
        patterns = [CSS_REF_RE]
    elif suffix == ".js":
        patterns = [JS_REF_RE]
    refs = []
    for pattern in patterns:
        refs.extend(match.group("ref") for match in pattern.finditer(text))
    return sorted(set(refs))


def _asset_record(
    root: Path,
    path: Path,
    association: str,
    *,
    remaining_bytes: int,
) -> tuple[McpAppAssetRecord, str | None, int]:
    rel = _safe_rel(root, path)
    if rel is None:
        return (
            McpAppAssetRecord(
                path="<outside_scan_root>",
                kind="unknown",
                association=association,
                size_bytes=None,
                sha256=None,
                skipped_reason="outside_scan_root",
            ),
            None,
            0,
        )
    kind = _asset_kind(rel) or "unknown"
    if _is_excluded_rel(rel):
        return (
            McpAppAssetRecord(rel, kind, association, None, None, "excluded_path"),
            None,
            0,
        )
    try:
        size_bytes = path.stat().st_size
    except OSError:
        return (
            McpAppAssetRecord(rel, kind, association, None, None, "missing_reference"),
            None,
            0,
        )
    if size_bytes > MCP_APP_MAX_ASSET_BYTES:
        return (
            McpAppAssetRecord(rel, kind, association, size_bytes, None, "asset_too_large"),
            None,
            0,
        )
    if size_bytes > remaining_bytes:
        return (
            McpAppAssetRecord(
                rel,
                kind,
                association,
                size_bytes,
                None,
                "asset_total_limit_exceeded",
            ),
            None,
            0,
        )
    try:
        with path.open("rb") as stream:
            data = stream.read(MCP_APP_MAX_ASSET_BYTES + 1)
    except OSError:
        return (
            McpAppAssetRecord(rel, kind, association, None, None, "missing_reference"),
            None,
            0,
        )
    if len(data) > MCP_APP_MAX_ASSET_BYTES:
        return (
            McpAppAssetRecord(rel, kind, association, len(data), None, "asset_too_large"),
            None,
            0,
        )
    sha256 = hashlib.sha256(data).hexdigest()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return (
            McpAppAssetRecord(rel, kind, association, len(data), sha256, "asset_not_utf8"),
            None,
            len(data),
        )
    return (McpAppAssetRecord(rel, kind, association, len(data), sha256, None), text, len(data))


def mcp_app_asset_paths(root: Path, seed_paths: set[Path]) -> list[Path]:
    inventory = inventory_local_mcp_app_assets(root, seed_paths)
    return sorted(
        {
            (root / asset.path).resolve()
            for asset in inventory.assets
            if asset.skipped_reason is None and asset.size_bytes is not None
        },
        key=lambda item: item.resolve().relative_to(root.resolve()).as_posix(),
    )


def inventory_local_mcp_app_assets(root: Path, seed_paths: set[Path]) -> McpAppAssetInventory:
    root = root.resolve()
    queue: list[tuple[Path, str]] = []
    records: dict[tuple[str, str], McpAppAssetRecord] = {}
    bridges: dict[tuple[str, tuple[str, ...], str], McpAppHostBridgeRecord] = {}
    reserved_records: set[tuple[str, str]] = set()
    remaining_bytes = MCP_APP_MAX_TOTAL_ASSET_BYTES
    limit_reached = False

    def reserve(path: str, association: str) -> bool:
        nonlocal limit_reached
        key = (path, association)
        if key in reserved_records:
            return False
        if len(reserved_records) >= MCP_APP_MAX_ASSETS:
            limit_reached = True
            return False
        reserved_records.add(key)
        return True

    def record_skip(path: str, association: str, kind: str, reason: str) -> None:
        if reserve(path, association):
            records[(path, association)] = McpAppAssetRecord(
                path, kind, association, None, None, reason
            )

    def enqueue(path: Path, association: str) -> None:
        rel = _safe_rel(root, path)
        if rel is None:
            record_skip("<outside_scan_root>", association, "unknown", "outside_scan_root")
            return
        if reserve(rel, association):
            queue.append((path.resolve(), association))

    for seed in sorted(seed_paths, key=lambda item: _safe_rel(root, item) or ""):
        try:
            data = json.loads(seed.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        inventory = inventory_from_json_text(
            json.dumps(data, sort_keys=True),
            declaration_path="",
            scope="local_assets",
        )
        for resource in inventory.resources:
            for inline in inventory.inline_resources:
                if inline.text and inline.resource_uri == resource.resource_uri:
                    markers = detect_bridge_markers(inline.text)
                    if markers:
                        bridge = McpAppHostBridgeRecord(
                            path=f"inline:{inline.resource_uri}",
                            markers=markers,
                            association=resource.resource_uri,
                        )
                        bridges[(bridge.path, bridge.markers, bridge.association)] = bridge
            for candidate in _resource_uri_candidates(root, seed, resource.resource_uri):
                rel = _safe_rel(root, candidate)
                if rel is None:
                    record_skip(
                        "<outside_scan_root>",
                        resource.resource_uri,
                        "unknown",
                        "outside_scan_root",
                    )
                    continue
                if _asset_kind(rel) is None:
                    continue
                enqueue(candidate, resource.resource_uri)

    while queue:
        path, association = queue.pop(0)
        record, text, consumed = _asset_record(
            root, path, association, remaining_bytes=remaining_bytes
        )
        remaining_bytes -= consumed
        records[(record.path, record.association)] = record
        if text is None:
            continue
        markers = detect_bridge_markers(text)
        if markers:
            bridge = McpAppHostBridgeRecord(
                path=record.path,
                markers=markers,
                association=association,
            )
            bridges[(bridge.path, bridge.markers, bridge.association)] = bridge
        for raw_ref in _refs_from_text(record.path, text):
            candidate, skip_reason = _resolve_ref(root, path, raw_ref)
            if candidate is None:
                skipped_path = _strip_ref_suffix(raw_ref)
                record_skip(
                    skipped_path,
                    association,
                    _asset_kind(skipped_path) or "unknown",
                    skip_reason or "unsupported_file_type",
                )
                continue
            if not candidate.exists():
                rel_candidate = _safe_rel(root, candidate) or _strip_ref_suffix(raw_ref)
                record_skip(
                    rel_candidate,
                    association,
                    _asset_kind(rel_candidate) or "unknown",
                    "missing_reference",
                )
                continue
            enqueue(candidate, association)

    return McpAppAssetInventory(
        assets=tuple(sorted(records.values(), key=lambda item: (item.path, item.association))),
        bridges=tuple(
            sorted(bridges.values(), key=lambda item: (item.path, item.markers, item.association))
        ),
        limit_reached=limit_reached,
    )


def mcp_app_asset_capabilities(
    inventory: McpAppAssetInventory,
    *,
    source_file: str | None = None,
) -> list[Capability]:
    from skillgate.rules.base import make_capability

    capabilities: list[Capability] = []
    for asset in inventory.assets:
        capabilities.append(
            make_capability(
                "mcp_app_asset",
                source_file or asset.path,
                None,
                resource=asset.path,
                kind=asset.kind,
                association=asset.association,
                size_bytes=asset.size_bytes,
                sha256=asset.sha256,
                skipped_reason=asset.skipped_reason,
            )
        )
    for bridge in inventory.bridges:
        for marker in bridge.markers:
            capabilities.append(
                make_capability(
                    "mcp_app_host_bridge",
                    source_file or bridge.path,
                    None,
                    resource=f"{bridge.path}:{marker}",
                    path=bridge.path,
                    marker=marker,
                    association=bridge.association,
                )
            )
    if inventory.limit_reached:
        capabilities.append(
            make_capability(
                "mcp_app_unknown_declaration",
                source_file or "<mcp-app-assets>",
                None,
                resource="<asset-inventory>",
                declaration_path="<asset-inventory>",
                reason="asset_count_limit_exceeded",
                scope="local_assets",
            )
        )
    return capabilities
