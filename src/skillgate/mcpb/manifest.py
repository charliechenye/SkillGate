from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from skillgate.archive import (
    ArchiveError,
    ArchiveLimits,
    ArchiveMember,
    normalize_archive_member_path,
)

from .errors import MAX_MCPB_MANIFEST_BYTES, McpbError
from .models import McpbManifestSummary, McpbStartupVariant

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
USER_CONFIG_RE = re.compile(r"\$\{user_config\.([A-Za-z0-9_.-]+)\}")
SENSITIVE_ARG_NAMES = {
    "token",
    "secret",
    "password",
    "api-key",
    "api_key",
    "credential",
    "credentials",
    "access-token",
    "access_token",
    "auth-token",
    "auth_token",
}
SCRIPT_OR_EXEC_SUFFIXES = {
    ".js",
    ".mjs",
    ".cjs",
    ".py",
    ".sh",
    ".bash",
    ".ps1",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
}
METADATA_URL_FIELDS = (
    ("homepage",),
    ("documentation",),
    ("support",),
    ("author", "url"),
    ("repository", "url"),
)


@dataclass(frozen=True)
class StartupVariantAnalysis:
    platform: str
    command: str
    raw_args: list[str]
    sanitized_args: list[str]
    env: dict[str, str]
    env_names: list[str]
    runtime_endpoints: list[str]
    startup_references: list[str]
    sensitive_user_config_refs: list[str]


@dataclass(frozen=True)
class ManifestAnalysis:
    summary: McpbManifestSummary
    startup_variants: list[StartupVariantAnalysis]
    startup_references: list[str]
    ancillary_references: list[str]
    version_conflict: bool
    unknown_server_type: bool
    extension_mismatch: bool


class _DuplicateKeyError(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(key)


def parse_manifest(
    root: Path,
    member: ArchiveMember,
    *,
    limits: ArchiveLimits,
) -> ManifestAnalysis:
    if member.uncompressed_size > MAX_MCPB_MANIFEST_BYTES:
        raise McpbError(
            "MCPB manifest exceeds maximum size",
            code="mcpb_manifest_too_large",
            manifest_path="manifest.json",
            limit="max_mcpb_manifest_bytes",
            observed=member.uncompressed_size,
            allowed=MAX_MCPB_MANIFEST_BYTES,
        )
    manifest_path = root / "manifest.json"
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise McpbError(
            "MCPB manifest is missing",
            code="mcpb_manifest_missing",
            manifest_path="manifest.json",
        ) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise McpbError(
            "MCPB manifest is not valid UTF-8",
            code="mcpb_manifest_invalid_utf8",
            manifest_path="manifest.json",
        ) from exc
    try:
        data = json.loads(text, object_pairs_hook=_object_no_duplicates)
    except _DuplicateKeyError as exc:
        raise McpbError(
            "MCPB manifest contains a duplicate key",
            code="mcpb_manifest_duplicate_key",
            manifest_path="manifest.json",
            field_path=exc.key,
        ) from exc
    except json.JSONDecodeError as exc:
        raise McpbError(
            "MCPB manifest is not valid JSON",
            code="mcpb_manifest_invalid_json",
            manifest_path="manifest.json",
        ) from exc
    if not isinstance(data, dict):
        _shape("manifest")

    name = _required_string(data, "name")
    version = _required_string(data, "version")
    server = _required_object(data, "server")
    server_type = _required_string(server, "server.type").strip().lower()
    entry_point = _normalize_reference(
        _required_string(server, "server.entry_point"),
        field_path="server.entry_point",
        limits=limits,
        entry_point=True,
    )
    mcp_config = _required_object(server, "server.mcp_config")
    base_command = _required_string(mcp_config, "server.mcp_config.command")
    base_args = _optional_args(mcp_config, "server.mcp_config.args")
    base_env = _optional_env(mcp_config, "server.mcp_config.env")
    overrides = _optional_overrides(mcp_config)

    manifest_version = _manifest_version(data)
    version_conflict = (
        isinstance(data.get("manifest_version"), str)
        and isinstance(data.get("dxt_version"), str)
        and data["manifest_version"] != data["dxt_version"]
    )
    user_config = _optional_user_config(data.get("user_config"))
    user_config_names = sorted(user_config)
    sensitive_user_config_names = sorted(
        name for name, item in user_config.items() if item.get("sensitive") is True
    )
    sensitive_set = set(sensitive_user_config_names)

    raw_variants: list[tuple[str, str, list[str], dict[str, str]]] = [
        ("default", base_command, base_args, base_env)
    ]
    for platform in sorted(overrides):
        override = overrides[platform]
        command = override.get("command", base_command)
        args = override.get("args", base_args)
        env = {**base_env, **override.get("env", {})}
        raw_variants.append((platform, command, args, env))

    startup_variants: list[StartupVariantAnalysis] = []
    for platform, command, args, env in raw_variants:
        sanitized_args = sanitize_args(args)
        runtime_values = [command, *args, *env.values()]
        runtime_endpoints = sorted(
            {url for value in runtime_values for url in extract_sanitized_urls(value)}
        )
        startup_refs = sorted(
            {
                ref
                for field, value in [("command", command), *[("args", arg) for arg in args]]
                for ref in _extract_local_refs(value, f"server.mcp_config.{field}", limits)
            }
        )
        sensitive_refs = sorted(
            {
                match.group(1)
                for value in env.values()
                for match in USER_CONFIG_RE.finditer(value)
                if match.group(1) in sensitive_set
            }
        )
        startup_variants.append(
            StartupVariantAnalysis(
                platform=platform,
                command=sanitize_command(command),
                raw_args=args,
                sanitized_args=sanitized_args,
                env=env,
                env_names=sorted(env),
                runtime_endpoints=runtime_endpoints,
                startup_references=startup_refs,
                sensitive_user_config_refs=sensitive_refs,
            )
        )

    startup_references = sorted(
        {entry_point, *[r for v in startup_variants for r in v.startup_references]}
    )
    ancillary_references = sorted(_ancillary_refs(data, limits))
    metadata_urls = sorted(_metadata_urls(data))
    runtime_endpoints = sorted(
        {url for variant in startup_variants for url in variant.runtime_endpoints}
    )
    public_variants = [
        McpbStartupVariant(
            platform=variant.platform,
            command=variant.command,
            args=variant.sanitized_args,
            env_names=variant.env_names,
        )
        for variant in startup_variants
    ]
    unknown_server_type = server_type not in {"node", "python", "binary", "uv"}
    extension_mismatch = _extension_mismatch(server_type, entry_point)
    summary = McpbManifestSummary(
        path="manifest.json",
        manifest_version=manifest_version,
        name=name.strip(),
        version=version.strip(),
        server_type=server_type,
        entry_point=entry_point,
        startup_variants=public_variants,
        env_names=sorted({name for variant in startup_variants for name in variant.env_names}),
        user_config_names=user_config_names,
        sensitive_user_config_names=sensitive_user_config_names,
        referenced_files=sorted({*startup_references, *ancillary_references}),
        runtime_endpoints=runtime_endpoints,
        metadata_urls=metadata_urls,
    )
    return ManifestAnalysis(
        summary=summary,
        startup_variants=startup_variants,
        startup_references=startup_references,
        ancillary_references=ancillary_references,
        version_conflict=version_conflict,
        unknown_server_type=unknown_server_type,
        extension_mismatch=extension_mismatch,
    )


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(str(key))
        result[key] = value
    return result


def _shape(field_path: str) -> None:
    raise McpbError(
        "MCPB manifest has an invalid shape",
        code="mcpb_manifest_invalid_shape",
        manifest_path="manifest.json",
        field_path=field_path,
    )


def _required_string(data: dict[str, Any], field_path: str) -> str:
    key = field_path.rsplit(".", 1)[-1]
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        _shape(field_path)
    return value


def _required_object(data: dict[str, Any], field_path: str) -> dict[str, Any]:
    key = field_path.rsplit(".", 1)[-1]
    value = data.get(key)
    if not isinstance(value, dict):
        _shape(field_path)
    return value


def _optional_args(data: dict[str, Any], field_path: str) -> list[str]:
    value = data.get(field_path.rsplit(".", 1)[-1], [])
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        _shape(field_path)
    return list(value)


def _optional_env(data: dict[str, Any], field_path: str) -> dict[str, str]:
    value = data.get(field_path.rsplit(".", 1)[-1], {})
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        _shape(field_path)
    return dict(value)


def _optional_overrides(mcp_config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    value = mcp_config.get("platform_overrides", {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        _shape("server.mcp_config.platform_overrides")
    result: dict[str, dict[str, Any]] = {}
    for platform, override in value.items():
        field = f"server.mcp_config.platform_overrides.{platform}"
        if not isinstance(override, dict):
            _shape(field)
        parsed: dict[str, Any] = {}
        if "command" in override:
            if not isinstance(override["command"], str) or not override["command"].strip():
                _shape(f"{field}.command")
            parsed["command"] = override["command"]
        if "args" in override:
            parsed["args"] = _optional_args(override, f"{field}.args")
        if "env" in override:
            parsed["env"] = _optional_env(override, f"{field}.env")
        result[str(platform)] = parsed
    return result


def _optional_user_config(value: object) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        _shape("user_config")
    result: dict[str, dict[str, Any]] = {}
    for name, item in value.items():
        if not isinstance(item, dict):
            _shape(f"user_config.{name}")
        result[str(name)] = {key: item.get(key) for key in ["type", "sensitive", "required"]}
    return result


def _manifest_version(data: dict[str, Any]) -> str | None:
    for key in ["manifest_version", "dxt_version"]:
        if key in data and data[key] is not None and not isinstance(data[key], str):
            _shape(key)
    if isinstance(data.get("manifest_version"), str):
        return data["manifest_version"]
    if isinstance(data.get("dxt_version"), str):
        return data["dxt_version"]
    return None


def _normalize_reference(
    raw: str, *, field_path: str, limits: ArchiveLimits, entry_point: bool = False
) -> str:
    try:
        normalized = normalize_archive_member_path(raw, is_dir=False, limits=limits)
    except ArchiveError as exc:
        raise McpbError(
            "MCPB entry point is unsafe" if entry_point else "MCPB local reference is unsafe",
            code="mcpb_entry_point_unsafe" if entry_point else "mcpb_reference_unsafe",
            manifest_path="manifest.json",
            field_path=field_path,
            member_path=raw,
            limit=exc.limit,
            observed=exc.observed,
            allowed=exc.allowed,
        ) from exc
    return normalized


def extract_sanitized_urls(value: str) -> list[str]:
    return [sanitize_url(match.group(0)) for match in URL_RE.finditer(value)]


def sanitize_url(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower()
    netloc = host
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "", "", ""))


def sanitize_command(command: str) -> str:
    urls = extract_sanitized_urls(command)
    if not urls:
        return command
    sanitized = command
    for raw in URL_RE.finditer(command):
        sanitized = sanitized.replace(raw.group(0), sanitize_url(raw.group(0)))
    return sanitized


def _arg_key(arg: str) -> str | None:
    token = arg.strip()
    while token.startswith("-"):
        token = token[1:]
    if token.startswith("/"):
        token = token[1:]
    if not token:
        return None
    return token.split("=", 1)[0].split(":", 1)[0].lower()


def _is_sensitive_arg_name(name: str | None) -> bool:
    return name in SENSITIVE_ARG_NAMES


def sanitize_args(args: list[str]) -> list[str]:
    sanitized: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            sanitized.append("<redacted>")
            redact_next = False
            continue
        if URL_RE.search(arg):
            clean = arg
            for match in URL_RE.finditer(arg):
                clean = clean.replace(match.group(0), sanitize_url(match.group(0)))
            arg = clean
        if "=" in arg:
            key, value = arg.split("=", 1)
            if _is_sensitive_arg_name(_arg_key(key)):
                sanitized.append(f"{key}=<redacted>")
                continue
        if ":" in arg and arg[:1] in {"/", "-"}:
            key, _value = arg.split(":", 1)
            if _is_sensitive_arg_name(_arg_key(key)):
                sanitized.append(f"{key}:<redacted>")
                continue
        sanitized.append(arg)
        if _is_sensitive_arg_name(_arg_key(arg)):
            redact_next = True
    return sanitized


def _extract_local_refs(value: str, field_path: str, limits: ArchiveLimits) -> list[str]:
    if not isinstance(value, str) or URL_RE.search(value) or USER_CONFIG_RE.search(value):
        return []
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        return []
    candidates: list[str] = []
    for prefix in ["${__dirname}/", "./"]:
        if normalized.startswith(prefix):
            candidates.append(normalized[len(prefix) :])
    if not candidates and "/" in normalized:
        suffix = PurePosixPath(normalized).suffix.lower()
        if suffix in SCRIPT_OR_EXEC_SUFFIXES:
            candidates.append(normalized)
    refs = []
    for candidate in candidates:
        refs.append(_normalize_reference(candidate, field_path=field_path, limits=limits))
    return refs


def _ancillary_refs(data: dict[str, Any], limits: ArchiveLimits) -> set[str]:
    refs: set[str] = set()
    for field, values in _metadata_file_values(data).items():
        for value in values:
            if isinstance(value, str) and _is_relative_file_ref(value):
                refs.add(_normalize_reference(value, field_path=field, limits=limits))
    return refs


def _metadata_file_values(data: dict[str, Any]) -> dict[str, list[object]]:
    values: dict[str, list[object]] = {}
    for key in ["icon", "screenshots"]:
        value = data.get(key)
        values[key] = value if isinstance(value, list) else [value]
    icons = data.get("icons")
    if isinstance(icons, list):
        values["icons.src"] = [item.get("src") for item in icons if isinstance(item, dict)]
    else:
        values["icons.src"] = []
    return values


def _metadata_urls(data: dict[str, Any]) -> set[str]:
    urls: set[str] = set()
    for path in METADATA_URL_FIELDS:
        value: object = data
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if isinstance(value, str):
            urls.update(extract_sanitized_urls(value))
    privacy = data.get("privacy_policies")
    if isinstance(privacy, list):
        for value in privacy:
            if isinstance(value, str):
                urls.update(extract_sanitized_urls(value))
    for value in _metadata_file_values(data).values():
        for item in value:
            if isinstance(item, str):
                urls.update(extract_sanitized_urls(item))
    return urls


def _is_relative_file_ref(value: str) -> bool:
    if URL_RE.search(value) or value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[/\\]", value):
        return False
    return bool(value and not value.startswith("${"))


def _extension_mismatch(server_type: str, entry_point: str) -> bool:
    suffix = PurePosixPath(entry_point).suffix.lower()
    if server_type == "node":
        return suffix not in {".js", ".mjs", ".cjs"}
    if server_type == "python":
        return suffix != ".py"
    return False
