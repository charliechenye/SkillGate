from __future__ import annotations

import json
import stat
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

from skillgate.mcpb.errors import McpbError
from skillgate.mcpb.manifest import sanitize_metadata_url, sanitize_runtime_url
from skillgate.mcpb.scan import scan_mcpb

FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def build_mcpb(path: Path, manifest_bytes: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in [("manifest.json", manifest_bytes), ("server/index.js", b"ok\n")]:
            info = zipfile.ZipInfo(name)
            info.date_time = FIXED_TIME
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, content)
    return path


def valid_manifest(**updates: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "manifest-test",
        "version": "1.0.0",
        "server": {
            "type": "python",
            "entry_point": "server/index.js",
            "mcp_config": {"command": "python", "args": ["${__dirname}/server/index.js"]},
        },
    }
    data.update(updates)
    return data


def test_minimal_manifest_accepts_missing_description_and_author(tmp_path: Path) -> None:
    result = scan_mcpb(build_mcpb(tmp_path / "minimal.mcpb", json.dumps(valid_manifest()).encode()))
    assert result.bundle_manifest.manifest.name == "manifest-test"
    assert result.bundle_manifest.manifest.manifest_version is None


def test_future_manifest_version_is_not_rejected(tmp_path: Path) -> None:
    data = valid_manifest(manifest_version="2029-01")
    result = scan_mcpb(build_mcpb(tmp_path / "future.mcpb", json.dumps(data).encode()))
    assert result.bundle_manifest.manifest.manifest_version == "2029-01"


def test_invalid_version_field_type_is_shape_error(tmp_path: Path) -> None:
    data = valid_manifest(manifest_version={"bad": True})
    with pytest.raises(McpbError) as excinfo:
        scan_mcpb(build_mcpb(tmp_path / "bad-version.mcpb", json.dumps(data).encode()))
    assert excinfo.value.code == "mcpb_manifest_invalid_shape"
    assert excinfo.value.field_path == "manifest_version"


def test_unsafe_entry_point_is_fatal(tmp_path: Path) -> None:
    data = valid_manifest(
        server={"type": "node", "entry_point": "../run.js", "mcp_config": {"command": "node"}}
    )
    with pytest.raises(McpbError) as excinfo:
        scan_mcpb(build_mcpb(tmp_path / "unsafe.mcpb", json.dumps(data).encode()))
    assert excinfo.value.code == "mcpb_entry_point_unsafe"
    assert excinfo.value.field_path == "server.entry_point"


def _set_manifest_value(
    data: dict[str, object], field_path: str, value: object
) -> dict[str, object]:
    updated = deepcopy(data)
    current: object = updated
    parts = field_path.split(".")
    for part in parts[:-1]:
        assert isinstance(current, dict)
        current = current.setdefault(part, {})
    assert isinstance(current, dict)
    current[parts[-1]] = value
    return updated


@pytest.mark.parametrize(
    ("field_path", "value"),
    [
        ("server.mcp_config.args", None),
        ("server.mcp_config.args", "argument"),
        ("server.mcp_config.args", ["ok", 2]),
        ("server.mcp_config.env", None),
        ("server.mcp_config.env", []),
        ("server.mcp_config.env", {"A": 1}),
        ("server.mcp_config.platform_overrides", None),
        ("server.mcp_config.platform_overrides.win32", None),
        ("server.mcp_config.platform_overrides.win32.command", None),
        ("server.mcp_config.platform_overrides.win32.args", None),
        ("server.mcp_config.platform_overrides.win32.env", None),
        ("user_config", None),
        ("user_config.api_key", None),
        ("user_config.api_key.type", None),
        ("user_config.api_key.sensitive", "true"),
        ("user_config.api_key.required", 1),
        ("manifest_version", None),
        ("dxt_version", None),
    ],
)
def test_invalid_present_interpreted_fields_are_shape_errors(
    tmp_path: Path, field_path: str, value: object
) -> None:
    data = _set_manifest_value(valid_manifest(), field_path, value)
    with pytest.raises(McpbError) as excinfo:
        scan_mcpb(build_mcpb(tmp_path / "invalid-field.mcpb", json.dumps(data).encode()))
    assert excinfo.value.code == "mcpb_manifest_invalid_shape"
    assert excinfo.value.field_path == field_path


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:not-a-port/api",
        "https://example.com:99999/api",
        "https://[::1/api",
        "https:///api",
        "http://",
        "https://:443/path",
    ],
)
def test_runtime_url_malformed_values_are_shape_errors(url: str) -> None:
    with pytest.raises(McpbError) as excinfo:
        sanitize_runtime_url(url, "server.mcp_config.command")
    assert excinfo.value.code == "mcpb_manifest_invalid_shape"
    assert excinfo.value.field_path == "server.mcp_config.command"
    assert url not in json.dumps(excinfo.value.to_data())


def test_runtime_url_ipv6_and_secret_parts_are_sanitized() -> None:
    assert (
        sanitize_runtime_url(
            "https://user:password@[2001:db8::1]:8443/api?token=secret#section",
            "server.mcp_config.command",
        )
        == "https://[2001:db8::1]:8443/api"
    )
    assert (
        sanitize_runtime_url("HTTP://[2001:db8::1]/api?x=1#frag", "server.mcp_config.command")
        == "http://[2001:db8::1]/api"
    )


def test_malformed_runtime_url_reports_platform_override_field_path(tmp_path: Path) -> None:
    data = valid_manifest(
        server={
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {
                "command": "node",
                "platform_overrides": {"win32": {"args": ["ok", "https://[::1/api"]}},
            },
        }
    )
    with pytest.raises(McpbError) as excinfo:
        scan_mcpb(build_mcpb(tmp_path / "bad-url.mcpb", json.dumps(data).encode()))
    assert excinfo.value.code == "mcpb_manifest_invalid_shape"
    assert excinfo.value.field_path == "server.mcp_config.platform_overrides.win32.args[1]"


def test_metadata_url_malformed_is_ignored_and_valid_is_retained(tmp_path: Path) -> None:
    assert sanitize_metadata_url("https://[::1/api") is None
    data = valid_manifest(
        homepage="https://[::1/api",
        documentation="https://user:pass@Example.COM:8443/docs?token=secret#frag",
    )
    result = scan_mcpb(build_mcpb(tmp_path / "metadata.mcpb", json.dumps(data).encode()))
    manifest = result.bundle_manifest.manifest
    assert manifest.metadata_urls == ["https://example.com:8443/docs"]
    assert "https://[::1/api" not in json.dumps(manifest.model_dump())
    assert "SG003" not in [finding.rule_id for finding in result.scan_report.findings]
    assert "network_egress" not in [cap.type for cap in result.scan_report.capabilities]
