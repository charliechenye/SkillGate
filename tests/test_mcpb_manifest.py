from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

import pytest

from skillgate.mcpb.errors import McpbError
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
