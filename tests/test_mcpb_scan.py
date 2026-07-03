from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

import pytest

from skillgate.mcpb.errors import McpbError, mcpb_archive_error_data, sanitized_archive_message
from skillgate.mcpb.reporting import mcpb_scan_json
from skillgate.mcpb.scan import (
    PREFIX_BYTES,
    _executable_kind,
    _looks_like_secret_env_name,
    scan_mcpb,
)

FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def manifest(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "example-bundle",
        "version": "1.0.0",
        "manifest_version": "0.1.0",
        "server": {
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {"command": "node", "args": ["${__dirname}/server/index.js"]},
        },
    }
    data.update(overrides)
    return data


def build_mcpb(path: Path, entries: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries:
            info = zipfile.ZipInfo(name)
            info.date_time = FIXED_TIME
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            mode = stat.S_IFDIR | 0o700 if name.endswith("/") else stat.S_IFREG | 0o600
            info.external_attr = (mode << 16) | (0x10 if name.endswith("/") else 0)
            archive.writestr(info, content)
        archive.comment = b""
    return path


def bundle(
    path: Path, data: dict[str, object], extra: list[tuple[str, bytes]] | None = None
) -> Path:
    entries = [
        ("manifest.json", json.dumps(data, sort_keys=True).encode()),
        ("server/index.js", b"console.log('ok')\n"),
    ]
    if extra:
        entries.extend(extra)
    return build_mcpb(path, entries)


def rule_ids(result) -> list[str]:
    return [finding.rule_id for finding in result.scan_report.findings]


def test_executable_kind_uses_bounded_prefix_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sizes: list[int] = []
    original_open = Path.open

    def fail_read_bytes(self: Path) -> bytes:
        raise AssertionError("Path.read_bytes must not be used for executable detection")

    class RecordingStream:
        def __init__(self, stream) -> None:
            self._stream = stream

        def __enter__(self):
            self._stream.__enter__()
            return self

        def __exit__(self, exc_type, exc, tb):
            return self._stream.__exit__(exc_type, exc, tb)

        def read(self, size: int = -1) -> bytes:
            sizes.append(size)
            return self._stream.read(size)

    def recording_open(self: Path, *args: object, **kwargs: object):
        return RecordingStream(original_open(self, *args, **kwargs))

    cases = [
        ("server/tool.exe", b"MZ" + b"x" * (PREFIX_BYTES * 4), "pe"),
        ("server/tool", b"\x7fELF" + b"x" * (PREFIX_BYTES * 4), "elf"),
        ("server/tool", b"\xfe\xed\xfa\xcf" + b"x" * (PREFIX_BYTES * 4), "mach_o"),
        ("server/tool.exe", b"plain" + b"x" * (PREFIX_BYTES * 4), "executable_extension"),
        ("server/lib.dll", b"plain" + b"x" * (PREFIX_BYTES * 4), "shared_library"),
        ("server/lib.so", b"plain" + b"x" * (PREFIX_BYTES * 4), "shared_library"),
        ("server/lib.dylib", b"plain" + b"x" * (PREFIX_BYTES * 4), "shared_library"),
    ]
    files = []
    for index, (_name, content, _expected) in enumerate(cases):
        file_path = tmp_path / f"artifact-{index}"
        file_path.write_bytes(content)
        files.append(file_path)

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)
    monkeypatch.setattr(Path, "open", recording_open)

    for file_path, (name, _content, expected) in zip(files, cases, strict=True):
        assert _executable_kind(file_path, name) == expected

    assert sizes == [PREFIX_BYTES] * len(cases)


@pytest.mark.parametrize(
    "name",
    [
        "API_KEY",
        "SERVICE_TOKEN",
        "CLIENT_SECRET",
        "DB_PASSWORD",
        "AWS_CREDENTIALS",
        "ACCESS_KEY_ID",
        "PRIVATE_KEY_PATH",
    ],
)
def test_secret_env_name_positive_cases_create_sg005(tmp_path: Path, name: str) -> None:
    assert _looks_like_secret_env_name(name)
    data = manifest(
        server={
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {"command": "node", "env": {name: "raw-secret-value"}},
        }
    )
    result = scan_mcpb(bundle(tmp_path / f"{name}.mcpb", data))
    rendered = mcpb_scan_json(result)
    assert "SG005" in rule_ids(result)
    assert name in rendered
    assert "raw-secret-value" not in rendered


@pytest.mark.parametrize(
    "name",
    [
        "MONKEY_MODE",
        "HOCKEY_SCORE",
        "KEYSTONE_REGION",
        "SECRETARY_EMAIL",
        "TOKENIZER_MODEL",
        "PASSWORDLESS_MODE",
        "PUBLIC_KEY",
        "CACHE_KEY",
        "SORT_KEY",
        "PRIMARY_KEY",
        "KEYBOARD_LAYOUT",
    ],
)
def test_secret_env_name_negative_cases_do_not_create_sg005(tmp_path: Path, name: str) -> None:
    assert not _looks_like_secret_env_name(name)
    data = manifest(
        server={
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {"command": "node", "env": {name: "not-public"}},
        }
    )
    result = scan_mcpb(bundle(tmp_path / f"{name}.mcpb", data))
    assert "SG005" not in rule_ids(result)
    assert "not-public" not in mcpb_scan_json(result)


def test_safe_bundle_scans_and_preserves_fingerprints(tmp_path: Path) -> None:
    path = bundle(tmp_path / "safe.mcpb", manifest())
    result = scan_mcpb(path)
    assert result.bundle_manifest.manifest.server_type == "node"
    assert result.bundle_manifest.manifest.entry_point == "server/index.js"
    assert "manifest.json" not in [file.path for file in result.scan_report.scanned_files]
    assert "server/index.js" in [file.path for file in result.scan_report.scanned_files]
    assert mcpb_scan_json(result) == mcpb_scan_json(scan_mcpb(path))
    data = json.loads(mcpb_scan_json(result))
    assert all("fingerprint" in item for item in data["scan_report"]["findings"])
    assert str(tmp_path) not in mcpb_scan_json(result)


def test_manifest_contract_accepts_missing_optional_and_future_version(tmp_path: Path) -> None:
    data = manifest(manifest_version="99.0.future", unknown={"ok": True})
    result = scan_mcpb(bundle(tmp_path / "future.mcpb", data))
    assert result.bundle_manifest.manifest.manifest_version == "99.0.future"
    assert "SG014" not in rule_ids(result)


def test_uv_is_known_and_unknown_server_type_gets_sg014(tmp_path: Path) -> None:
    uv_data = manifest(
        server={
            "type": "uv",
            "entry_point": "server/index.js",
            "mcp_config": {"command": "uv", "args": []},
        }
    )
    assert "SG014" not in rule_ids(scan_mcpb(bundle(tmp_path / "uv.mcpb", uv_data)))
    odd = manifest(
        server={
            "type": "ruby",
            "entry_point": "server/index.js",
            "mcp_config": {"command": "ruby", "args": []},
        }
    )
    result = scan_mcpb(bundle(tmp_path / "odd.mcpb", odd))
    assert any(f.rule_id == "SG014" and f.severity == "medium" for f in result.scan_report.findings)


def test_conflicting_versions_produce_sg014_not_fatal(tmp_path: Path) -> None:
    data = manifest(manifest_version="1", dxt_version="2")
    result = scan_mcpb(bundle(tmp_path / "versions.mcpb", data))
    assert result.bundle_manifest.manifest.manifest_version == "1"
    assert any(
        "conflicts" in (f.evidence or "")
        for f in result.scan_report.findings
        if f.rule_id == "SG014"
    )


def test_duplicate_nested_environment_key_is_rejected(tmp_path: Path) -> None:
    raw = (
        b'{"name":"x","version":"1","server":{"type":"node",'
        b'"entry_point":"server/index.js","mcp_config":{"command":"node",'
        b'"env":{"A":"1","A":"2"}}}}'
    )
    path = build_mcpb(tmp_path / "dup.mcpb", [("manifest.json", raw), ("server/index.js", b"ok")])
    with pytest.raises(McpbError) as excinfo:
        scan_mcpb(path)
    assert excinfo.value.code == "mcpb_manifest_duplicate_key"


def test_manifest_size_boundary(tmp_path: Path) -> None:
    exact = b" " * (1_048_576 - 2) + b"{}"
    accepted = build_mcpb(tmp_path / "exact.mcpb", [("manifest.json", exact)])
    with pytest.raises(McpbError) as excinfo:
        scan_mcpb(accepted)
    assert excinfo.value.code == "mcpb_manifest_invalid_shape"
    too_large = build_mcpb(
        tmp_path / "large.mcpb", [("manifest.json", b"{" + b" " * 1_048_575 + b"}")]
    )
    with pytest.raises(McpbError) as large:
        scan_mcpb(too_large)
    assert large.value.code == "mcpb_manifest_too_large"
    assert large.value.to_data()["limit"] == "max_mcpb_manifest_bytes"
    assert large.value.to_data()["observed"] == 1_048_577
    assert large.value.to_data()["allowed"] == 1_048_576


def test_platform_overrides_are_effective_and_private(tmp_path: Path) -> None:
    data = manifest(
        user_config={"api_key": {"type": "string", "sensitive": True}},
        server={
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {
                "command": "node",
                "args": ["${__dirname}/server/index.js"],
                "env": {"BASE_TOKEN": "base-secret"},
                "platform_overrides": {
                    "win32": {
                        "command": "C:\\Windows\\System32\\cmd.exe",
                        "args": [
                            "/password",
                            "literal-password-value",
                            "https://user:pass@example.com:8443/api?token=x#frag",
                        ],
                        "env": {"API_KEY": "${user_config.api_key}"},
                    },
                    "linux": {"env": {"BASE_TOKEN": "replacement"}},
                },
            },
        },
    )
    result = scan_mcpb(bundle(tmp_path / "overrides.mcpb", data))
    variants = result.bundle_manifest.manifest.startup_variants
    assert [variant.platform for variant in variants] == ["default", "linux", "win32"]
    assert variants[1].env_names == ["BASE_TOKEN"]
    assert variants[2].env_names == ["API_KEY", "BASE_TOKEN"]
    rendered = mcpb_scan_json(result)
    assert "base-secret" not in rendered
    assert "replacement" not in rendered
    assert "literal-password-value" not in rendered
    assert "https://example.com:8443/api" in rendered
    assert "user:pass" not in rendered
    assert "token=x" not in rendered
    assert {"SG001", "SG003", "SG005"} <= set(rule_ids(result))


def test_file_selection_excludes_dependencies_and_includes_runtime_files(tmp_path: Path) -> None:
    extra = [
        ("server/helper.js", b"console.log('helper')\n"),
        ("server/node_modules/bad/index.js", b"bash evil.sh\n"),
        ("server/venv/bad.py", b"import os; os.system('bad')\n"),
        ("requirements.txt", b"safe\n"),
        ("requirements-test.txt", b"safe\n"),
        ("vendor/requirements.txt", b"bash no.sh\n"),
        ("uv.lock", b"version = 1\n"),
    ]
    result = scan_mcpb(bundle(tmp_path / "select.mcpb", manifest(), extra))
    scanned = {file.path for file in result.scan_report.scanned_files}
    assert {
        "server/index.js",
        "server/helper.js",
        "requirements.txt",
        "requirements-test.txt",
        "uv.lock",
    } <= scanned
    assert "server/node_modules/bad/index.js" not in scanned
    assert "server/venv/bad.py" not in scanned
    assert "vendor/requirements.txt" not in scanned
    assert "SG001" not in rule_ids(result)


def test_deduplicates_missing_entry_and_artifacts(tmp_path: Path) -> None:
    data = manifest(
        server={
            "type": "binary",
            "entry_point": "server/tool.exe",
            "mcp_config": {"command": "server/tool.exe", "args": ["${__dirname}/server/tool.exe"]},
        }
    )
    result = scan_mcpb(bundle(tmp_path / "bin.mcpb", data, [("server/tool.exe", b"MZbinary")]))
    sg015 = [f for f in result.scan_report.findings if f.rule_id == "SG015"]
    assert len(sg015) == 1
    assert result.bundle_manifest.embedded_binaries[0].kind == "pe"
    assert result.bundle_manifest.embedded_binaries[0].is_entry_point is True

    missing = manifest(
        server={
            "type": "node",
            "entry_point": "server/missing.js",
            "mcp_config": {"command": "node", "args": ["${__dirname}/server/missing.js"]},
        }
    )
    missing_result = scan_mcpb(
        build_mcpb(tmp_path / "missing.mcpb", [("manifest.json", json.dumps(missing).encode())])
    )
    sg014 = [
        f
        for f in missing_result.scan_report.findings
        if f.rule_id == "SG014" and "missing.js" in (f.evidence or "")
    ]
    assert len(sg014) == 1


def test_nested_archives_and_shared_libraries_get_single_sg015(tmp_path: Path) -> None:
    result = scan_mcpb(
        bundle(
            tmp_path / "artifacts.mcpb",
            manifest(),
            [("lib/libnative.so", b"not-magic"), ("deps/pkg.whl", b"PK\x03\x04nested")],
        )
    )
    sg015 = [f for f in result.scan_report.findings if f.rule_id == "SG015"]
    assert len(sg015) == 2
    assert "deps/pkg.whl" in result.bundle_manifest.nested_archives


def test_archive_error_sanitization_preserves_member_not_archive(tmp_path: Path) -> None:
    path = build_mcpb(tmp_path / "private-name.mcpb", [("../escape.txt", b"x")])
    with pytest.raises(Exception) as excinfo:
        scan_mcpb(path.resolve())
    data = mcpb_archive_error_data(excinfo.value)
    assert data["code"] == "unsafe_path"
    assert data["member_path"] == "../escape.txt"
    assert "archive_path" not in data
    assert str(path) not in json.dumps(data)
    assert path.name not in json.dumps(data)
    assert (
        sanitized_archive_message(excinfo.value)
        == "Archive member path must not contain parent traversal"
    )


def test_sanitizer_does_not_broadly_remove_archive_word(tmp_path: Path) -> None:
    missing = tmp_path / "missing.mcpb"
    with pytest.raises(Exception) as excinfo:
        scan_mcpb(missing.resolve())
    assert "Archive path does not exist" == sanitized_archive_message(excinfo.value)
