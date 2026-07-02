from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

from conftest import runner

from skillgate.cli import app

FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def build_mcpb(path: Path, entries: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries:
            info = zipfile.ZipInfo(name)
            info.date_time = FIXED_TIME
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, content)
    return path


def manifest(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "cli-bundle",
        "version": "1.0.0",
        "server": {
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {"command": "node", "args": ["${__dirname}/server/index.js"]},
        },
    }
    data.update(overrides)
    return data


def bundle(
    path: Path, data: dict[str, object] | None = None, extra: list[tuple[str, bytes]] | None = None
) -> Path:
    entries = [
        ("manifest.json", json.dumps(data or manifest(), sort_keys=True).encode()),
        ("server/index.js", b"console.log('ok')\n"),
    ]
    if extra:
        entries.extend(extra)
    return build_mcpb(path, entries)


def test_help_commands() -> None:
    assert runner.invoke(app, ["mcpb", "--help"]).exit_code == 0
    result = runner.invoke(app, ["mcpb", "scan", "--help"])
    assert result.exit_code == 0
    assert "MCPB bundle to inspect" in result.output


def test_text_and_json_scan(tmp_path: Path) -> None:
    path = bundle(tmp_path / "safe.mcpb")
    text = runner.invoke(app, ["mcpb", "scan", str(path)])
    assert text.exit_code == 0
    assert "SkillGate MCPB scan completed" in text.output
    assert "Bundle: cli-bundle@1.0.0" in text.output
    json_result = runner.invoke(app, ["mcpb", "scan", str(path), "--format", "json"])
    assert json_result.exit_code == 0
    data = json.loads(json_result.output)
    assert data["bundle_manifest"]["manifest"]["name"] == "cli-bundle"
    assert "scan_report" in data
    assert str(path) not in json_result.output


def test_fail_on_writes_manifest_output_on_exit_1(tmp_path: Path) -> None:
    data = manifest(
        server={
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {"command": "/bin/bash", "args": ["-c", "echo ok"]},
        }
    )
    path = bundle(tmp_path / "risky.mcpb", data)
    manifest_output = tmp_path / "manifest.json"
    result = runner.invoke(
        app,
        [
            "mcpb",
            "scan",
            str(path),
            "--fail-on",
            "medium",
            "--manifest-output",
            str(manifest_output),
        ],
    )
    assert result.exit_code == 1
    assert manifest_output.exists()
    assert (
        json.loads(manifest_output.read_text(encoding="utf-8"))["manifest"]["name"] == "cli-bundle"
    )


def test_fatal_json_and_text_do_not_leak_absolute_path(tmp_path: Path) -> None:
    path = build_mcpb(tmp_path / "private-name.mcpb", [("../escape.txt", b"x")])
    text = runner.invoke(app, ["mcpb", "scan", str(path.resolve())])
    assert text.exit_code == 2
    assert "Error: Archive member path must not contain parent traversal" in text.output
    assert str(path) not in text.output
    assert path.name not in text.output
    json_result = runner.invoke(app, ["mcpb", "scan", str(path.resolve()), "--format", "json"])
    assert json_result.exit_code == 2
    data = json.loads(json_result.output)
    assert data["error"]["code"] == "unsafe_path"
    assert data["error"]["member_path"] == "../escape.txt"
    assert "archive_path" not in data["error"]
    assert str(path) not in json_result.output
    assert path.name not in json_result.output


def test_manifest_output_absent_on_exit_2(tmp_path: Path) -> None:
    path = build_mcpb(tmp_path / "bad.mcpb", [("manifest.json", b"{")])
    output = tmp_path / "manifest-output.json"
    result = runner.invoke(app, ["mcpb", "scan", str(path), "--manifest-output", str(output)])
    assert result.exit_code == 2
    assert not output.exists()


def test_conflicting_output_paths_fail_before_scanning(tmp_path: Path) -> None:
    path = bundle(tmp_path / "safe.mcpb")
    output = tmp_path / "same.json"
    result = runner.invoke(
        app, ["mcpb", "scan", str(path), "--output", str(output), "--manifest-output", str(output)]
    )
    assert result.exit_code == 2
    assert not output.exists()


def test_invalid_format_and_missing_path_are_typer_errors(tmp_path: Path) -> None:
    path = bundle(tmp_path / "safe.mcpb")
    result = runner.invoke(app, ["mcpb", "scan", str(path), "--format", "sarif"])
    assert result.exit_code == 2
    missing = runner.invoke(app, ["mcpb", "scan"])
    assert missing.exit_code == 2
