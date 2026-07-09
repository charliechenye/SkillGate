from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

from conftest import runner

from skillgate.cli import app
from skillgate.demo import DEMO_MCPB_SHA256

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
    assert runner.invoke(app, ["demo", "--help"]).exit_code == 0
    assert runner.invoke(app, ["demo", "mcpb", "--help"]).exit_code == 0
    assert runner.invoke(app, ["demo", "skill", "--help"]).exit_code == 0
    result = runner.invoke(app, ["mcpb", "scan", "--help"])
    assert result.exit_code == 0
    assert "MCPB bundle to inspect" in result.output


def test_demo_mcpb_builds_deterministic_bundle(tmp_path: Path) -> None:
    output = tmp_path / "reviewable-node.mcpb"
    result = runner.invoke(app, ["demo", "mcpb", "--output", str(output)])
    assert result.exit_code == 0
    assert output.exists()
    assert f"SHA-256: {DEMO_MCPB_SHA256}" in result.output
    assert f"Next: skillgate mcpb scan {output}" in result.output
    assert result.output.startswith("Built deterministic demo MCPB:")


def test_demo_mcpb_protects_existing_output_unless_forced(tmp_path: Path) -> None:
    output = tmp_path / "reviewable-node.mcpb"
    output.write_bytes(b"keep me")

    blocked = runner.invoke(app, ["demo", "mcpb", "--output", str(output)])
    assert blocked.exit_code == 2
    assert "output file already exists" in blocked.output
    assert output.read_bytes() == b"keep me"

    forced = runner.invoke(app, ["demo", "mcpb", "--output", str(output), "--force"])
    assert forced.exit_code == 0
    assert f"SHA-256: {DEMO_MCPB_SHA256}" in forced.output


def test_demo_mcpb_scan_prints_normal_scan_output(tmp_path: Path) -> None:
    output = tmp_path / "reviewable-node.mcpb"
    result = runner.invoke(app, ["demo", "mcpb", "--output", str(output), "--scan"])
    assert result.exit_code == 0
    assert f"SHA-256: {DEMO_MCPB_SHA256}" in result.output
    assert "SkillGate MCPB scan completed" in result.output
    assert "Entry point: server/index.js" in result.output
    assert "Endpoint: https://api.example.invalid/v1" in result.output
    assert "Secret reference: SERVICE_TOKEN" in result.output


def test_demo_skill_builds_and_runs_both_review_views(tmp_path: Path) -> None:
    output = tmp_path / "reviewable-demo"
    result = runner.invoke(
        app,
        [
            "demo",
            "skill",
            "--output",
            str(output),
            "--validate",
            "--scan",
        ],
    )
    assert result.exit_code == 0
    assert (output / "SKILL.md").exists()
    assert (output / "scripts" / "bootstrap.sh").exists()
    assert "SkillGate skills validation completed" in result.output
    assert "SKILL007" in result.output
    assert "SG004" in result.output


def test_demo_skill_protects_existing_directory_unless_forced(tmp_path: Path) -> None:
    output = tmp_path / "reviewable-demo"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("keep me", encoding="utf-8")

    blocked = runner.invoke(app, ["demo", "skill", "--output", str(output)])
    assert blocked.exit_code == 2
    assert "output directory already exists" in blocked.output
    assert marker.read_text(encoding="utf-8") == "keep me"

    forced = runner.invoke(app, ["demo", "skill", "--output", str(output), "--force"])
    assert forced.exit_code == 0
    assert marker.read_text(encoding="utf-8") == "keep me"
    assert (output / "SKILL.md").exists()


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


def test_sarif_scan_uses_mcp_bundle_category(tmp_path: Path) -> None:
    path = bundle(tmp_path / "safe.mcpb")
    result = runner.invoke(app, ["mcpb", "scan", str(path), "--format", "sarif"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["automationDetails"]["id"] == "skillgate/mcp-bundle"
    assert data["runs"][0]["results"] == []
    assert str(path) not in result.output


def test_sarif_scan_includes_mcpb_rule_metadata_and_fail_on(tmp_path: Path) -> None:
    data = manifest(
        server={
            "type": "node",
            "entry_point": "server/missing.js",
            "mcp_config": {"command": "node", "args": ["${__dirname}/server/missing.js"]},
        }
    )
    path = build_mcpb(
        tmp_path / "review.mcpb",
        [
            ("manifest.json", json.dumps(data, sort_keys=True).encode()),
            ("deps/pkg.whl", b"PK\x03\x04nested"),
        ],
    )
    result = runner.invoke(
        app,
        ["mcpb", "scan", str(path), "--format", "sarif", "--fail-on", "high"],
    )
    assert result.exit_code == 1
    sarif = json.loads(result.output)
    rules = {rule["id"]: rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert {"SG014", "SG015"} <= set(rules)
    assert "capability:mcpb_startup" in rules["SG014"]["properties"]["tags"]
    assert "capability:mcpb_embedded_artifact" in rules["SG015"]["properties"]["tags"]
    result_ids = {item["ruleId"] for item in sarif["runs"][0]["results"]}
    assert {"SG014", "SG015"} <= result_ids


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
    result = runner.invoke(app, ["mcpb", "scan", str(path), "--format", "xml"])
    assert result.exit_code == 2
    missing = runner.invoke(app, ["mcpb", "scan"])
    assert missing.exit_code == 2


def test_malformed_runtime_url_json_error_envelope(tmp_path: Path) -> None:
    data = manifest(
        server={
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {"command": "node", "args": ["https://example.com:not-a-port/api"]},
        }
    )
    path = bundle(tmp_path / "bad-url.mcpb", data)
    result = runner.invoke(app, ["mcpb", "scan", str(path), "--format", "json"])
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload == {
        "error": {
            "code": "mcpb_manifest_invalid_shape",
            "field_path": "server.mcp_config.args[0]",
            "manifest_path": "manifest.json",
            "message": "MCPB manifest has an invalid shape",
        }
    }
    assert "not-a-port" not in result.output
    assert str(path) not in result.output
