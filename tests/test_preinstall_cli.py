from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest
from conftest import ROOT, runner

from skillgate.cli import app
from skillgate.demo import build_demo_mcpb
from skillgate.mcp_app_assets import inventory_local_mcp_app_assets

SKILLS_FIXTURES = ROOT / "fixtures" / "skills-validation"
COVERAGE_FIXTURES = ROOT / "fixtures" / "preinstall-review"


def test_preinstall_local_review_validates_discovered_skills() -> None:
    result = runner.invoke(
        app,
        [
            "review",
            "preinstall",
            str(SKILLS_FIXTURES / "valid-complex"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["source"]["kind"] == "local"
    assert payload["skills"]["validated"] is True
    assert payload["skills"]["summary"]["skills"] == 1
    assert payload["reviewer"]["no_execution"] is True


def test_preinstall_fail_on_includes_skill_findings_and_writes_sidecar(tmp_path) -> None:
    json_output = tmp_path / "packets" / "nested" / "review.json"
    result = runner.invoke(
        app,
        [
            "review",
            "preinstall",
            str(SKILLS_FIXTURES / "missing-required"),
            "--fail-on",
            "high",
            "--json-output",
            str(json_output),
        ],
    )
    assert result.exit_code == 1
    assert "Review threshold failed" in result.output
    assert json.loads(json_output.read_text(encoding="utf-8"))["findings"]["total"] >= 1


@pytest.mark.parametrize("outputs", ["markdown", "json", "both"])
def test_preinstall_creates_missing_output_directories(tmp_path: Path, outputs: str) -> None:
    markdown = tmp_path / "summaries" / "nested" / "review.md"
    sidecar = tmp_path / "packets" / "nested" / "review.json"
    args = ["review", "preinstall", str(COVERAGE_FIXTURES / "clean")]
    if outputs in {"markdown", "both"}:
        args.extend(["--output", str(markdown)])
    if outputs in {"json", "both"}:
        args.extend(["--json-output", str(sidecar)])
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    if outputs in {"markdown", "both"}:
        assert "SkillGate" in markdown.read_text()
    if outputs in {"json", "both"}:
        assert json.loads(sidecar.read_text())["metadata"]["coverage"]["status"] == "complete"


def test_preinstall_mcpb_review_uses_bundle_metadata(tmp_path) -> None:
    bundle = tmp_path / "reviewable.mcpb"
    build_demo_mcpb(bundle)
    result = runner.invoke(app, ["review", "preinstall", str(bundle), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["source"]["kind"] == "mcpb"
    assert payload["source"]["digest"]
    assert payload["source"]["metadata"]["manifest"]["entry_point"] == "server/index.js"


def test_preinstall_invalid_source_exits_two() -> None:
    result = runner.invoke(app, ["review", "preinstall", "missing-source"])
    assert result.exit_code == 2
    assert "source does not exist" in result.output


def test_preinstall_accepts_a_non_skill_local_file(tmp_path) -> None:
    source = tmp_path / "instructions.md"
    source.write_text("Review this text without executing it.\n", encoding="utf-8")
    result = runner.invoke(app, ["review", "preinstall", str(source), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["source"]["kind"] == "local"
    assert payload["skills"]["validated"] is False


def test_preinstall_schema_command_and_scanner_no_execution_boundary(tmp_path) -> None:
    schema_result = runner.invoke(app, ["review", "schema"])
    assert schema_result.exit_code == 0
    schema = json.loads(schema_result.output)
    assert schema["properties"]["schema_version"] == {"const": "2"}

    source = tmp_path / "skill"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    (source / "SKILL.md").write_text("Read `scripts/trap.py` for review.\n", encoding="utf-8")
    (scripts / "trap.py").write_text(
        'raise RuntimeError("scanned content must never execute")\n', encoding="utf-8"
    )

    result = runner.invoke(app, ["review", "preinstall", str(source), "--format", "json"])

    assert result.exit_code == 0
    assert json.loads(result.output)["reviewer"]["no_execution"] is True


@pytest.mark.parametrize(
    ("fixture", "status", "scanned", "skipped"),
    [
        ("clean", "complete", 1, 0),
        ("unsupported", "unsupported", 0, 1),
        ("partial", "incomplete", 1, 1),
    ],
)
def test_preinstall_distinguishes_zero_findings_from_missing_coverage(
    fixture: str, status: str, scanned: int, skipped: int
) -> None:
    source = COVERAGE_FIXTURES / fixture
    advisory = runner.invoke(app, ["review", "preinstall", str(source), "--format", "json"])
    assert advisory.exit_code == 0, advisory.output
    payload = json.loads(advisory.output)
    assert payload["findings"]["total"] == 0
    assert payload["metadata"]["coverage"]["status"] == status
    assert payload["source_manifest"]["scanned_file_count"] == scanned
    assert payload["source_manifest"]["skipped_file_count"] == skipped
    assert payload["reviewer"]["decision"] == (
        "no_findings" if status == "complete" else "review_required"
    )

    gate = runner.invoke(
        app, ["review", "preinstall", str(source), "--require-complete", "--format", "json"]
    )
    assert gate.exit_code == (0 if status == "complete" else 1), gate.output
    assert json.loads(gate.output) == payload


def test_preinstall_empty_coverage_remains_advisory_but_can_fail_ci(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["review", "preinstall", str(tmp_path), "--fail-on", "high", "--format", "json"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["metadata"]["coverage"]["status"] == "empty"
    assert payload["metadata"]["coverage"]["reasons"] == ["no_scannable_files"]
    assert payload["reviewer"]["decision"] == "review_required"
    assert not any(
        "continue with normal" in action for action in payload["reviewer"]["next_actions"]
    )

    source = tmp_path / "empty"
    source.mkdir()
    output = tmp_path / "review.md"
    json_output = tmp_path / "review.json"
    gate = runner.invoke(
        app,
        [
            "review",
            "preinstall",
            str(source),
            "--require-complete",
            "--fail-on",
            "high",
            "--output",
            str(output),
            "--json-output",
            str(json_output),
        ],
    )
    assert gate.exit_code == 1
    markdown = output.read_text(encoding="utf-8")
    assert "Review coverage failed" in markdown
    assert "Review threshold failed" not in markdown
    assert "| 0 | 0 | 0 | 0 | 0 | 0 |" in markdown
    assert json.loads(json_output.read_text())["metadata"]["coverage"]["status"] == "empty"


@pytest.mark.parametrize("filename", ["plugin.json", "opaque.bin", "skill.zip"])
def test_preinstall_explicit_unsupported_files_are_not_complete(
    filename: str, tmp_path: Path
) -> None:
    source = tmp_path / filename
    source.write_bytes(b"unsupported content\x00")
    result = runner.invoke(
        app, ["review", "preinstall", str(source), "--require-complete", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["metadata"]["coverage"]["status"] == "unsupported"


def test_preinstall_complete_coverage_does_not_hide_high_findings() -> None:
    source = ROOT / "fixtures" / "benchmark" / "05-remote-download-execute" / "SKILL.md"
    coverage_only = runner.invoke(
        app, ["review", "preinstall", str(source), "--require-complete", "--format", "json"]
    )
    assert coverage_only.exit_code == 0, coverage_only.output
    payload = json.loads(coverage_only.output)
    assert payload["metadata"]["coverage"]["status"] == "complete"
    assert payload["reviewer"]["decision"] == "review_required"
    assert payload["findings"]["by_severity"]["high"] > 0
    severity_gate = runner.invoke(
        app,
        [
            "review",
            "preinstall",
            str(source),
            "--require-complete",
            "--fail-on",
            "high",
            "--format",
            "json",
        ],
    )
    assert severity_gate.exit_code == 1
    assert json.loads(severity_gate.output) == payload


def test_preinstall_local_skips_are_deterministic_and_redacted() -> None:
    source = COVERAGE_FIXTURES / "partial"
    args = ["review", "preinstall", str(source), "--format", "json"]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)
    assert first.exit_code == second.exit_code == 0
    assert first.output == second.output
    assert str(ROOT) not in first.output
    assert json.loads(first.output)["source_manifest"]["skipped_files"] == [
        {"path": "helper.rb", "reason": "not_selected"}
    ]


def test_preinstall_standard_exclusions_define_the_review_scope(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("Describe changes clearly.\n")
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "trap.py").write_text('raise RuntimeError("must not execute")\n')
    result = runner.invoke(
        app, ["review", "preinstall", str(tmp_path), "--require-complete", "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["metadata"]["coverage"]["status"] == "complete"
    assert "standard discovery exclusions" in payload["metadata"]["coverage"]["scope"]
    assert payload["source_manifest"]["scanned_file_count"] == 1


def test_preinstall_symlink_directory_is_not_followed_or_complete(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "AGENTS.md").write_text("Describe changes clearly.\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "trap.py").write_text('raise RuntimeError("must not execute")\n')
    (source / "linked").symlink_to(outside, target_is_directory=True)
    result = runner.invoke(
        app, ["review", "preinstall", str(source), "--require-complete", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["metadata"]["coverage"]["status"] == "incomplete"
    assert payload["source_manifest"]["skipped_files"] == [
        {"path": "linked", "reason": "symlink_directory"}
    ]
    assert "trap.py" not in result.output


@pytest.mark.parametrize(
    ("filename", "content", "reason"),
    [
        ("server/tool.exe", b"MZ\x00", "embedded executable requires review"),
        ("nested.zip", b"PK\x03\x04", "nested archive retained but not recursively inspected"),
    ],
)
def test_preinstall_mcpb_uninspected_members_are_counted(
    tmp_path: Path, filename: str, content: bytes, reason: str
) -> None:
    source = tmp_path / "reviewable.mcpb"
    build_demo_mcpb(source)
    with zipfile.ZipFile(source, "a") as archive:
        archive.writestr(filename, content)
    result = runner.invoke(
        app, ["review", "preinstall", str(source), "--require-complete", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["metadata"]["coverage"]["status"] == "incomplete"
    skipped = payload["source_manifest"]["skipped_files"]
    assert {"path": filename, "reason": reason} in skipped
    assert not any(item["path"] == "manifest.json" for item in skipped)


def test_preinstall_mcp_app_missing_asset_fails_coverage_without_findings(tmp_path: Path) -> None:
    (tmp_path / "server.json").write_text(
        json.dumps(
            {
                "name": "io.example.app",
                "_meta": {
                    "ui": {
                        "resourceUri": "ui://app/index.html",
                        "mimeType": "text/html;profile=mcp-app",
                    }
                },
            }
        )
    )
    result = runner.invoke(
        app, ["review", "preinstall", str(tmp_path), "--require-complete", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["findings"]["total"] == 0
    assert payload["metadata"]["coverage"]["status"] == "incomplete"
    assert "missing_reference" in payload["metadata"]["coverage"]["reasons"]


def test_preinstall_asset_count_limit_is_a_gap_even_without_a_skipped_asset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"_meta": {"ui": {"resourceUri": "ui://app/index.html"}}})
    )
    monkeypatch.setattr(
        "skillgate.scan.inventory_local_mcp_app_assets",
        lambda root, paths: inventory_local_mcp_app_assets(root, paths, max_assets=0),
    )
    result = runner.invoke(
        app, ["review", "preinstall", str(tmp_path), "--require-complete", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["metadata"]["mcp_apps"]["assets"] == []
    assert "asset_count_limit_exceeded" in payload["metadata"]["coverage"]["reasons"]


@pytest.mark.parametrize("entry_point", ["server/index.js", "node_modules/index.js"])
def test_preinstall_mcpb_declared_startup_must_be_scanned_for_complete_coverage(
    tmp_path: Path, entry_point: str
) -> None:
    source = tmp_path / "startup.mcpb"
    manifest = {
        "name": "startup-test",
        "version": "1.0.0",
        "manifest_version": "0.1.0",
        "server": {
            "type": "node",
            "entry_point": entry_point,
            "mcp_config": {"command": "node", "args": ["${__dirname}/" + entry_point]},
        },
    }
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("package.json", '{"name":"startup-test","version":"1.0.0"}')
        archive.writestr(entry_point, "console.log('ok')\n")
    result = runner.invoke(
        app, ["review", "preinstall", str(source), "--require-complete", "--format", "json"]
    )
    excluded = entry_point.startswith("node_modules/")
    assert result.exit_code == (1 if excluded else 0), result.output
    payload = json.loads(result.output)
    assert payload["metadata"]["coverage"]["status"] == ("incomplete" if excluded else "complete")
    if excluded:
        assert "unscanned_entry_point" in payload["metadata"]["coverage"]["reasons"]
    assert not any(
        item["path"] == "manifest.json" for item in payload["source_manifest"]["skipped_files"]
    )


def test_preinstall_directory_enumeration_error_cannot_report_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "AGENTS.md").write_text("Describe changes clearly.\n")
    unreadable = tmp_path / "unreadable"
    unreadable.mkdir()
    scandir = os.scandir

    def deny_directory(path):
        if Path(path) == unreadable:
            raise PermissionError("directory cannot be inspected")
        return scandir(path)

    monkeypatch.setattr(os, "scandir", deny_directory)
    result = runner.invoke(app, ["review", "preinstall", str(tmp_path), "--format", "json"])
    assert result.exit_code == 2, result.output
    assert "directory cannot be inspected" in result.output
