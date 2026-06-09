from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillgate.baseline import create_baseline, diff_against_baseline
from skillgate.cli import app
from skillgate.discovery import discover_paths, scan_file_metadata
from skillgate.models import stable_json
from skillgate.policy import evaluate_policy, load_policy
from skillgate.sarif import sarif_report
from skillgate.scan import scan_repository

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "benchmark"
TEST_OUTPUTS = ROOT / "test-outputs"
runner = CliRunner()


def rule_ids(path: str) -> set[str]:
    return {finding.rule_id for finding in scan_repository(FIXTURES / path).findings}


def test_recursive_discovery_includes_referenced_script() -> None:
    paths = [
        path.relative_to(FIXTURES / "02-shell-execution").as_posix()
        for path in discover_paths(FIXTURES / "02-shell-execution")
    ]
    assert paths == ["SKILL.md", "scripts/build.sh"]


def clean_test_dir(name: str) -> Path:
    path = TEST_OUTPUTS / name
    if path.exists():
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
        path.rmdir()
    path.mkdir(parents=True)
    return path


def test_excluded_directories_are_skipped() -> None:
    workdir = clean_test_dir("excluded-directories")
    (workdir / "SKILL.md").write_text("Safe", encoding="utf-8")
    excluded = workdir / "node_modules" / "package" / "SKILL.md"
    excluded.parent.mkdir(parents=True)
    excluded.write_text("bash setup.sh", encoding="utf-8")
    paths = [path.relative_to(workdir).as_posix() for path in discover_paths(workdir)]
    assert paths == ["SKILL.md"]


def test_stable_file_hashing() -> None:
    path = FIXTURES / "01-safe-documentation-skill" / "SKILL.md"
    first = scan_file_metadata(FIXTURES / "01-safe-documentation-skill", path)
    second = scan_file_metadata(FIXTURES / "01-safe-documentation-skill", path)
    assert first.sha256 == second.sha256
    assert len(first.sha256) == 64


@pytest.mark.parametrize(
    ("fixture", "rule_id"),
    [
        ("02-shell-execution", "SG001"),
        ("03-destructive-command", "SG002"),
        ("04-network-egress", "SG003"),
        ("05-remote-download-execute", "SG004"),
        ("06-secret-access", "SG005"),
        ("07-filesystem-write", "SG006"),
        ("08-prompt-override", "SG007"),
        ("09-unicode-obfuscation", "SG008"),
        ("10-mcp-config", "SG009"),
    ],
)
def test_required_rules(fixture: str, rule_id: str) -> None:
    assert rule_id in rule_ids(fixture)


def test_secret_values_are_not_reported() -> None:
    report = scan_repository(FIXTURES / "06-secret-access")
    rendered = stable_json(report)
    assert "GITHUB_TOKEN" in rendered
    assert "token[:4]" not in rendered


def test_mcp_config_parses_metadata() -> None:
    report = scan_repository(FIXTURES / "10-mcp-config")
    mcp = [capability for capability in report.capabilities if capability.type == "mcp_server"][0]
    assert mcp.resource == "github"
    assert mcp.details["command"] == "node"
    assert "GITHUB_TOKEN" in mcp.details["env"]


def test_policy_blocks_remote_download_execute() -> None:
    report = scan_repository(FIXTURES / "05-remote-download-execute")
    result = evaluate_policy(report, load_policy(ROOT / "skillgate.example.yaml"))
    assert result.blocked
    assert any("Shell execution is not allowed" in item.message for item in result.violations)


def test_lockfile_generation_is_stable_json() -> None:
    lock = create_baseline(FIXTURES / "11-mcp-capability-drift-before")
    data = json.loads(stable_json(lock))
    assert data["schema_version"] == "1"
    assert data["files"][0]["path"] == ".mcp.json"


def test_capability_diff_reports_mcp_change() -> None:
    baseline = create_baseline(FIXTURES / "11-mcp-capability-drift-before")
    diff, _report = diff_against_baseline(FIXTURES / "12-mcp-capability-drift-after", baseline)
    assert any(finding.rule_id == "SG010" for finding in diff.findings)
    assert "before=" in diff.findings[0].evidence
    assert "after=" in diff.findings[0].evidence


def test_json_report_is_machine_readable_and_stable() -> None:
    report = scan_repository(FIXTURES / "02-shell-execution")
    first = stable_json(report)
    second = stable_json(report)
    assert first == second
    assert json.loads(first)["findings"][0]["rule_id"] == "SG001"


def test_sarif_structure() -> None:
    report = scan_repository(FIXTURES / "05-remote-download-execute")
    sarif = sarif_report(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "SkillGate"
    assert sarif["runs"][0]["results"][0]["ruleId"]


def test_cli_scan_exit_code_and_output() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "02-shell-execution")])
    assert result.exit_code == 0
    assert "SG001" in result.output


def test_cli_check_blocks() -> None:
    result = runner.invoke(
        app,
        [
            "check",
            str(FIXTURES / "05-remote-download-execute"),
            "--policy",
            str(ROOT / "skillgate.example.yaml"),
        ],
    )
    assert result.exit_code == 1
    assert "BLOCKED" in result.output


def test_cli_baseline_and_diff() -> None:
    workdir = clean_test_dir("baseline-diff")
    lock = workdir / "skillgate.lock"
    create = runner.invoke(
        app,
        [
            "baseline",
            "create",
            str(FIXTURES / "11-mcp-capability-drift-before"),
            "--output",
            str(lock),
        ],
    )
    assert create.exit_code == 0
    diff = runner.invoke(
        app,
        [
            "diff",
            str(FIXTURES / "12-mcp-capability-drift-after"),
            "--baseline",
            str(lock),
        ],
    )
    assert diff.exit_code == 0
    assert "SG010" in diff.output
