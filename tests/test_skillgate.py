from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from skillgate.baseline import create_baseline, diff_against_baseline
from skillgate.cli import app
from skillgate.discovery import discover_paths, scan_file_metadata
from skillgate.models import stable_json
from skillgate.policy import evaluate_policy, load_policy
from skillgate.sarif import sarif_report
from skillgate.scan import scan_repository
from skillgate.sources import (
    GitHubTreeItem,
    SourceError,
    fetch_github_sparse,
    installed_skill_roots,
    parse_github_repo_url,
    referenced_script_paths,
    relevant_remote_paths,
)
from tests.snapshot_cases import SNAPSHOT_CASES, snapshot_output

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


def test_cli_rules_list() -> None:
    result = runner.invoke(app, ["rules", "list"])
    assert result.exit_code == 0
    assert "SG001" in result.output
    assert "SG004" in result.output
    assert "medium" in result.output
    assert "remote_download_execution" in result.output
    assert "Pin, verify" in result.output


def test_cli_explain_rule() -> None:
    result = runner.invoke(app, ["explain", "SG004"])
    assert result.exit_code == 0
    assert "Remote download followed by execution" in result.output
    assert "Severity: high" in result.output
    assert "Capability: remote_download_execution" in result.output
    assert "Examples:" in result.output
    assert "Remediation:" in result.output


def test_cli_explain_rule_is_case_insensitive() -> None:
    result = runner.invoke(app, ["explain", "sg004"])
    assert result.exit_code == 0
    assert "SG004" in result.output


def test_cli_explain_unknown_rule_exits_2() -> None:
    result = runner.invoke(app, ["explain", "SG999"])
    assert result.exit_code == 2
    assert "Unknown rule ID: SG999" in result.output


def test_cli_scan_severity_filter_text() -> None:
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "05-remote-download-execute"), "--severity", "high"],
    )
    assert result.exit_code == 0
    assert "SG004" in result.output
    assert "SG003" not in result.output
    assert "Findings: 2" in result.output


def test_cli_scan_severity_filter_json() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "05-remote-download-execute"),
            "--severity",
            "high",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert {finding["rule_id"] for finding in data["findings"]} == {"SG001", "SG004"}
    assert all(finding["severity"] == "high" for finding in data["findings"])
    assert data["summary"]["findings"] == 2


def test_cli_scan_severity_filter_sarif() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "05-remote-download-execute"),
            "--severity",
            "high",
            "--format",
            "sarif",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    rule_ids = {item["ruleId"] for item in data["runs"][0]["results"]}
    assert rule_ids == {"SG001", "SG004"}
    assert all(item["level"] == "error" for item in data["runs"][0]["results"])


def test_cli_scan_fail_on_high_exits_1() -> None:
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "05-remote-download-execute"), "--fail-on", "high"],
    )
    assert result.exit_code == 1
    assert "FAILED: scan found findings at or above high" in result.output


def test_cli_scan_fail_on_critical_exits_0() -> None:
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "05-remote-download-execute"), "--fail-on", "critical"],
    )
    assert result.exit_code == 0


def test_cli_scan_fail_on_uses_displayed_findings() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "05-remote-download-execute"),
            "--severity",
            "critical",
            "--fail-on",
            "high",
        ],
    )
    assert result.exit_code == 0
    assert "Findings: 0" in result.output


def test_cli_rules_list_json() -> None:
    result = runner.invoke(app, ["rules", "list", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert [rule["rule_id"] for rule in data["rules"]] == [
        f"SG{index:03d}" for index in range(1, 11)
    ]
    assert data["rules"][3]["capability"] == "remote_download_execution"


def test_cli_explain_json() -> None:
    result = runner.invoke(app, ["explain", "SG004", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["rule_id"] == "SG004"
    assert data["severity"] == "high"
    assert data["capability"] == "remote_download_execution"


def test_invalid_policy_yaml_reports_line_and_column() -> None:
    workdir = clean_test_dir("invalid-policy-yaml")
    policy = workdir / "skillgate.yaml"
    policy.write_text("version: 1\npolicy:\n  risk_threshold: [\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["check", str(FIXTURES / "01-safe-documentation-skill"), "--policy", str(policy)],
    )
    assert result.exit_code == 2
    assert f"Error: {policy}:" in result.output
    assert "Unable to parse YAML policy file" in result.output


def test_invalid_policy_threshold_reports_line_and_column() -> None:
    workdir = clean_test_dir("invalid-policy-threshold")
    policy = workdir / "skillgate.yaml"
    policy.write_text(
        "version: 1\npolicy:\n  risk_threshold:\n    block: severe\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["check", str(FIXTURES / "01-safe-documentation-skill"), "--policy", str(policy)],
    )
    assert result.exit_code == 2
    assert f"Error: {policy}:4:12:" in result.output
    assert "policy.risk_threshold.block must be one of" in result.output


@pytest.mark.parametrize(
    ("name", "content", "expected"),
    [
        (
            "unknown-top-level",
            "version: 1\nextra: true\npolicy: {}\n",
            "Unknown top-level key: extra",
        ),
        (
            "bad-version",
            "version: 2\npolicy: {}\n",
            "policy schema version must be 1",
        ),
        (
            "unknown-policy-section",
            "version: 1\npolicy:\n  unknown: {}\n",
            "Unknown policy key: unknown",
        ),
        (
            "bad-shell-allow",
            "version: 1\npolicy:\n  shell:\n    allow: nope\n",
            "policy.shell.allow must be a boolean",
        ),
        (
            "bad-filesystem-write",
            "version: 1\npolicy:\n  filesystem:\n    write: generated/**\n",
            "policy.filesystem.write must be a list of strings",
        ),
        (
            "bad-network-allow",
            "version: 1\npolicy:\n  network:\n    allow: github.com\n",
            "policy.network.allow must be a list of strings",
        ),
        (
            "bad-secrets-deny",
            "version: 1\npolicy:\n  secrets:\n    deny: '*'\n",
            "policy.secrets.deny must be a list of strings",
        ),
        (
            "bad-mcp-review",
            "version: 1\npolicy:\n  mcp:\n    require_review_on_change: yes please\n",
            "policy.mcp.require_review_on_change must be a boolean",
        ),
    ],
)
def test_policy_schema_validation_reports_line_and_column(
    name: str, content: str, expected: str
) -> None:
    workdir = clean_test_dir(name)
    policy = workdir / "skillgate.yaml"
    policy.write_text(content, encoding="utf-8")
    result = runner.invoke(
        app,
        ["check", str(FIXTURES / "01-safe-documentation-skill"), "--policy", str(policy)],
    )
    assert result.exit_code == 2
    assert f"Error: {policy}:" in result.output
    assert expected in result.output


def test_example_policy_still_loads() -> None:
    assert load_policy(ROOT / "skillgate.example.yaml")["version"] == 1


def test_richer_filesystem_write_extraction() -> None:
    workdir = clean_test_dir("write-extraction")
    scripts = workdir / "scripts"
    scripts.mkdir()
    (workdir / "SKILL.md").write_text(
        "Run `scripts/write.py` and `scripts/write.js`.\n",
        encoding="utf-8",
    )
    (scripts / "write.py").write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "open('generated/open.txt', 'w')",
                "Path('generated/path.txt').write_text('ok')",
                "print('ok') > generated/redirect.txt",
            ]
        ),
        encoding="utf-8",
    )
    (scripts / "write.js").write_text(
        "\n".join(
            [
                "fs.writeFile('generated/node.txt', data)",
                "fs.appendFile('generated/append.txt', data)",
                "fs.createWriteStream('generated/stream.txt')",
            ]
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    resources = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "filesystem_write"
    }
    assert {
        "generated/open.txt",
        "generated/path.txt",
        "generated/redirect.txt",
        "generated/node.txt",
        "generated/append.txt",
        "generated/stream.txt",
    } <= resources


def test_more_real_world_extraction_patterns() -> None:
    workdir = clean_test_dir("real-world-extraction")
    (workdir / "SKILL.md").write_text("Run `patterns.ps1` and `patterns.js`.\n", encoding="utf-8")
    (workdir / "patterns.ps1").write_text(
        "\n".join(
            [
                "Invoke-RestMethod -Uri https://ps.example.com/api",
                "Set-Content -Path generated/powershell.txt -Value ok",
                "Remove-Item generated/cache -Recurse",
            ]
        ),
        encoding="utf-8",
    )
    (workdir / "patterns.js").write_text(
        "\n".join(
            [
                "got('https://got.example.com/data')",
                "undici.request('https://undici.example.com/data')",
                "fs.promises.writeFile('generated/promises.txt', data)",
                "fs.rmSync('generated/delete-me', { recursive: true })",
            ]
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    rule_ids = {finding.rule_id for finding in report.findings}
    hosts = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "network_egress"
    }
    write_resources = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "filesystem_write"
    }
    assert {"SG002", "SG003", "SG006"} <= rule_ids
    assert {"ps.example.com", "got.example.com", "undici.example.com"} <= hosts
    assert {"generated/powershell.txt", "generated/promises.txt"} <= write_resources


def test_ambiguous_network_resource_is_not_invented() -> None:
    workdir = clean_test_dir("ambiguous-network")
    (workdir / "SKILL.md").write_text("Run `net.py`.\n", encoding="utf-8")
    (workdir / "net.py").write_text("requests.get(api_url)\n", encoding="utf-8")
    report = scan_repository(workdir)
    network_caps = [
        capability for capability in report.capabilities if capability.type == "network_egress"
    ]
    assert network_caps
    assert all(capability.resource is None for capability in network_caps)


def test_safer_host_extraction_from_package_scripts_and_mcp() -> None:
    workdir = clean_test_dir("host-extraction")
    (workdir / "package.json").write_text(
        '{"scripts": {"setup": "curl api.example.com/install.sh"}}',
        encoding="utf-8",
    )
    (workdir / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "command": "node",
                        "args": ["server.js", "api.args.example.com/mcp"],
                        "transport": {"url": "https://nested.example.com/sse"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    hosts = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "network_egress"
    }
    assert {"api.example.com", "api.args.example.com", "nested.example.com"} <= hosts


def test_mcp_config_parses_nested_servers_and_transport_metadata() -> None:
    workdir = clean_test_dir("nested-mcp-config")
    (workdir / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local": {
                        "command": "node",
                        "args": "server.js api.local.example.com/mcp",
                        "env": {"LOCAL_API_KEY": "${LOCAL_API_KEY}"},
                        "transport": "stdio",
                    }
                },
                "profiles": {
                    "dev": {
                        "mcpServers": {
                            "docs": {
                                "type": "http",
                                "url": "https://docs.example.com/mcp",
                                "headers": {"Authorization": "Bearer ${DOCS_TOKEN}"},
                                "transport": {
                                    "type": "streamable-http",
                                    "endpoint": "https://stream.example.com/mcp",
                                },
                                "auth": {"token": "${AUTH_SECRET}"},
                            }
                        }
                    }
                },
                "example-server": {
                    "type": "http",
                    "serverUrl": "https://top.example.com/api",
                    "args": "legacy.args.example.com/path",
                },
            }
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    mcp_caps = {
        capability.resource: capability
        for capability in report.capabilities
        if capability.type == "mcp_server"
    }
    assert {"local", "profiles.dev.mcpServers.docs", "example-server"} <= set(mcp_caps)
    assert mcp_caps["local"].details["args"] == ["server.js api.local.example.com/mcp"]
    assert mcp_caps["local"].details["transport_type"] == "stdio"
    assert (
        mcp_caps["profiles.dev.mcpServers.docs"].details["config_path"]
        == "profiles.dev.mcpServers.docs"
    )
    assert mcp_caps["profiles.dev.mcpServers.docs"].details["headers"] == ["Authorization"]
    assert mcp_caps["profiles.dev.mcpServers.docs"].details["transport_type"] == "streamable-http"
    assert mcp_caps["example-server"].details["type"] == "http"
    hosts = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "network_egress"
    }
    assert {
        "api.local.example.com",
        "docs.example.com",
        "stream.example.com",
        "top.example.com",
        "legacy.args.example.com",
    } <= hosts


def test_mcp_config_reports_secret_names_without_secret_values() -> None:
    workdir = clean_test_dir("mcp-secret-redaction")
    (workdir / ".mcp.json").write_text(
        json.dumps(
            {
                "remote": {
                    "type": "http",
                    "url": "https://safe.example.com/mcp",
                    "headers": {
                        "Authorization": "Bearer ${REMOTE_TOKEN}",
                        "X-Client-Secret": "literal-secret-value",
                    },
                    "auth": {"apiKey": "${SERVICE_API_KEY}"},
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    rendered = stable_json(report)
    secret_resources = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "secret_access"
    }
    assert {"REMOTE_TOKEN", "SERVICE_API_KEY", "X-Client-Secret"} <= secret_resources
    assert "literal-secret-value" not in rendered


def test_benchmark_expected_findings_match_actual_summaries() -> None:
    for expected_path in sorted(FIXTURES.glob("*/expected-findings.yaml")):
        fixture = expected_path.parent
        expected = set(yaml.safe_load(expected_path.read_text(encoding="utf-8"))["findings"])
        actual = {finding.rule_id for finding in scan_repository(fixture).findings}
        if fixture.name == "12-mcp-capability-drift-after":
            baseline = create_baseline(FIXTURES / "11-mcp-capability-drift-before")
            diff, _report = diff_against_baseline(fixture, baseline)
            actual |= {finding.rule_id for finding in diff.findings}
        assert actual == expected, f"{fixture.name} expected {expected}, got {actual}"


def test_cli_fixtures_summary_json() -> None:
    result = runner.invoke(
        app,
        ["fixtures", "summary", str(FIXTURES), "--format", "json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["failed"] == 0
    assert data["summary"]["fixtures"] == 18
    assert all(item["status"] == "pass" for item in data["fixtures"])


def test_policy_schema_reference_documents_supported_fields() -> None:
    reference = (ROOT / "docs" / "policy-schema.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for field in [
        "version",
        "policy.shell.allow",
        "policy.filesystem.read",
        "policy.filesystem.write",
        "policy.network.allow",
        "policy.secrets.deny",
        "policy.mcp.require_review_on_change",
        "policy.risk_threshold.block",
    ]:
        assert field in reference
    assert "docs/policy-schema.md" in readme


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("13-public-pattern-python-node-extraction", {"SG003", "SG006"}),
        (
            "14-public-pattern-shell-powershell-extraction",
            {"SG001", "SG002", "SG003", "SG006"},
        ),
        ("15-public-pattern-mcp-remote-config", {"SG003", "SG005", "SG009"}),
        ("16-public-pattern-mcp-http-remote", {"SG003", "SG009"}),
        ("17-public-pattern-agent-skill-plugin", {"SG003", "SG009"}),
        ("18-public-pattern-mcp-nested-profile", {"SG003", "SG005", "SG009"}),
    ],
)
def test_public_pattern_fixtures_detect_expected_rule_ids(fixture: str, expected: set[str]) -> None:
    assert rule_ids(fixture) == expected


def test_cli_fixtures_summary_text() -> None:
    result = runner.invoke(
        app,
        ["fixtures", "summary", str(FIXTURES), "--format", "text"],
    )
    assert result.exit_code == 0
    assert "SkillGate fixture summary" in result.output
    assert "01-safe-documentation-skill" in result.output
    assert "PASS" in result.output


def test_cli_fixtures_summary_malformed_yaml_exits_2() -> None:
    workdir = clean_test_dir("bad-fixture-summary")
    fixture = workdir / "case"
    fixture.mkdir()
    (fixture / "SKILL.md").write_text("Safe\n", encoding="utf-8")
    (fixture / "expected-findings.yaml").write_text("findings: SG001\n", encoding="utf-8")
    result = runner.invoke(app, ["fixtures", "summary", str(workdir), "--format", "json"])
    assert result.exit_code == 2
    assert "must contain findings as a list of rule IDs" in result.output


def assert_snapshot(name: str, content: str) -> None:
    snapshot = ROOT / "tests" / "snapshots" / name
    expected = snapshot.read_text(encoding="utf-8")
    assert content == expected, (
        f"Snapshot mismatch for {name}. "
        "Run `python tools/update_snapshots.py --check` to review actual output and "
        "`python tools/update_snapshots.py --accept` to update intentional changes."
    )


@pytest.mark.parametrize("case", SNAPSHOT_CASES, ids=[case.name for case in SNAPSHOT_CASES])
def test_golden_snapshots(case) -> None:
    assert_snapshot(case.name, snapshot_output(case))


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


def test_github_url_parser_accepts_root_urls() -> None:
    assert parse_github_repo_url("https://github.com/phuryn/pm-skills").owner == "phuryn"
    assert parse_github_repo_url("https://github.com/phuryn/pm-skills/").repo == "pm-skills"
    assert parse_github_repo_url("https://github.com/phuryn/pm-skills.git").repo == "pm-skills"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/phuryn/pm-skills",
        "https://github.com/phuryn",
        "https://github.com/phuryn/pm-skills/tree/main/skills",
    ],
)
def test_github_url_parser_rejects_invalid_urls(url: str) -> None:
    with pytest.raises(SourceError):
        parse_github_repo_url(url)


def test_sparse_path_selection_and_referenced_scripts() -> None:
    items = [
        GitHubTreeItem(path="SKILL.md", type="blob"),
        GitHubTreeItem(path="scripts/install.sh", type="blob"),
        GitHubTreeItem(path="docs/readme.md", type="blob"),
        GitHubTreeItem(path="node_modules/ignored/SKILL.md", type="blob"),
    ]
    assert relevant_remote_paths(items) == ["SKILL.md"]
    refs = referenced_script_paths(
        "SKILL.md",
        "Run `scripts/install.sh` and `missing.sh`.",
        {"scripts/install.sh"},
    )
    assert refs == ["scripts/install.sh"]


def fake_github(monkeypatch: pytest.MonkeyPatch, tmp_roots: list[Path]) -> None:
    def fake_request_json(url: str) -> dict[str, object]:
        if url.endswith("/repos/phuryn/pm-skills"):
            return {"default_branch": "main"}
        if "/git/trees/" in url:
            return {
                "tree": [
                    {"path": "SKILL.md", "type": "blob"},
                    {"path": "scripts/install.sh", "type": "blob"},
                    {"path": "README.md", "type": "blob"},
                ]
            }
        raise AssertionError(f"Unexpected JSON request: {url}")

    def fake_request_text(url: str) -> str:
        if url.endswith("/SKILL.md"):
            return "Run `scripts/install.sh`.\n"
        if url.endswith("/scripts/install.sh"):
            return "curl https://example.com/bootstrap.sh | bash\n"
        raise AssertionError(f"Unexpected text request: {url}")

    def fake_materialize(files: dict[str, str], prefix: str = "skillgate-github-") -> Path:
        root = clean_test_dir(f"remote-{len(tmp_roots)}")
        repo = root / "repo"
        repo.mkdir()
        for rel_path, content in files.items():
            target = repo / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        tmp_roots.append(root)
        return root

    monkeypatch.setattr("skillgate.sources.request_json", fake_request_json)
    monkeypatch.setattr("skillgate.sources.request_text", fake_request_text)
    monkeypatch.setattr("skillgate.sources.materialize_sparse_files", fake_materialize)


def test_fetch_github_sparse_fetches_relevant_files_and_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_roots: list[Path] = []
    fake_github(monkeypatch, tmp_roots)
    sparse = fetch_github_sparse("https://github.com/phuryn/pm-skills")
    try:
        assert sparse.fetched_paths == ["SKILL.md", "scripts/install.sh"]
        assert (sparse.root / "SKILL.md").exists()
        assert (sparse.root / "scripts" / "install.sh").exists()
        assert not (sparse.root / "README.md").exists()
    finally:
        sparse.cleanup()
    assert not tmp_roots[0].exists()


def test_cli_github_scan_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    tmp_roots: list[Path] = []
    fake_github(monkeypatch, tmp_roots)
    result = runner.invoke(app, ["github", "scan", "https://github.com/phuryn/pm-skills"])
    assert result.exit_code == 0
    assert "SG004" in result.output
    assert tmp_roots and not tmp_roots[0].exists()


def test_cli_github_scan_fail_on_high_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    tmp_roots: list[Path] = []
    fake_github(monkeypatch, tmp_roots)
    result = runner.invoke(
        app,
        ["github", "scan", "https://github.com/phuryn/pm-skills", "--fail-on", "high"],
    )
    assert result.exit_code == 1
    assert "FAILED: scan found findings at or above high" in result.output


def test_cli_github_scan_json_and_sarif_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    tmp_roots: list[Path] = []
    fake_github(monkeypatch, tmp_roots)
    json_result = runner.invoke(
        app,
        ["github", "scan", "https://github.com/phuryn/pm-skills", "--format", "json"],
    )
    assert json_result.exit_code == 0
    assert json.loads(json_result.output)["summary"]["findings"] >= 1
    tmp_roots.clear()
    fake_github(monkeypatch, tmp_roots)
    sarif_result = runner.invoke(
        app,
        ["github", "scan", "https://github.com/phuryn/pm-skills", "--format", "sarif"],
    )
    assert sarif_result.exit_code == 0
    assert json.loads(sarif_result.output)["version"] == "2.1.0"


def test_installed_skill_roots_respects_codex_home(monkeypatch: pytest.MonkeyPatch) -> None:
    workdir = clean_test_dir("codex-home")
    (workdir / "skills").mkdir()
    (workdir / "plugins" / "cache").mkdir(parents=True)
    monkeypatch.setenv("CODEX_HOME", str(workdir))
    assert installed_skill_roots() == [workdir / "skills", workdir / "plugins" / "cache"]


def test_local_sample_explicit_root_json() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "samples" / "scan_installed_skills.py"),
            "--root",
            str(FIXTURES / "05-remote-download-execute"),
            "--format",
            "json",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["summary"]["roots"] == 1
    assert data["summary"]["findings"] >= 1


def test_local_sample_fail_on_high() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "samples" / "scan_installed_skills.py"),
            "--root",
            str(FIXTURES / "05-remote-download-execute"),
            "--fail-on",
            "high",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert "FAILED: installed skills scan found findings at or above high" in result.stdout
