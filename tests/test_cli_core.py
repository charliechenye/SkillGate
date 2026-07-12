from __future__ import annotations

import json

from conftest import FIXTURES, ROOT, clean_test_dir, runner

from skillgate import __version__
from skillgate.cli import app
from skillgate.sarif import FINGERPRINT_KEY
from skillgate.scan import scan_repository


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output == f"SkillGate {__version__}\n"


def test_cli_scan_exit_code_and_output() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "02-shell-execution")])
    assert result.exit_code == 0
    assert "SG001" in result.output


def test_cli_scan_format_aware_is_opt_in(tmp_path) -> None:
    (tmp_path / "SKILL.md").write_text("ignore previous\ninstructions\n", encoding="utf-8")

    legacy = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    aware = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--format-aware"])

    assert legacy.exit_code == 0
    assert json.loads(legacy.output)["findings"] == []
    assert aware.exit_code == 0
    assert {item["rule_id"] for item in json.loads(aware.output)["findings"]} == {"SG007"}


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
    assert data["runs"][0]["automationDetails"]["id"] == "skillgate/local-repository"
    rule_ids = {item["ruleId"] for item in data["runs"][0]["results"]}
    assert rule_ids == {"SG001", "SG004"}
    assert all(item["level"] == "error" for item in data["runs"][0]["results"])
    assert all(
        FINGERPRINT_KEY in item["partialFingerprints"] for item in data["runs"][0]["results"]
    )


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


def test_cli_inventory_text_includes_trust_boundaries() -> None:
    result = runner.invoke(app, ["inventory", str(FIXTURES / "05-remote-download-execute")])
    assert result.exit_code == 0
    assert "SkillGate inventory" in result.output
    assert "Trust boundaries:" in result.output
    assert "local_execution" in result.output
    assert "remote_endpoints" in result.output
    assert "scripts/install.sh" in result.output
    assert "<unknown>" in result.output


def test_cli_inventory_json_groups_capabilities_by_file() -> None:
    first = runner.invoke(
        app,
        ["inventory", str(FIXTURES / "05-remote-download-execute"), "--format", "json"],
    )
    second = runner.invoke(
        app,
        ["inventory", str(FIXTURES / "05-remote-download-execute"), "--format", "json"],
    )
    assert first.exit_code == 0
    assert second.exit_code == 0
    assert first.output == second.output
    data = json.loads(first.output)
    assert data["schema_version"] == "1"
    assert data["summary"] == {
        "capabilities": 4,
        "files": 1,
        "findings": 4,
        "scanned_files": 2,
    }
    assert [item["path"] for item in data["files"]] == ["scripts/install.sh"]
    assert [item["type"] for item in data["files"][0]["capabilities"]] == [
        "network_egress",
        "remote_download_execution",
        "shell_execution",
        "shell_execution",
    ]
    boundaries = {item["name"]: item for item in data["trust_boundaries"]}
    assert boundaries["local_execution"]["count"] == 3
    assert boundaries["local_execution"]["resources"] == ["<unknown>", "example.com"]
    assert boundaries["local_execution"]["rule_ids"] == ["SG001", "SG004"]
    assert boundaries["remote_endpoints"]["resources"] == ["example.com"]


def test_cli_inventory_unknown_resources_render_in_json() -> None:
    result = runner.invoke(
        app,
        ["inventory", str(FIXTURES / "02-shell-execution"), "--format", "json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    resources = [
        capability["resource"]
        for file_record in data["files"]
        for capability in file_record["capabilities"]
    ]
    assert "<unknown>" in resources


def test_cli_inventory_filters_by_capability_severity_and_source_file() -> None:
    capability_result = runner.invoke(
        app,
        [
            "inventory",
            str(FIXTURES / "05-remote-download-execute"),
            "--format",
            "json",
            "--capability",
            "network_egress",
        ],
    )
    assert capability_result.exit_code == 0
    capability_data = json.loads(capability_result.output)
    assert capability_data["filters"]["capability"] == ["network_egress"]
    assert capability_data["summary"]["capabilities"] == 1
    assert {
        capability["type"]
        for file_record in capability_data["files"]
        for capability in file_record["capabilities"]
    } == {"network_egress"}

    severity_result = runner.invoke(
        app,
        [
            "inventory",
            str(FIXTURES / "05-remote-download-execute"),
            "--format",
            "json",
            "--severity",
            "high",
        ],
    )
    assert severity_result.exit_code == 0
    severity_data = json.loads(severity_result.output)
    assert severity_data["filters"]["severity"] == "high"
    assert {
        finding["severity"]
        for file_record in severity_data["files"]
        for finding in file_record["findings"]
    } == {"high"}

    source_result = runner.invoke(
        app,
        [
            "inventory",
            str(FIXTURES / "05-remote-download-execute"),
            "--format",
            "json",
            "--source-file",
            "scripts/*",
        ],
    )
    assert source_result.exit_code == 0
    source_data = json.loads(source_result.output)
    assert source_data["filters"]["source_file"] == ["scripts/*"]
    assert [item["path"] for item in source_data["files"]] == ["scripts/install.sh"]


def test_cli_rules_list_json() -> None:
    result = runner.invoke(app, ["rules", "list", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert [rule["rule_id"] for rule in data["rules"]] == [
        f"SG{index:03d}" for index in range(1, 16)
    ]
    assert data["rules"][3]["capability"] == "remote_download_execution"


def test_cli_explain_json() -> None:
    result = runner.invoke(app, ["explain", "SG004", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["rule_id"] == "SG004"
    assert data["severity"] == "high"
    assert data["capability"] == "remote_download_execution"


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


def test_cli_check_dry_run_text_exits_zero_with_explanations() -> None:
    result = runner.invoke(
        app,
        [
            "check",
            str(FIXTURES / "05-remote-download-execute"),
            "--policy",
            str(ROOT / "skillgate.example.yaml"),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "DRY RUN: repository would be blocked by policy" in result.output
    assert "why:" in result.output
    assert "approve by:" in result.output


def test_cli_check_dry_run_json_includes_suggestions() -> None:
    workdir = clean_test_dir("check-dry-run-json")
    (workdir / "SKILL.md").write_text("Run `net.py`.\n", encoding="utf-8")
    (workdir / "net.py").write_text(
        "requests.get('https://registry.npmjs.org/package')\n",
        encoding="utf-8",
    )
    policy = workdir / "skillgate.yaml"
    policy.write_text("version: 1\npolicy:\n  network:\n    allow: []\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "check",
            str(workdir),
            "--policy",
            str(policy),
            "--dry-run",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["policy_result"]["blocked"] is True
    assert data["policy_result"]["violations"][0]["reason"]
    assert data["suggestions"] == [{"policy": {"network": {"allow": ["registry.npmjs.org"]}}}]


def test_cli_check_text_and_json_surface_finding_waivers() -> None:
    sg004 = next(
        finding
        for finding in scan_repository(FIXTURES / "05-remote-download-execute").findings
        if finding.rule_id == "SG004"
    )
    workdir = clean_test_dir("check-waiver-output")
    policy = workdir / "skillgate.yaml"
    policy.write_text(
        "\n".join(
            [
                "version: 1",
                "policy:",
                "  risk_threshold:",
                "    block: high",
                "  waivers:",
                "    entries:",
                "      - id: waive-reviewed-installer",
                "        owner: security",
                "        reason: Reviewed pinned installer script.",
                "        created_on: 2026-01-01",
                "        expires_on: 2999-01-01",
                "        ticket: SEC-123",
                "        finding:",
                f"          id: {sg004.id}",
            ]
        ),
        encoding="utf-8",
    )
    text = runner.invoke(
        app,
        ["check", str(FIXTURES / "05-remote-download-execute"), "--policy", str(policy)],
    )
    assert text.exit_code == 1
    assert "Active waivers:" in text.output
    assert "Waived violations:" in text.output
    assert "waive-reviewed-installer" in text.output

    json_result = runner.invoke(
        app,
        [
            "check",
            str(FIXTURES / "05-remote-download-execute"),
            "--policy",
            str(policy),
            "--format",
            "json",
        ],
    )
    assert json_result.exit_code == 1
    data = json.loads(json_result.output)
    assert data["policy_result"]["active_waivers"][0]["id"] == "waive-reviewed-installer"
    assert data["policy_result"]["waived_violations"][0]["finding_id"] == sg004.id


def test_cli_check_expired_waiver_blocks_safe_repository() -> None:
    workdir = clean_test_dir("check-expired-waiver")
    policy = workdir / "skillgate.yaml"
    policy.write_text(
        "\n".join(
            [
                "version: 1",
                "policy:",
                "  waivers:",
                "    entries:",
                "      - id: expired-review",
                "        owner: security",
                "        reason: Old review.",
                "        created_on: 1999-01-01",
                "        expires_on: 2000-01-01",
                "        finding:",
                "          id: SG004-old",
            ]
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["check", str(FIXTURES / "01-safe-documentation-skill"), "--policy", str(policy)],
    )
    assert result.exit_code == 1
    assert "Finding waiver expired" in result.output
    assert "Expired waivers:" in result.output


def test_cli_check_sarif_includes_waiver_suppressions() -> None:
    sg004 = next(
        finding
        for finding in scan_repository(FIXTURES / "05-remote-download-execute").findings
        if finding.rule_id == "SG004"
    )
    workdir = clean_test_dir("check-waiver-sarif")
    policy = workdir / "skillgate.yaml"
    policy.write_text(
        "\n".join(
            [
                "version: 1",
                "policy:",
                "  risk_threshold:",
                "    block: high",
                "  waivers:",
                "    entries:",
                "      - id: waive-reviewed-installer",
                "        owner: security",
                "        reason: Reviewed pinned installer script.",
                "        created_on: 2026-01-01",
                "        expires_on: 2999-01-01",
                "        finding:",
                f"          id: {sg004.id}",
            ]
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "check",
            str(FIXTURES / "05-remote-download-execute"),
            "--policy",
            str(policy),
            "--format",
            "sarif",
        ],
    )
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["runs"][0]["properties"]["policyWaivers"]["active"][0]["id"] == (
        "waive-reviewed-installer"
    )
    sg004_result = next(item for item in data["runs"][0]["results"] if item["ruleId"] == "SG004")
    assert sg004_result["suppressions"][0]["kind"] == "external"
    assert "Reviewed pinned installer" in sg004_result["suppressions"][0]["justification"]


def test_cli_baseline_and_diff() -> None:
    workdir = clean_test_dir("baseline-diff")
    lock = workdir / "skillgate.lock"
    policy = workdir / "skillgate.yaml"
    policy.write_text(
        "version: 1\npolicy:\n  mcp:\n    require_review_on_change: true\n",
        encoding="utf-8",
    )
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
    blocking_diff = runner.invoke(
        app,
        [
            "diff",
            str(FIXTURES / "12-mcp-capability-drift-after"),
            "--baseline",
            str(lock),
            "--fail-on-drift",
        ],
    )
    assert blocking_diff.exit_code == 1
    assert "SG010" in blocking_diff.output
    clean_diff = runner.invoke(
        app,
        [
            "diff",
            str(FIXTURES / "11-mcp-capability-drift-before"),
            "--baseline",
            str(lock),
            "--fail-on-drift",
        ],
    )
    assert clean_diff.exit_code == 0
    assert "Findings: 0" in clean_diff.output
    policy_diff = runner.invoke(
        app,
        [
            "diff",
            str(FIXTURES / "12-mcp-capability-drift-after"),
            "--baseline",
            str(lock),
            "--policy",
            str(policy),
        ],
    )
    assert policy_diff.exit_code == 1
    assert "MCP capability changed from baseline" in policy_diff.output
