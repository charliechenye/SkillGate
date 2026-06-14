from __future__ import annotations

import json
from datetime import date

import pytest
import yaml
from conftest import FINGERPRINT_ERROR, FIXTURES, ROOT, clean_test_dir, runner

from skillgate.cli import app
from skillgate.identity import finding_fingerprint
from skillgate.policy import evaluate_policy, load_policy
from skillgate.policy_schema import POLICY_JSON_SCHEMA
from skillgate.scan import scan_repository


def test_policy_reexports_waiver_helpers_for_compatibility() -> None:
    import skillgate.policy_waivers as policy_waivers
    from skillgate.policy import (
        FINDING_WAIVER_SELECTOR_KEYS,
        FINGERPRINT_RE,
        NARROW_FINDING_SELECTOR_KEYS,
        finding_matches_waiver,
        finding_value,
        is_broad_selector,
        matching_waiver_for_violation,
        policy_waiver_entries,
        waiver_expires_on,
        waiver_selector_label,
        waiver_summary,
    )

    assert FINGERPRINT_RE is policy_waivers.FINGERPRINT_RE
    assert FINDING_WAIVER_SELECTOR_KEYS is policy_waivers.FINDING_WAIVER_SELECTOR_KEYS
    assert NARROW_FINDING_SELECTOR_KEYS is policy_waivers.NARROW_FINDING_SELECTOR_KEYS
    assert is_broad_selector is policy_waivers.is_broad_selector
    assert policy_waiver_entries is policy_waivers.policy_waiver_entries
    assert waiver_selector_label is policy_waivers.waiver_selector_label
    assert waiver_summary is policy_waivers.waiver_summary
    assert waiver_expires_on is policy_waivers.waiver_expires_on
    assert finding_value is policy_waivers.finding_value
    assert finding_matches_waiver is policy_waivers.finding_matches_waiver
    assert matching_waiver_for_violation is policy_waivers.matching_waiver_for_violation


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
        (
            "bad-shell-command-allow",
            "version: 1\npolicy:\n  shell:\n    commands:\n      allow: python\n",
            "policy.shell.commands.allow must be a list of strings",
        ),
        (
            "bad-network-category",
            "version: 1\npolicy:\n  network:\n    allow_categories:\n      - mystery\n",
            "policy.network.allow_categories must contain known categories",
        ),
        (
            "bad-capability-group",
            "version: 1\npolicy:\n  capabilities:\n    allow:\n      - network.mystery\n",
            "policy.capabilities.allow must contain known capability groups",
        ),
        (
            "bad-capability-group-type",
            "version: 1\npolicy:\n  capabilities:\n    deny: network.any\n",
            "policy.capabilities.deny must be a list of strings",
        ),
        (
            "bad-secret-env-allow",
            "version: 1\npolicy:\n  secrets:\n    env:\n      allow: GITHUB_TOKEN\n",
            "policy.secrets.env.allow must be a list of strings",
        ),
        (
            "bad-waiver-owner",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n      - reason: reviewed\n"
                "        created_on: 2026-01-01\n        expires_on: 2026-02-01\n"
                "        finding:\n          id: SG004-abc\n"
            ),
            "policy.waivers.entries.owner is required",
        ),
        (
            "bad-waiver-date",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n"
                "      - owner: sec\n        reason: reviewed\n"
                "        created_on: yesterday\n        expires_on: 2026-02-01\n"
                "        finding:\n          id: SG004-abc\n"
            ),
            "policy.waivers.entries.created_on must be an ISO date",
        ),
        (
            "bad-waiver-date-order",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n"
                "      - owner: sec\n        reason: reviewed\n"
                "        created_on: 2026-03-01\n        expires_on: 2026-02-01\n"
                "        finding:\n          id: SG004-abc\n"
            ),
            "policy.waivers.entries.created_on must be on or before expires_on",
        ),
        (
            "bad-waiver-capability-selector",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n"
                "      - owner: sec\n        reason: reviewed\n"
                "        created_on: 2026-01-01\n        expires_on: 2026-02-01\n"
                "        capability:\n          type: network_egress\n"
            ),
            "Unknown policy.waivers.entries key: capability",
        ),
        (
            "bad-waiver-broad-selector",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n"
                "      - owner: sec\n        reason: reviewed\n"
                "        created_on: 2026-01-01\n        expires_on: 2026-02-01\n"
                "        finding:\n          rule_id: SG004\n"
            ),
            "policy.waivers.entries.finding selector is too broad",
        ),
        (
            "bad-waiver-fingerprint-wildcard",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n"
                "      - owner: sec\n        reason: reviewed\n"
                "        created_on: 2026-01-01\n        expires_on: 2026-02-01\n"
                "        finding:\n          fingerprint: 'sha256:*'\n"
            ),
            FINGERPRINT_ERROR,
        ),
        (
            "bad-waiver-fingerprint-prefix",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n"
                "      - owner: sec\n        reason: reviewed\n"
                "        created_on: 2026-01-01\n        expires_on: 2026-02-01\n"
                "        finding:\n          fingerprint: 'sha256:abc*'\n"
            ),
            FINGERPRINT_ERROR,
        ),
        (
            "bad-waiver-fingerprint-uppercase",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n"
                "      - owner: sec\n        reason: reviewed\n"
                "        created_on: 2026-01-01\n        expires_on: 2026-02-01\n"
                f"        finding:\n          fingerprint: 'sha256:{'A' * 64}'\n"
            ),
            FINGERPRINT_ERROR,
        ),
        (
            "bad-waiver-fingerprint-short",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n"
                "      - owner: sec\n        reason: reviewed\n"
                "        created_on: 2026-01-01\n        expires_on: 2026-02-01\n"
                "        finding:\n          fingerprint: 'sha256:abc123'\n"
            ),
            FINGERPRINT_ERROR,
        ),
        (
            "bad-waiver-fingerprint-invalid-hex",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n"
                "      - owner: sec\n        reason: reviewed\n"
                "        created_on: 2026-01-01\n        expires_on: 2026-02-01\n"
                f"        finding:\n          fingerprint: 'sha256:{'g' * 64}'\n"
            ),
            FINGERPRINT_ERROR,
        ),
        (
            "bad-waiver-fingerprint-uppercase-prefix",
            (
                "version: 1\npolicy:\n  waivers:\n    entries:\n"
                "      - owner: sec\n        reason: reviewed\n"
                "        created_on: 2026-01-01\n        expires_on: 2026-02-01\n"
                f"        finding:\n          fingerprint: 'SHA256:{'a' * 64}'\n"
            ),
            FINGERPRINT_ERROR,
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


def test_policy_waiver_broad_selector_requires_explicit_opt_in() -> None:
    workdir = clean_test_dir("policy-waiver-broad-opt-in")
    policy = workdir / "skillgate.yaml"
    policy.write_text(
        "\n".join(
            [
                "version: 1",
                "policy:",
                "  waivers:",
                "    allow_broad_selectors: true",
                "    entries:",
                "      - owner: security",
                "        reason: temporary reviewed installer exception",
                "        created_on: 2026-01-01",
                "        expires_on: 2026-02-01",
                "        finding:",
                "          rule_id: SG004",
            ]
        ),
        encoding="utf-8",
    )
    data = load_policy(policy)
    assert data["policy"]["waivers"]["entries"][0]["finding"]["rule_id"] == "SG004"


def test_policy_fingerprint_waiver_survives_line_shift_but_not_evidence_change() -> None:
    report = scan_repository(FIXTURES / "05-remote-download-execute")
    finding = next(item for item in report.findings if item.rule_id == "SG004")
    shifted = finding.model_copy(update={"line_number": (finding.line_number or 1) + 100})
    changed = finding.model_copy(update={"evidence": f"{finding.evidence} changed"})
    policy = {
        "version": 1,
        "policy": {
            "risk_threshold": {"block": "high"},
            "waivers": {
                "entries": [
                    {
                        "id": "waive-fingerprint",
                        "owner": "security",
                        "reason": "reviewed stable finding",
                        "created_on": "2026-06-13",
                        "expires_on": "2026-07-13",
                        "finding": {"fingerprint": finding_fingerprint(finding)},
                    }
                ]
            },
        },
    }

    exact_result = evaluate_policy(report.model_copy(update={"findings": [finding]}), policy)
    shifted_result = evaluate_policy(report.model_copy(update={"findings": [shifted]}), policy)
    changed_result = evaluate_policy(report.model_copy(update={"findings": [changed]}), policy)

    assert not exact_result.blocked
    assert exact_result.waived_violations[0]["fingerprint"] == finding_fingerprint(finding)
    assert not shifted_result.blocked
    assert shifted_result.waived_violations[0]["fingerprint"] == finding_fingerprint(finding)
    assert changed_result.blocked


def test_policy_valid_fingerprint_waiver_loads() -> None:
    workdir = clean_test_dir("policy-valid-fingerprint-waiver")
    policy = workdir / "skillgate.yaml"
    fingerprint = f"sha256:{'0' * 64}"
    policy.write_text(
        "\n".join(
            [
                "version: 1",
                "policy:",
                "  waivers:",
                "    entries:",
                "      - owner: security",
                "        reason: reviewed stable finding",
                "        created_on: 2026-06-13",
                "        expires_on: 2026-07-13",
                "        finding:",
                f"          fingerprint: {fingerprint}",
            ]
        ),
        encoding="utf-8",
    )
    data = load_policy(policy)
    assert data["policy"]["waivers"]["entries"][0]["finding"]["fingerprint"] == fingerprint


def test_policy_command_allowlist_blocks_unapproved_shell_commands() -> None:
    workdir = clean_test_dir("policy-command-allow")
    (workdir / "SKILL.md").write_text("Run `run.py`.\n", encoding="utf-8")
    (workdir / "run.py").write_text(
        "import subprocess\nsubprocess.run(['python', 'safe.py'])\n",
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    allowed = evaluate_policy(
        report,
        {
            "version": 1,
            "policy": {"shell": {"commands": {"allow": ["subprocess.run*"]}}},
        },
    )
    blocked = evaluate_policy(
        report,
        {
            "version": 1,
            "policy": {"shell": {"commands": {"allow": ["python safe.py"]}}},
        },
    )
    assert not allowed.blocked
    assert blocked.blocked
    assert "Shell command is not allowlisted" in blocked.violations[0].message


def test_policy_secret_env_allowlist_exempts_named_env() -> None:
    workdir = clean_test_dir("policy-secret-env-allow")
    (workdir / "SKILL.md").write_text("Use GITHUB_TOKEN for release metadata.\n", encoding="utf-8")
    report = scan_repository(workdir)
    result = evaluate_policy(
        report,
        {
            "version": 1,
            "policy": {
                "secrets": {
                    "deny": ["*"],
                    "env": {"allow": ["GITHUB_TOKEN"]},
                }
            },
        },
    )
    assert not result.blocked


def test_policy_network_categories_and_deny_precedence() -> None:
    workdir = clean_test_dir("policy-network-categories")
    (workdir / "SKILL.md").write_text("Run `net.py`.\n", encoding="utf-8")
    (workdir / "net.py").write_text(
        "\n".join(
            [
                "requests.get('https://api.github.com/repos/example/repo')",
                "requests.get('http://169.254.169.254/latest/meta-data')",
            ]
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    result = evaluate_policy(
        report,
        {
            "version": 1,
            "policy": {
                "network": {
                    "allow": ["169.254.169.254"],
                    "allow_categories": ["source_control"],
                    "deny_categories": ["cloud_metadata"],
                }
            },
        },
    )
    assert result.blocked
    assert any("Network host category is denied" in item.message for item in result.violations)
    assert not any("api.github.com" in item.message for item in result.violations)


def test_policy_capability_groups_allow_network_and_deny_precedence() -> None:
    workdir = clean_test_dir("policy-capability-network-groups")
    (workdir / "SKILL.md").write_text("Run `net.py`.\n", encoding="utf-8")
    (workdir / "net.py").write_text(
        "\n".join(
            [
                "requests.get('https://registry.npmjs.org/package')",
                "requests.get('https://example.com/api')",
            ]
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    allowed = evaluate_policy(
        report,
        {
            "version": 1,
            "policy": {
                "network": {"allow": []},
                "capabilities": {"allow": ["network.package_registry"]},
            },
        },
    )
    assert allowed.blocked
    assert not any("registry.npmjs.org" in item.message for item in allowed.violations)
    assert any("example.com" in item.message for item in allowed.violations)
    denied = evaluate_policy(
        report,
        {
            "version": 1,
            "policy": {
                "network": {"allow": ["registry.npmjs.org"]},
                "capabilities": {
                    "allow": ["network.any"],
                    "deny": ["network.package_registry"],
                },
            },
        },
    )
    assert denied.blocked
    assert any(
        "Capability group is denied: network.package_registry" in item.message
        for item in denied.violations
    )
    assert not any("example.com" in item.message for item in denied.violations)


def test_policy_capability_groups_allow_shell_mcp_and_cloud_secrets() -> None:
    shell_dir = clean_test_dir("policy-capability-shell")
    scripts = shell_dir / "scripts"
    scripts.mkdir()
    (shell_dir / "SKILL.md").write_text("Run `scripts/build.sh`.\n", encoding="utf-8")
    (scripts / "build.sh").write_text("bash scripts/build.sh\n", encoding="utf-8")
    shell_result = evaluate_policy(
        scan_repository(shell_dir),
        {
            "version": 1,
            "policy": {
                "shell": {"allow": False},
                "capabilities": {"allow": ["shell.local_script"]},
            },
        },
    )
    assert not shell_result.blocked

    remote_result = evaluate_policy(
        scan_repository(FIXTURES / "05-remote-download-execute"),
        {
            "version": 1,
            "policy": {
                "shell": {"allow": False},
                "capabilities": {"allow": ["shell.local_script"]},
            },
        },
    )
    assert remote_result.blocked
    assert any(
        "remote download execution" in (item.reason or "").lower()
        for item in remote_result.violations
    )

    mcp_result = evaluate_policy(
        scan_repository(FIXTURES / "16-public-pattern-mcp-http-remote"),
        {
            "version": 1,
            "policy": {
                "network": {"allow": []},
                "capabilities": {"allow": ["mcp.remote_http"]},
            },
        },
    )
    assert not mcp_result.blocked

    secret_dir = clean_test_dir("policy-capability-cloud-secrets")
    (secret_dir / "SKILL.md").write_text("Use OPENAI_API_KEY.\n", encoding="utf-8")
    secret_result = evaluate_policy(
        scan_repository(secret_dir),
        {
            "version": 1,
            "policy": {
                "secrets": {"deny": ["*"]},
                "capabilities": {"allow": ["secrets.cloud"]},
            },
        },
    )
    assert not secret_result.blocked


def test_policy_violations_include_explanations_and_suggestions() -> None:
    workdir = clean_test_dir("policy-explanations")
    (workdir / "SKILL.md").write_text("Run `net.py`.\n", encoding="utf-8")
    (workdir / "net.py").write_text(
        "requests.get('https://registry.npmjs.org/package')\n",
        encoding="utf-8",
    )
    result = evaluate_policy(
        scan_repository(workdir),
        {"version": 1, "policy": {"network": {"allow": []}}},
    )
    assert result.blocked
    violation = result.violations[0]
    assert violation.reason
    assert violation.approval_hint
    assert violation.suggested_policy == {"policy": {"network": {"allow": ["registry.npmjs.org"]}}}


def test_active_finding_waiver_suppresses_specific_sg004_threshold_violation() -> None:
    report = scan_repository(FIXTURES / "05-remote-download-execute")
    sg004 = next(finding for finding in report.findings if finding.rule_id == "SG004")
    report = report.model_copy(update={"findings": [sg004], "capabilities": []})
    result = evaluate_policy(
        report,
        {
            "version": 1,
            "policy": {
                "risk_threshold": {"block": "high"},
                "waivers": {
                    "entries": [
                        {
                            "id": "waive-reviewed-installer",
                            "owner": "security",
                            "reason": "Reviewed pinned installer script.",
                            "created_on": "2026-01-01",
                            "expires_on": "2026-02-01",
                            "ticket": "SEC-123",
                            "finding": {"id": sg004.id},
                        }
                    ]
                },
            },
        },
        today=date(2026, 1, 15),
    )
    assert not result.blocked
    assert result.active_waivers[0]["id"] == "waive-reviewed-installer"
    assert result.waived_violations[0]["finding_id"] == sg004.id
    assert result.waived_violations[0]["waiver"]["ticket"] == "SEC-123"


def test_nonmatching_and_expired_finding_waivers_do_not_approve_findings() -> None:
    report = scan_repository(FIXTURES / "05-remote-download-execute")
    sg004 = next(finding for finding in report.findings if finding.rule_id == "SG004")
    report = report.model_copy(update={"findings": [sg004], "capabilities": []})
    nonmatching = evaluate_policy(
        report,
        {
            "version": 1,
            "policy": {
                "risk_threshold": {"block": "high"},
                "waivers": {
                    "entries": [
                        {
                            "owner": "security",
                            "reason": "Different reviewed finding.",
                            "created_on": "2026-01-01",
                            "expires_on": "2026-02-01",
                            "finding": {"id": "SG004-nope"},
                        }
                    ]
                },
            },
        },
        today=date(2026, 1, 15),
    )
    assert nonmatching.blocked
    assert not nonmatching.waived_violations

    expired = evaluate_policy(
        report,
        {
            "version": 1,
            "policy": {
                "risk_threshold": {"block": "high"},
                "waivers": {
                    "entries": [
                        {
                            "id": "expired-installer",
                            "owner": "security",
                            "reason": "Old review.",
                            "created_on": "2026-01-01",
                            "expires_on": "2026-01-10",
                            "finding": {"id": sg004.id},
                        }
                    ]
                },
            },
        },
        today=date(2026, 1, 15),
    )
    assert expired.blocked
    assert expired.expired_waivers[0]["id"] == "expired-installer"
    assert any("Finding waiver expired" in item.message for item in expired.violations)


def test_finding_waivers_do_not_suppress_capability_only_violations() -> None:
    workdir = clean_test_dir("policy-waiver-capability-only")
    (workdir / "SKILL.md").write_text("Run `net.py`.\n", encoding="utf-8")
    (workdir / "net.py").write_text(
        "requests.get('https://api.github.com/repos/example/repo')\n",
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    result = evaluate_policy(
        report,
        {
            "version": 1,
            "policy": {
                "network": {"allow": []},
                "waivers": {
                    "entries": [
                        {
                            "owner": "security",
                            "reason": "Finding waiver does not approve capability.",
                            "created_on": "2026-01-01",
                            "expires_on": "2026-02-01",
                            "finding": {
                                "rule_id": "SG003",
                                "file_path": "net.py",
                            },
                        }
                    ]
                },
            },
        },
        today=date(2026, 1, 15),
    )
    assert result.blocked
    assert any("Network host is not allowlisted" in item.message for item in result.violations)
    assert not result.waived_violations


def test_policy_schema_cli_and_file_are_stable_json() -> None:
    result = runner.invoke(app, ["policy", "schema"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    schema_file = json.loads(
        (ROOT / "schemas" / "skillgate-policy.schema.json").read_text(encoding="utf-8")
    )
    assert data == POLICY_JSON_SCHEMA == schema_file
    assert data["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert data["properties"]["version"]["const"] == 1
    assert data["properties"]["policy"]["properties"]["risk_threshold"]["properties"]["block"][
        "enum"
    ] == ["informational", "low", "medium", "high", "critical"]


def test_policy_schema_cli_writes_output() -> None:
    workdir = clean_test_dir("policy-schema-output")
    output = workdir / "schema.json"
    result = runner.invoke(app, ["policy", "schema", "--output", str(output)])
    assert result.exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8")) == POLICY_JSON_SCHEMA


@pytest.mark.parametrize("profile", ["audit", "preinstall", "strict", "mcp"])
def test_policy_init_profiles_emit_valid_yaml(profile: str) -> None:
    result = runner.invoke(app, ["policy", "init", "--profile", profile])
    assert result.exit_code == 0
    data = yaml.safe_load(result.output)
    assert data["version"] == 1
    workdir = clean_test_dir(f"policy-init-{profile}")
    policy = workdir / "skillgate.yaml"
    policy.write_text(result.output, encoding="utf-8")
    assert load_policy(policy)["version"] == 1


def test_policy_init_writes_output_file() -> None:
    workdir = clean_test_dir("policy-init-output")
    output = workdir / "skillgate.yaml"
    result = runner.invoke(
        app,
        ["policy", "init", "--profile", "strict", "--output", str(output)],
    )
    assert result.exit_code == 0
    data = load_policy(output)
    assert data["policy"]["risk_threshold"]["block"] == "medium"


def test_policy_init_refuses_to_overwrite_existing_output() -> None:
    workdir = clean_test_dir("policy-init-existing")
    output = workdir / "skillgate.yaml"
    output.write_text("version: 1\npolicy: {}\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["policy", "init", "--profile", "strict", "--output", str(output)],
    )
    assert result.exit_code == 2
    assert "output file already exists" in result.output


def test_policy_init_unknown_profile_exits_2() -> None:
    result = runner.invoke(app, ["policy", "init", "--profile", "unknown"])
    assert result.exit_code == 2
    assert "unknown policy profile" in result.output


def test_policy_schema_reference_documents_supported_fields() -> None:
    reference = (ROOT / "docs" / "policy-schema.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for field in [
        "version",
        "policy.capabilities.allow",
        "policy.capabilities.deny",
        "policy.shell.allow",
        "policy.shell.commands.allow",
        "policy.filesystem.read",
        "policy.filesystem.write",
        "policy.network.allow",
        "policy.network.allow_categories",
        "policy.network.deny_categories",
        "policy.secrets.deny",
        "policy.secrets.env.allow",
        "policy.mcp.require_review_on_change",
        "policy.risk_threshold.block",
        "policy.waivers",
        "allow_broad_selectors",
        "created_on",
        "expires_on",
        "fingerprint",
    ]:
        assert field in reference
    assert "docs/policy-schema.md" in readme
    assert "docs/editor-setup.md" in readme
    assert "skillgate inventory" in readme
    assert "skillgate provenance create" in readme
    assert "skillgate policy init" in readme
    assert "skillgate policy init --profile strict" in reference
