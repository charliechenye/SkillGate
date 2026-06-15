from __future__ import annotations

import json

from conftest import FIXTURES, clean_test_dir, runner

from skillgate.baseline import create_baseline, save_baseline
from skillgate.cli import app
from skillgate.identity import finding_fingerprint
from skillgate.scan import scan_repository


def test_review_summary_markdown_and_json_with_baseline_and_policy() -> None:
    workdir = clean_test_dir("review-summary")
    lock = create_baseline(FIXTURES / "11-mcp-capability-drift-before")
    lock_path = workdir / "skillgate.lock"
    save_baseline(lock, lock_path)
    policy_path = workdir / "skillgate.yaml"
    policy_path.write_text(
        "version: 1\npolicy:\n  mcp:\n    require_review_on_change: true\n",
        encoding="utf-8",
    )
    json_output = workdir / "skillgate-review.json"
    result = runner.invoke(
        app,
        [
            "review",
            "summary",
            str(FIXTURES / "12-mcp-capability-drift-after"),
            "--baseline",
            str(lock_path),
            "--policy",
            str(policy_path),
            "--json-output",
            str(json_output),
            "--sarif-artifact",
            "skillgate.sarif",
            "--json-artifact",
            "skillgate-review.json",
        ],
    )
    assert result.exit_code == 0
    assert "# SkillGate Review Summary" in result.output
    assert "## Introduced Capabilities" in result.output
    assert "## Changed Trust Boundaries" in result.output
    assert "## Policy Violations" in result.output
    assert "MCP capability changed from baseline" in result.output
    assert "skillgate.sarif" in result.output
    data = json.loads(json_output.read_text(encoding="utf-8"))
    assert data["status"]["baseline_compared"] is True
    assert data["status"]["policy_evaluated"] is True
    assert data["status"]["policy_blocked"] is True
    assert data["summary"]["introduced_capabilities"] >= 1
    assert data["summary"]["changed_trust_boundaries"] >= 1
    assert data["summary"]["policy_violations"] >= 1
    assert data["artifacts"]["json"] == "skillgate-review.json"
    assert "new_high_risk_findings" in data


def test_review_summary_current_high_risk_and_active_waivers() -> None:
    workdir = clean_test_dir("review-summary-waiver")
    report = scan_repository(FIXTURES / "05-remote-download-execute")
    finding = next(item for item in report.findings if item.rule_id == "SG004")
    policy_path = workdir / "skillgate.yaml"
    policy_path.write_text(
        "\n".join(
            [
                "version: 1",
                "policy:",
                "  risk_threshold:",
                "    block: high",
                "  waivers:",
                "    entries:",
                "      - id: reviewed-installer",
                "        owner: security@example.com",
                "        reason: reviewed before release",
                "        created_on: 2026-01-01",
                "        expires_on: 2026-12-31",
                "        finding:",
                f"          fingerprint: {finding_fingerprint(finding)}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "review",
            "summary",
            str(FIXTURES / "05-remote-download-execute"),
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "current_high_risk_findings" in data
    assert data["summary"]["current_high_risk_findings"] >= 1
    assert data["summary"]["active_waivers"] == 1
    assert data["active_waivers"][0]["id"] == "reviewed-installer"
