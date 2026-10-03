from __future__ import annotations

import json
import tomllib

import pytest
import yaml
from conftest import FIXTURES, ROOT, clean_test_dir, runner

from skillgate import __version__
from skillgate.baseline import create_baseline, diff_against_baseline
from skillgate.cli import app
from skillgate.scan import scan_repository


def rule_ids(path: str) -> set[str]:
    return {finding.rule_id for finding in scan_repository(FIXTURES / path).findings}


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


def test_public_pattern_fixtures_have_attribution_metadata() -> None:
    result = runner.invoke(
        app,
        ["fixtures", "summary", str(FIXTURES), "--format", "json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    public_fixtures = [item for item in data["fixtures"] if "-public-pattern-" in item["name"]]
    assert public_fixtures
    assert all(item.get("attribution", {}).get("sources") for item in public_fixtures)
    assert all(item["attribution"]["retrieved_on"] == "2026-06-11" for item in public_fixtures)


def test_public_pattern_fixture_missing_attribution_exits_2() -> None:
    workdir = clean_test_dir("missing-public-attribution")
    fixture = workdir / "01-public-pattern-missing-attribution"
    fixture.mkdir()
    (fixture / "SKILL.md").write_text("Safe\n", encoding="utf-8")
    (fixture / "expected-findings.yaml").write_text("findings: []\n", encoding="utf-8")
    result = runner.invoke(app, ["fixtures", "summary", str(workdir), "--format", "json"])
    assert result.exit_code == 2
    assert "must contain attribution for public-pattern fixtures" in result.output


def test_public_pattern_fixture_malformed_attribution_exits_2() -> None:
    workdir = clean_test_dir("malformed-public-attribution")
    fixture = workdir / "01-public-pattern-malformed-attribution"
    fixture.mkdir()
    (fixture / "SKILL.md").write_text("Safe\n", encoding="utf-8")
    (fixture / "expected-findings.yaml").write_text(
        "findings: []\nattribution:\n  sources:\n    - name: Missing URL\n"
        '  reduction: Reduced.\n  retrieved_on: "2026-06-11"\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["fixtures", "summary", str(workdir), "--format", "json"])
    assert result.exit_code == 2
    assert "attribution.sources entries require url" in result.output


def test_cli_fixtures_summary_json() -> None:
    result = runner.invoke(
        app,
        ["fixtures", "summary", str(FIXTURES), "--format", "json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["failed"] == 0
    assert data["summary"]["fixtures"] == 31
    assert all(item["status"] == "pass" for item in data["fixtures"])


def test_cli_fixtures_summary_markdown_is_reviewable() -> None:
    result = runner.invoke(
        app,
        ["fixtures", "summary", str(FIXTURES), "--format", "markdown"],
    )
    assert result.exit_code == 0
    assert "# SkillGate Benchmark Report" in result.output
    assert "Scanner version:" in result.output
    assert "## Rule Coverage" in result.output
    assert "Expected fixtures" in result.output
    assert "SG014" in result.output
    assert "not covered" in result.output
    assert "## Attribution" in result.output
    assert "not a real-world detection accuracy benchmark" in result.output


def test_cli_provenance_create_and_verify() -> None:
    workdir = clean_test_dir("provenance-create-verify")
    (workdir / "SKILL.md").write_text("Safe\n", encoding="utf-8")
    policy = workdir / "skillgate.yaml"
    policy.write_text("version: 1\npolicy: {}\n", encoding="utf-8")
    baseline = workdir / "skillgate.lock"
    manifest = workdir / "skillgate.provenance.json"
    baseline_result = runner.invoke(
        app,
        ["baseline", "create", str(workdir), "--output", str(baseline)],
    )
    assert baseline_result.exit_code == 0
    create_result = runner.invoke(
        app,
        [
            "provenance",
            "create",
            "--policy",
            str(policy),
            "--baseline",
            str(baseline),
            "--output",
            str(manifest),
        ],
    )
    assert create_result.exit_code == 0
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["algorithm"] == "sha256"
    assert [item["role"] for item in data["files"]] == ["policy", "baseline"]
    verify_result = runner.invoke(app, ["provenance", "verify", "--manifest", str(manifest)])
    assert verify_result.exit_code == 0
    assert "provenance verification passed" in verify_result.output


def test_cli_provenance_verify_detects_changed_file() -> None:
    workdir = clean_test_dir("provenance-changed-file")
    (workdir / "SKILL.md").write_text("Safe\n", encoding="utf-8")
    policy = workdir / "skillgate.yaml"
    policy.write_text("version: 1\npolicy: {}\n", encoding="utf-8")
    baseline = workdir / "skillgate.lock"
    manifest = workdir / "skillgate.provenance.json"
    runner.invoke(app, ["baseline", "create", str(workdir), "--output", str(baseline)])
    runner.invoke(
        app,
        [
            "provenance",
            "create",
            "--policy",
            str(policy),
            "--baseline",
            str(baseline),
            "--output",
            str(manifest),
        ],
    )
    policy.write_text("version: 1\npolicy:\n  risk_threshold:\n    block: high\n", encoding="utf-8")
    result = runner.invoke(app, ["provenance", "verify", "--manifest", str(manifest)])
    assert result.exit_code == 1
    assert "Checksum mismatch" in result.output


def test_cli_provenance_verify_missing_and_malformed_exit_2() -> None:
    workdir = clean_test_dir("provenance-errors")
    missing = runner.invoke(
        app,
        ["provenance", "verify", "--manifest", str(workdir / "missing.json")],
    )
    assert missing.exit_code == 2
    assert "Unable to load provenance manifest" in missing.output

    malformed = workdir / "bad.json"
    malformed.write_text(
        '{"schema_version": "1", "algorithm": "md5", "files": []}\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["provenance", "verify", "--manifest", str(malformed)])
    assert result.exit_code == 2
    assert "algorithm must be sha256" in result.output

    missing_target = workdir / "missing-target.json"
    missing_target.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "tool_version": "0.4.0",
                "created_at": "2026-06-11T00:00:00Z",
                "algorithm": "sha256",
                "files": [
                    {
                        "role": "policy",
                        "path": "missing-skillgate.yaml",
                        "sha256": "0" * 64,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    missing_file = runner.invoke(
        app,
        ["provenance", "verify", "--manifest", str(missing_target)],
    )
    assert missing_file.exit_code == 2
    assert "Missing policy file" in missing_file.output


def test_release_metadata_and_roadmap_are_consistent() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    future_steps = (ROOT / "future_steps.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    skills_docs = ROOT / "docs" / "skills-validation.md"
    sessions_docs = ROOT / "docs" / "sessions" / "README.md"
    release_checklist = (ROOT / "docs" / "release-checklist.md").read_text(encoding="utf-8")
    mcp_apps_docs = ROOT / "docs" / "mcp-apps-static-review.md"
    release_notes = ROOT / "docs" / "release-notes" / "0.1.3.md"
    assert pyproject["project"]["name"] == "openevalgate-skillgate"
    assert pyproject["project"]["authors"] == [{"name": "Chenye Zhu"}]
    assert pyproject["project"]["version"] == "0.1.3"
    assert pyproject["project"]["license"] == "MIT"
    assert pyproject["project"]["license-files"] == ["LICENSE"]
    assert "License :: OSI Approved :: MIT License" not in pyproject["project"]["classifiers"]
    assert __version__ == "0.1.3"
    assert '"version": "0.1.3"' in (ROOT / "package.json").read_text(encoding="utf-8")
    assert "## 0.1.3 - Review evidence foundations and MCP compatibility inventory" in changelog
    assert "Released 2026-07-29." in changelog
    assert "## 0.1.2 - Guided review workflows" in changelog
    assert "Released 2026-07-09." in changelog
    assert "reusable, bounded ZIP inspection foundation" in changelog
    assert "### Build A Reusable Safe-Archive Layer" not in future_steps
    assert (ROOT / "docs" / "archive-safety.md").exists()
    assert "## 0.4.0" not in changelog
    assert "## 0.1.1 - Release consistency and review ergonomics" in changelog
    assert "`0.1.1` is planned and not yet published" not in changelog
    assert "## 0.1.0 - Initial public release" in changelog
    assert "README SEO" not in changelog
    assert "skillgate diff --fail-on-drift" in changelog
    assert "MCP protocol-version and extension inventory" in changelog
    assert "Publish the first tagged GitHub release as `v0.1.0`" not in future_steps
    assert "supplied `baseline` plus `fail-on-drift`" in future_steps
    assert "skillgate skills validate" in readme
    assert skills_docs.exists()
    assert "skillgate skills validate" in skills_docs.read_text(encoding="utf-8")
    assert "declared-vs-observed" in skills_docs.read_text(encoding="utf-8")
    assert sessions_docs.exists()
    assert "Pre-install review" in sessions_docs.read_text(encoding="utf-8")
    assert "GitHub tags and GitHub Release assets are the" in future_steps
    assert "docs/mcp-compatibility.md" in future_steps
    assert "docs/mcp-apps-static-review.md" in future_steps
    assert "MCP Apps static adapter (implemented)" in future_steps
    assert "Skills over MCP contract study (next)" in future_steps
    assert "Tasks capability signal (implemented)" in future_steps
    assert mcp_apps_docs.exists()
    assert "Local scans never dereference" in mcp_apps_docs.read_text(encoding="utf-8")
    assert "The current stable release is `v0.1.3`." in future_steps
    assert "For `v0.1.3`, both version commands should print `0.1.3`." in release_checklist
    assert 'git tag -a v0.1.3 -m "SkillGate v0.1.3"' in release_checklist
    assert "gh release create v0.1.3" in release_checklist
    assert 'SKILLGATE_VERSION="v0.1.3"' in release_checklist
    assert "git tag -f v0 v0.1.3" in release_checklist
    assert "Review Workflow Smoke Tests" in release_checklist
    assert "only builder and uploader" in release_checklist
    assert "assets from a workstation" in release_checklist
    assert "Do not run this section for `v0.1.3`" in release_checklist
    assert "prefer yanking the affected file or version" in release_checklist
    assert release_notes.exists()
    assert "Review evidence foundations" in release_notes.read_text(encoding="utf-8")
    assert "--notes-file docs\\release-notes\\0.1.3.md" in release_checklist

    current_release, released = changelog.split("## 0.1.1", maxsplit=1)

    assert "## 0.1.2 - Guided review workflows" in current_release
    assert (
        "## 0.1.3 - Review evidence foundations and MCP compatibility inventory" in current_release
    )
    assert "skillgate demo skill" in current_release
    assert "reusable, bounded ZIP inspection foundation" not in released


def test_action_uses_action_path_and_explicit_policy_behavior() -> None:
    action_text = (ROOT / "action.yml").read_text(encoding="utf-8")
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert "python -m pip install ." not in action_text
    assert action["inputs"]["policy"]["default"] == ""
    assert action["inputs"]["fail-on-drift"]["default"] == "false"
    assert action["inputs"]["summary-output"]["default"] == ""
    assert action["inputs"]["json-output"]["default"] == ""
    assert action["inputs"]["step-summary"]["default"] == "false"
    assert action["inputs"]["mcpb-path"]["default"] == ""
    assert action["inputs"]["mcpb-fail-on"]["default"] == ""
    assert action["inputs"]["mcpb-sarif-output"]["default"] == ""
    steps = {step["name"]: step for step in action["runs"]["steps"]}
    assert steps["Install SkillGate"]["run"] == 'python -m pip install "${{ github.action_path }}"'
    assert steps["Run SkillGate policy check"]["if"] == "${{ inputs.policy != '' }}"
    assert steps["Run SkillGate scan"]["if"] == "${{ inputs.policy == '' }}"
    assert steps["Run SkillGate baseline diff without policy"]["if"] == (
        "${{ inputs.baseline != '' && inputs.policy == '' && inputs.fail-on-drift != 'true' }}"
    )
    assert steps["Run SkillGate baseline diff without policy"]["run"] == (
        'skillgate diff "${{ inputs.path }}" --baseline "${{ inputs.baseline }}"'
    )
    assert steps["Run blocking SkillGate baseline diff without policy"]["if"] == (
        "${{ inputs.baseline != '' && inputs.policy == '' && inputs.fail-on-drift == 'true' }}"
    )
    assert steps["Run blocking SkillGate baseline diff without policy"]["run"] == (
        'skillgate diff "${{ inputs.path }}" --baseline "${{ inputs.baseline }}" --fail-on-drift'
    )
    assert action_text.count("--fail-on-drift") == 1
    assert steps["Generate policy-aware SARIF"]["if"] == (
        "${{ always() && inputs.sarif-output != '' && inputs.policy != '' }}"
    )
    assert "--dry-run" in steps["Generate policy-aware SARIF"]["run"]
    assert "--format sarif" in steps["Generate policy-aware SARIF"]["run"]
    assert steps["Generate policy-aware SARIF"]["run"].startswith("skillgate check ")
    assert steps["Generate SARIF"]["if"] == (
        "${{ always() && inputs.sarif-output != '' && inputs.policy == '' }}"
    )
    assert steps["Run SkillGate MCPB scan"]["if"] == "${{ inputs.mcpb-path != '' }}"
    assert 'args=(mcpb scan "${{ inputs.mcpb-path }}")' in steps["Run SkillGate MCPB scan"]["run"]
    assert "--fail-on" in steps["Run SkillGate MCPB scan"]["run"]
    assert steps["Generate MCPB SARIF"]["if"] == (
        "${{ always() && inputs.mcpb-path != '' && inputs.mcpb-sarif-output != '' }}"
    )
    assert "--format sarif" in steps["Generate MCPB SARIF"]["run"]
    assert "${{ inputs.mcpb-sarif-output }}" in steps["Generate MCPB SARIF"]["run"]
    assert steps["Generate SkillGate review summary"]["if"] == (
        "${{ always() && (inputs.summary-output != '' || inputs.json-output != '' || "
        "inputs.step-summary == 'true') }}"
    )
    assert 'skillgate "${args[@]}"' in steps["Generate SkillGate review summary"]["run"]
    assert "--json-output" in steps["Generate SkillGate review summary"]["run"]
    assert "$GITHUB_STEP_SUMMARY" in steps["Generate SkillGate review summary"]["run"]
    step_names = [step["name"] for step in action["runs"]["steps"]]
    assert step_names.index("Run SkillGate policy check") < step_names.index(
        "Generate policy-aware SARIF"
    )
    assert step_names.index("Generate SARIF") < step_names.index(
        "Generate SkillGate review summary"
    )
    assert step_names.index("Run SkillGate MCPB scan") < step_names.index("Generate MCPB SARIF")
    assert step_names.index("Generate MCPB SARIF") < step_names.index(
        "Generate SkillGate review summary"
    )


def test_docs_are_main_branch_and_discovery_friendly() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    workflow_text = (ROOT / ".github" / "workflows" / "skillgate.yml").read_text()
    workflow = yaml.safe_load(workflow_text)
    discovery = (ROOT / "docs" / "discovery.md").read_text(encoding="utf-8")
    action_examples = (ROOT / "docs" / "examples" / "github-action-minimal.md").read_text(
        encoding="utf-8"
    )
    dependabot = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    assert "branch=main" in readme
    assert "## Start With Pre-Install Review" in readme
    assert "skillgate review preinstall SOURCE --json-output skillgate-review.json" in readme
    assert "## Start With Three Direct Scans" in readme
    assert "docs/public-scan-reports/README.md" in readme
    assert "Stable compatibility channel: `v0`" in readme
    assert "docs/examples/github-action-minimal.md" in readme
    assert "## Try The Local Demos" in readme
    assert "skillgate demo skill --output test-outputs/reviewable-demo --validate --scan" in readme
    assert "skillgate demo mcpb --output test-outputs/reviewable-node.mcpb --scan" in readme
    assert "skillgate --version" in readme
    assert "SHA-256: 6948b641f88671717de7142ce075f21f9710621392b115a311eee05831fe5a1c" in readme
    assert "refs/tags/v0" in readme
    assert 'SkillGate.git@v0"' in readme
    assert "SkillGate.git@v0.1.1" not in readme
    assert "latest compatible GitHub release tag" in readme
    assert "img.shields.io/github/v/release/charliechenye/SkillGate" in readme
    assert "analysis-static" in readme
    assert "runtime-no%20execution" in readme
    assert "policy-as%20code" in readme
    assert "img.shields.io/github/stars" not in readme
    assert "img.shields.io/github/issues" not in readme
    assert "img.shields.io/github/forks" not in readme
    assert "--fail-on-drift" in readme
    assert "## SEO And Agent Discovery" not in readme
    assert "openevalgate-skillgate" in readme
    assert "policy-aware SARIF" in readme
    assert "AI-agent security scanner" in discovery
    assert "SkillGate generates SARIF" in action_examples
    assert "GitHub's upload action" in action_examples
    assert "uploads that SARIF file" in action_examples
    assert "mcpb-path: dist/server.mcpb" in action_examples
    assert "docs/sessions/README.md" in readme
    assert "mcpb-sarif-output: skillgate-mcpb.sarif" in action_examples
    workflow_steps = {
        step["name"]: step for step in workflow["jobs"]["skillgate"]["steps"] if "name" in step
    }
    assert workflow_steps["Run Node wrapper tests"]["run"] == "npm test"
    assert workflow_steps["Upload SARIF review artifact"]["uses"] == ("actions/upload-artifact@v7")
    assert workflow_steps["Upload SARIF to GitHub Code Scanning"]["if"] == (
        "github.event_name != 'pull_request' && always()"
    )
    assert action_examples.count("name: SkillGate") == 4
    assert action_examples.count("security-events: write") == 4
    assert action_examples.count("sarif-output: skillgate.sarif") == 4
    assert action_examples.count('step-summary: "true"') == 4
    assert action_examples.count("json-output: skillgate-review.json") == 4
    assert action_examples.count("github/codeql-action/upload-sarif@v4") == 5
    assert action_examples.count("actions/upload-artifact@v7") == 4
    assert "actions/upload-artifact@v4" not in action_examples
    assert "actions/upload-artifact@v6" not in action_examples
    assert "actions/download-artifact@v4" not in action_examples
    assert action_examples.count("if: always()") == 4
    assert action_examples.count("if: github.event_name != 'pull_request' && always()") == 5
    assert 'fail-on-drift: "true"' in action_examples
    assert workflow["jobs"]["skillgate"]["env"]["FORCE_JAVASCRIPT_ACTIONS_TO_NODE24"] is True
    assert "actions/upload-artifact@v7" in workflow_text
    assert "actions/upload-artifact@v4" not in workflow_text
    assert "actions/upload-artifact@v6" not in workflow_text
    assert "ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION" not in workflow_text
    assert dependabot["version"] == 2
    assert {
        item["package-ecosystem"]: item["schedule"]["interval"] for item in dependabot["updates"]
    } == {"github-actions": "weekly", "pip": "weekly"}
    workflow_triggers = workflow.get("on") or workflow.get(True)
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow_triggers["push"]["branches"] == ["main"]
    compatibility = workflow["jobs"]["python-compatibility"]
    assert compatibility["strategy"]["matrix"]["python-version"] == ["3.11", "3.13"]
    assert compatibility["steps"][-1]["run"] == "uv run pytest"
    package_steps = {
        step["name"]: step for step in workflow["jobs"]["package-smoke"]["steps"] if "name" in step
    }
    assert package_steps["Build package"]["run"] == "uv build --out-dir test-outputs/dist"
    assert "twine check test-outputs/dist/*" in package_steps["Check distributions"]["run"]
    assert "skillgate/py.typed" in package_steps["Verify typed package marker"]["run"]
    assert (
        "review preinstall examples/preinstall-starter"
        in package_steps["Run clean-install smoke tests"]["run"]
    )


def test_contributing_documents_rule_fixture_test_workflow() -> None:
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    for phrase in [
        "stable rule ID",
        "rule documentation registry",
        "expected-findings.yaml",
        "focused regression test",
        "golden snapshots",
        "do not vendor upstream content verbatim",
    ]:
        assert phrase in contributing


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
        ("19-public-pattern-plugin-hooks", {"SG001", "SG003", "SG004", "SG006"}),
        ("20-public-pattern-marketplace-mcp-package", {"SG003", "SG009"}),
        ("21-public-pattern-agent-command-pack", {"SG003", "SG006"}),
        ("22-public-pattern-mcp-local-bridge", {"SG003", "SG009"}),
        ("23-public-pattern-skill-tool-metadata", {"SG007"}),
        ("24-public-pattern-mcp-tool-metadata-risk", {"SG003", "SG007", "SG011"}),
        ("25-public-pattern-mcp-app-web-surface", {"SG003", "SG011"}),
        ("26-public-pattern-mcp-dangerous-transport", {"SG001", "SG003", "SG012"}),
        ("27-public-pattern-mcp-registry-package-metadata", {"SG003", "SG012"}),
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
