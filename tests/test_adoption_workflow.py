from __future__ import annotations

import json
from pathlib import Path

import yaml
from conftest import FIXTURES, ROOT, runner

from skillgate.cli import app
from skillgate.demo import build_demo_mcpb
from skillgate.fixtures import fixture_summary_markdown, summarize_fixtures

STARTER = ROOT / "examples" / "preinstall-starter"


class FakeSparseResult:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.manifest = {
            "resolved_ref": "main",
            "resolved_commit_sha": "0123456789abcdef0123456789abcdef01234567",
            "downloaded_files": [
                {
                    "remote_path": "SKILL.md",
                    "materialized_path": "SKILL.md",
                    "sha256": "a" * 64,
                    "size_bytes": 8,
                    "reason": "relevant_path",
                }
            ],
        }
        self.cleaned = False

    def cleanup(self) -> None:
        self.cleaned = True


def test_starter_repository_has_clean_unified_review() -> None:
    result = runner.invoke(app, ["review", "preinstall", str(STARTER), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["source"]["kind"] == "local"
    assert payload["skills"]["validated"] is True
    assert payload["skills"]["summary"]["findings"] == 0
    assert payload["findings"]["by_severity"]["high"] == 0
    assert payload["reviewer"]["decision"] in {"no_findings", "review_required"}


def test_mocked_github_review_uses_immutable_manifest(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: remote-safe\ndescription: A safe remote fixture.\n---\n", encoding="utf-8"
    )
    fake = FakeSparseResult(tmp_path)
    monkeypatch.setattr("skillgate.cli.fetch_github_sparse", lambda _url: fake)
    result = runner.invoke(
        app,
        [
            "review",
            "preinstall",
            "https://github.com/example/repo/tree/main/skills",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["source"]["kind"] == "github"
    assert payload["source"]["revision"] == fake.manifest["resolved_commit_sha"]
    assert payload["source"]["metadata"]["downloaded_files"][0]["remote_path"] == "SKILL.md"
    assert fake.cleaned is True


def test_mcpb_review_and_explicit_fail_on_are_advisory_then_enforceable(tmp_path: Path) -> None:
    bundle = tmp_path / "reviewable.mcpb"
    build_demo_mcpb(bundle)
    bundle_result = runner.invoke(
        app,
        ["review", "preinstall", str(bundle), "--format", "json"],
    )
    assert bundle_result.exit_code == 0
    assert json.loads(bundle_result.output)["source"]["kind"] == "mcpb"

    finding_result = runner.invoke(
        app,
        [
            "review",
            "preinstall",
            str(FIXTURES / "05-remote-download-execute"),
            "--fail-on",
            "high",
        ],
    )
    assert finding_result.exit_code == 1
    assert "review_required" in finding_result.output
    assert "Review threshold failed" in finding_result.output


def test_benchmark_report_and_workflow_keep_pr_sarif_nonblocking() -> None:
    benchmark_root = Path("fixtures/benchmark")
    assert fixture_summary_markdown(benchmark_root, summarize_fixtures(benchmark_root)) == (
        ROOT / "docs" / "benchmark" / "0.1.3.md"
    ).read_text(encoding="utf-8")

    workflow = yaml.safe_load(
        (STARTER / ".github" / "workflows" / "skillgate-review.yml").read_text()
    )
    steps = workflow["jobs"]["review"]["steps"]
    artifact = next(step for step in steps if step.get("name") == "Upload review artifacts")
    publish = next(
        step
        for step in steps
        if step.get("name") == "Publish SARIF on protected branches and manual runs"
    )
    assert artifact["if"] == "always()"
    assert "skillgate.sarif" in artifact["with"]["path"]
    assert publish["if"] == "github.event_name != 'pull_request' && always()"


def test_docs_make_external_paths_explicit() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    starter = (STARTER / "README.md").read_text(encoding="utf-8")
    assert "The default path is local and upload-free" in readme
    assert "Nothing in a local SkillGate invocation uploads findings automatically." in readme
    assert "Connections are explicit opt-ins" in readme
    assert "This local command is the default starter path." in starter
    assert "workflow in `.github/workflows/skillgate-review.yml` is optional" in starter
    assert "local commands above." in starter


def test_adoption_discovery_docs_are_linked_from_readme() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    discovery = (ROOT / "docs" / "discovery.md").read_text(encoding="utf-8")
    assert "[Adoption guide](docs/adoption.md)" in readme
    assert "[llms.txt](llms.txt)" in readme
    assert "[recommendation guide](docs/recommendation-guide.md)" in readme
    assert "[SUPPORT.md](SUPPORT.md)" in readme
    assert "[repository settings checklist](docs/repository-settings.md)" in readme
    assert "[llms.txt](../llms.txt)" in discovery
    assert "[docs/adoption.md](adoption.md)" in discovery
    assert "[docs/recommendation-guide.md](recommendation-guide.md)" in discovery


def test_llms_txt_names_primary_commands_and_boundaries() -> None:
    llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
    for command in [
        "skillgate review preinstall SOURCE",
        "skillgate scan .",
        "skillgate github scan https://github.com/OWNER/REPO",
        "skillgate mcpb scan bundle.mcpb",
        "skillgate check . --policy skillgate.yaml",
    ]:
        assert command in llms
    assert "does not execute scanned code" in llms
    assert "install packages" in llms
    assert "start MCP servers" in llms
    assert "call LLM APIs" in llms
    assert "upload findings automatically" in llms


def test_contributing_uses_single_uv_setup_story() -> None:
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert contributing.count("## Development Setup") == 1
    assert "# Development setup" not in contributing
    assert 'python -m pip install -e ".[dev]"' not in contributing
    assert "uv sync --locked --group dev" in contributing
    assert "uv run pytest" in contributing
    assert "uv run ruff check ." in contributing
    assert "uv run ruff format --check ." in contributing
    assert "npm test" in contributing


def test_github_community_templates_exist_and_parse() -> None:
    pr_template = ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md"
    assert pr_template.exists()
    assert "SkillGate Invariants" in pr_template.read_text(encoding="utf-8")

    template_dir = ROOT / ".github" / "ISSUE_TEMPLATE"
    for name in [
        "bug_report.yml",
        "false_positive.yml",
        "rule_request.yml",
        "adoption_help.yml",
    ]:
        template = template_dir / name
        assert template.exists()
        payload = yaml.safe_load(template.read_text(encoding="utf-8"))
        assert payload["name"]
        assert payload["body"]

    assert (ROOT / "CODE_OF_CONDUCT.md").exists()
    assert (ROOT / "SUPPORT.md").exists()
