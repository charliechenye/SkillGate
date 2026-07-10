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
            "commit_sha": "0123456789abcdef0123456789abcdef01234567",
            "fetched_files": ["SKILL.md"],
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
    assert payload["source"]["revision"] == fake.manifest["commit_sha"]
    assert payload["source"]["metadata"]["fetched_files"] == ["SKILL.md"]
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
