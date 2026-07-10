from __future__ import annotations

import json

from conftest import ROOT, runner

from skillgate.cli import app
from skillgate.demo import build_demo_mcpb

SKILLS_FIXTURES = ROOT / "fixtures" / "skills-validation"


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
    json_output = tmp_path / "review.json"
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
