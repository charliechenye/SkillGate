from __future__ import annotations

import hashlib

from conftest import ROOT, clean_test_dir

from skillgate.mcpb.scan import scan_mcpb
from tools.build_demo_mcpb import DEFAULT_SOURCE, build_demo_mcpb

DEMO_MCPB_SHA256 = "6948b641f88671717de7142ce075f21f9710621392b115a311eee05831fe5a1c"


def test_demo_mcpb_builder_is_deterministic_and_reviewable() -> None:
    workdir = clean_test_dir("demo-mcpb-builder")
    first = workdir / "first.mcpb"
    second = workdir / "second.mcpb"

    build_demo_mcpb(DEFAULT_SOURCE, first)
    build_demo_mcpb(DEFAULT_SOURCE, second)

    first_hash = hashlib.sha256(first.read_bytes()).hexdigest()
    second_hash = hashlib.sha256(second.read_bytes()).hexdigest()
    assert first_hash == DEMO_MCPB_SHA256
    assert second_hash == DEMO_MCPB_SHA256

    result = scan_mcpb(first)
    assert result.bundle_manifest.archive.sha256 == DEMO_MCPB_SHA256
    assert result.bundle_manifest.manifest.name == "reviewable-node"
    assert result.bundle_manifest.manifest.runtime_endpoints == ["https://api.example.invalid/v1"]
    assert {finding.rule_id for finding in result.scan_report.findings} == {"SG003", "SG005"}
    assert result.scan_report.summary["findings"] == 4


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
    assert "What SkillGate Cannot Conclude" in mcpb
