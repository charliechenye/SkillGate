from __future__ import annotations

import pytest
from conftest import FIXTURES, ROOT

from skillgate.identity import finding_fingerprint
from skillgate.sarif import FINGERPRINT_KEY, sarif_report
from skillgate.scan import scan_repository
from tests.snapshot_cases import SNAPSHOT_CASES, snapshot_output


def test_sarif_structure() -> None:
    report = scan_repository(FIXTURES / "05-remote-download-execute")
    sarif = sarif_report(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["automationDetails"]["id"] == "skillgate/local-repository"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "SkillGate"
    assert (
        sarif["runs"][0]["tool"]["driver"]["informationUri"]
        == "https://github.com/charliechenye/SkillGate"
    )
    assert sarif["runs"][0]["taxonomies"][0]["organization"] == "Chenye Zhu / SkillGate"
    assert sarif["runs"][0]["results"][0]["ruleId"]
    rules = {rule["id"]: rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "capability:remote_download_execution" in rules["SG004"]["properties"]["tags"]
    result = sarif["runs"][0]["results"][0]
    assert result["partialFingerprints"][FINGERPRINT_KEY]
    assert result["partialFingerprints"][FINGERPRINT_KEY].startswith("sha256:")
    assert result["properties"]["capability"]
    assert result["properties"]["severity"]
    assert result["taxa"][0]["toolComponent"]["name"] == "SkillGate capabilities"
    taxa = {item["id"] for item in sarif["runs"][0]["taxonomies"][0]["taxa"]}
    assert "network_egress" in taxa


def test_sarif_fingerprints_are_stable_across_line_shifts() -> None:
    report = scan_repository(FIXTURES / "05-remote-download-execute")
    finding = report.findings[0]
    shifted = finding.model_copy(update={"line_number": (finding.line_number or 1) + 20})
    changed = finding.model_copy(update={"evidence": f"{finding.evidence} changed"})
    base_report = report.model_copy(update={"findings": [finding]})
    shifted_report = report.model_copy(update={"findings": [shifted]})
    changed_report = report.model_copy(update={"findings": [changed]})

    first = sarif_report(base_report)["runs"][0]["results"][0]["partialFingerprints"][
        FINGERPRINT_KEY
    ]
    second = sarif_report(base_report)["runs"][0]["results"][0]["partialFingerprints"][
        FINGERPRINT_KEY
    ]
    line_shifted = sarif_report(shifted_report)["runs"][0]["results"][0]["partialFingerprints"][
        FINGERPRINT_KEY
    ]
    identity_changed = sarif_report(changed_report)["runs"][0]["results"][0]["partialFingerprints"][
        FINGERPRINT_KEY
    ]

    assert first == second
    assert first == line_shifted
    assert first != identity_changed
    assert first == finding_fingerprint(finding)


def test_sarif_run_categories() -> None:
    report = scan_repository(FIXTURES / "05-remote-download-execute")
    remote = sarif_report(report, category="remote_github")
    registry = sarif_report(report, category="mcp_registry_compare")
    bundle = sarif_report(report, category="mcp_bundle")
    assert remote["runs"][0]["automationDetails"]["id"] == "skillgate/remote-github"
    assert registry["runs"][0]["automationDetails"]["id"] == "skillgate/mcp-registry-compare"
    assert bundle["runs"][0]["automationDetails"]["id"] == "skillgate/mcp-bundle"


def test_sarif_includes_mcp_capability_tags_and_taxa() -> None:
    report = scan_repository(FIXTURES / "24-public-pattern-mcp-tool-metadata-risk")
    sarif = sarif_report(report)
    rules = {rule["id"]: rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "capability:mcp_tool_metadata" in rules["SG011"]["properties"]["tags"]
    result = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "SG011")
    assert "capability:mcp_tool_metadata" in result["properties"]["tags"]
    taxa = {item["id"] for item in sarif["runs"][0]["taxonomies"][0]["taxa"]}
    assert "mcp_tool_metadata" in taxa


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
