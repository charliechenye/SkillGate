from __future__ import annotations

import json

from conftest import FIXTURES, ROOT, runner

from skillgate.baseline import create_baseline, diff_against_baseline
from skillgate.cli import app
from skillgate.mcp_compatibility import inventory_mcp_compatibility
from skillgate.mcp_registry import compare_registry_metadata
from skillgate.preinstall import build_preinstall_packet, render_preinstall_markdown
from skillgate.scan import scan_repository

COMPATIBILITY_FIXTURE = FIXTURES / "28-mcp-compatibility-inventory"
MCP_COMPATIBILITY_FIXTURES = ROOT / "fixtures" / "mcp-compatibility"


def test_inventory_uses_explicit_declarations_and_redacts_unknown_values() -> None:
    inventory = inventory_mcp_compatibility(
        {
            "version": "literal-secret-value",
            "protocolVersions": ["2026-07-28", "TOKEN=literal-secret"],
            "_meta": {
                "io.modelcontextprotocol/clientCapabilities": {
                    "extensions": {
                        "io.modelcontextprotocol/ui": {"version": "1.0.0"},
                        "not-a-reverse-dns-id": {"token": "literal-secret-value"},
                    }
                }
            },
            "extensions": {"com.example/bad-version": {"version": "TOKEN=literal-secret"}},
        },
        declaration_path="server",
        scope="registry:example",
    )

    assert [item.version for item in inventory.protocol_versions] == ["2026-07-28"]
    assert [(item.identifier, item.version) for item in inventory.extensions] == [
        ("com.example/bad-version", None),
        ("io.modelcontextprotocol/ui", "1.0.0"),
    ]
    assert {item.reason for item in inventory.unknown_declarations} == {
        "invalid_extension_id",
        "invalid_extension_version",
        "invalid_protocol_version",
    }
    assert "literal-secret-value" not in repr(inventory)


def test_scan_inventory_is_advisory_and_preserves_mcp_server_drift_details() -> None:
    report = scan_repository(COMPATIBILITY_FIXTURE)
    capabilities = {item.type: [] for item in report.capabilities}
    for capability in report.capabilities:
        capabilities[capability.type].append(capability)

    assert {item.resource for item in capabilities["mcp_protocol_version"]} == {"2026-07-28"}
    assert {item.resource for item in capabilities["mcp_extension"]} == {
        "com.example/audit",
        "com.example/tasks",
        "io.modelcontextprotocol/ui",
    }
    assert capabilities["mcp_unknown_declaration"]
    assert {finding.rule_id for finding in report.findings} == {"SG003", "SG009"}
    server = next(item for item in report.capabilities if item.type == "mcp_server")
    assert server.details["protocol_versions"] == ["2026-07-28"]
    assert {item["id"] for item in server.details["extensions"]} == {
        "com.example/tasks",
        "io.modelcontextprotocol/ui",
    }


def test_preinstall_packet_exposes_compatibility_evidence_without_schema_bump() -> None:
    report = scan_repository(COMPATIBILITY_FIXTURE)
    packet = build_preinstall_packet(
        {
            "kind": "local",
            "reference": str(COMPATIBILITY_FIXTURE),
            "path": str(COMPATIBILITY_FIXTURE),
        },
        report,
    )

    evidence = packet["metadata"]["mcp_compatibility"]
    assert packet["schema_version"] == "2"
    assert {item["version"] for item in evidence["protocol_versions"]} == {"2026-07-28"}
    assert {item["id"] for item in evidence["extensions"]} == {
        "com.example/audit",
        "com.example/tasks",
        "io.modelcontextprotocol/ui",
    }
    assert evidence["unknown_declarations"]
    assert "## MCP Compatibility" in render_preinstall_markdown(packet)
    assert "unknown MCP compatibility declarations" in "\n".join(packet["reviewer"]["next_actions"])


def test_compatibility_changes_produce_mcp_baseline_drift() -> None:
    baseline = create_baseline(MCP_COMPATIBILITY_FIXTURES / "baseline-before")
    diff, _report = diff_against_baseline(MCP_COMPATIBILITY_FIXTURES / "baseline-after", baseline)

    finding = next(item for item in diff.findings if item.rule_id == "SG010")
    assert "extensions" in (finding.evidence or "")
    assert {item.type for item in diff.added_capabilities} >= {"mcp_extension"}


def test_registry_comparison_reports_extension_drift_from_local_fixture() -> None:
    report = compare_registry_metadata(
        MCP_COMPATIBILITY_FIXTURES / "registry" / "local",
        "io.example.compatibility",
        str(MCP_COMPATIBILITY_FIXTURES / "registry" / "registry.json"),
    )

    drift = report.summary["registry_drift"]
    assert {item["field"] for item in drift} == {"extensions"}
    assert any(item.rule_id == "SG013" for item in report.findings)


def test_cli_preinstall_compatibility_packet_is_json_and_no_execution(tmp_path) -> None:
    output = tmp_path / "packet.json"
    result = runner.invoke(
        app,
        [
            "review",
            "preinstall",
            str(COMPATIBILITY_FIXTURE),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    packet = json.loads(output.read_text(encoding="utf-8"))
    assert packet["reviewer"]["no_execution"] is True
    assert packet["metadata"]["mcp_compatibility"]["extensions"]
