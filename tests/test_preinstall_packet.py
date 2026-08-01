from __future__ import annotations

import json
from pathlib import Path

from conftest import FIXTURES, ROOT
from jsonschema import Draft202012Validator

from skillgate.baseline import create_baseline, diff_against_baseline
from skillgate.preinstall import (
    build_preinstall_packet,
    preinstall_packet_json,
    render_preinstall_markdown,
)
from skillgate.preinstall_schema import PREINSTALL_REVIEW_JSON_SCHEMA
from skillgate.scan import scan_repository

SNAPSHOTS = Path(__file__).parent / "snapshots"


def packet() -> dict[str, object]:
    root = FIXTURES / "05-remote-download-execute"
    return build_preinstall_packet(
        {
            "kind": "local",
            "reference": str(root),
            "path": str(root),
            "metadata": {"token": "super-secret-value", "owner_path": str(root / "private")},
        },
        scan_repository(root),
    )


def test_preinstall_packet_is_stable_and_redacted() -> None:
    first = packet()
    second = packet()
    assert first == second
    encoded = preinstall_packet_json(first)
    assert json.loads(encoded) == first
    assert "super-secret-value" not in encoded
    assert str(FIXTURES) not in encoded
    assert first["schema_version"] == "2"
    assert first["packet_digest"].startswith("sha256:")
    assert first["source_manifest"]["scanned_file_count"] == 2
    assert first["source_manifest"]["manifest_sha256"].startswith("sha256:")
    assert first["reviewer"]["no_execution"] is True
    assert first["findings"]["by_severity"]["high"] >= 1


def test_preinstall_packet_markdown_has_decision_sections() -> None:
    markdown = render_preinstall_markdown(packet())
    assert markdown.startswith("# SkillGate Pre-install Review\n")
    assert "## Capability Inventory" in markdown
    assert "## Decision Summary" in markdown
    assert "## Source Manifest" in markdown
    assert "## Findings By Severity" in markdown
    assert "## Reviewer Next Actions" in markdown
    assert "## Limitations" in markdown
    assert "No code was executed by the packet renderer." in markdown
    assert str(FIXTURES) not in markdown


def test_preinstall_schema_matches_packet_contract() -> None:
    packet_data = packet()
    schema = PREINSTALL_REVIEW_JSON_SCHEMA
    assert schema["properties"]["schema_version"] == {"const": "2"}
    assert set(schema["required"]) <= set(packet_data)
    assert packet_data["packet_digest"] == packet_data["packet_digest"].lower()


def test_committed_preinstall_schema_matches_export_and_validates_packets() -> None:
    committed = json.loads(
        (ROOT / "schemas" / "skillgate-review.schema.json").read_text(encoding="utf-8")
    )
    assert committed == PREINSTALL_REVIEW_JSON_SCHEMA

    validator = Draft202012Validator(committed)
    validator.validate(packet())

    mcp_packet = build_preinstall_packet(
        {
            "kind": "local",
            "reference": str(FIXTURES / "28-mcp-compatibility-inventory"),
            "path": str(FIXTURES / "28-mcp-compatibility-inventory"),
        },
        scan_repository(FIXTURES / "28-mcp-compatibility-inventory"),
    )
    validator.validate(mcp_packet)


def test_preinstall_packet_exposes_mcp_apps_evidence_and_actions(
    tmp_path: Path,
) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "example": {
                        "command": "node",
                        "_meta": {
                            "ui": {
                                "resourceUri": "ui://app/index.html",
                                "mimeType": "text/html;profile=mcp-app",
                                "csp": {"connect_domains": ["https://api.example.com"]},
                                "permissions": ["camera"],
                                "appCallableTools": [{"name": "search", "appCallable": True}],
                            }
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.html").write_text('<script src="app.js"></script>', encoding="utf-8")
    (app / "app.js").write_text("callServerTool('search')", encoding="utf-8")
    report = scan_repository(tmp_path)

    packet_data = build_preinstall_packet(
        {"kind": "local", "reference": str(tmp_path), "path": str(tmp_path)},
        report,
    )
    Draft202012Validator(PREINSTALL_REVIEW_JSON_SCHEMA).validate(packet_data)

    apps = packet_data["metadata"]["mcp_apps"]
    assert packet_data["schema_version"] == "2"
    assert apps["resources"]
    assert apps["assets"]
    assert apps["origins"]
    assert apps["permissions"]
    assert apps["tools"]
    assert apps["bridges"]
    assert any("UI-callable tool" in action for action in packet_data["reviewer"]["next_actions"])
    assert any("external origins" in action for action in packet_data["reviewer"]["next_actions"])
    markdown = render_preinstall_markdown(packet_data)
    assert "## MCP Apps" in markdown
    assert "### Resources" in markdown
    assert "### Bridges" in markdown
    assert "ui://app/index.html" in markdown
    assert "callServerTool" in markdown


def test_preinstall_packet_mcp_apps_redacts_unknowns_and_skipped_assets(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.json").write_text(
        json.dumps(
            {
                "server": {
                    "name": "io.example.bad-app",
                    "version": "1.0.0",
                    "_meta": {
                        "ui": {
                            "resourceUri": "TOKEN=literal-secret",
                            "mimeType": "text/html;profile=mcp-app",
                        }
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    packet_data = build_preinstall_packet(
        {"kind": "local", "reference": str(tmp_path), "path": str(tmp_path)},
        scan_repository(tmp_path),
    )

    encoded = preinstall_packet_json(packet_data)
    assert "literal-secret" not in encoded
    assert packet_data["metadata"]["mcp_apps"]["unknown_declarations"]
    assert any(
        "malformed or redacted MCP Apps declarations" in action
        for action in packet_data["reviewer"]["next_actions"]
    )


def test_mcp_apps_declarative_changes_produce_baseline_drift(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    config_path = root / ".mcp.json"
    before = {
        "mcpServers": {
            "example": {
                "command": "node",
                "_meta": {
                    "ui": {
                        "resourceUri": "ui://app/index.html",
                        "mimeType": "text/html;profile=mcp-app",
                    }
                },
            }
        }
    }
    config_path.write_text(json.dumps(before), encoding="utf-8")
    baseline = create_baseline(root)
    after = json.loads(json.dumps(before))
    after["mcpServers"]["example"]["_meta"]["ui"]["permissions"] = ["camera"]
    config_path.write_text(json.dumps(after), encoding="utf-8")

    diff, _report = diff_against_baseline(root, baseline)

    assert any(capability.type == "mcp_app_permission" for capability in diff.added_capabilities)
    finding = next(item for item in diff.findings if item.rule_id == "SG010")
    assert "mcp_apps" in (finding.evidence or "")


def test_preinstall_packet_snapshots_are_deterministic() -> None:
    built = packet()
    assert preinstall_packet_json(built) == (SNAPSHOTS / "preinstall_packet.json").read_text(
        encoding="utf-8"
    )
    assert render_preinstall_markdown(built) == (SNAPSHOTS / "preinstall_packet.txt").read_text(
        encoding="utf-8"
    )
