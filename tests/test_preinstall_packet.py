from __future__ import annotations

import json
from pathlib import Path

from conftest import FIXTURES, ROOT
from jsonschema import Draft202012Validator

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


def test_preinstall_packet_snapshots_are_deterministic() -> None:
    built = packet()
    assert preinstall_packet_json(built) == (SNAPSHOTS / "preinstall_packet.json").read_text(
        encoding="utf-8"
    )
    assert render_preinstall_markdown(built) == (SNAPSHOTS / "preinstall_packet.txt").read_text(
        encoding="utf-8"
    )
