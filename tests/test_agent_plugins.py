from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import ROOT

from skillgate.agent_plugins import (
    MCP_SCHEMA,
    PLUGIN_SCHEMA,
    agent_plugin_to_data,
    load_agent_plugin,
)

FIXTURES = ROOT / "fixtures" / "agent-plugins"


def manifest(name: str = "test-plugin", **extra: object) -> dict[str, object]:
    return {"$schema": PLUGIN_SCHEMA, "name": name, **extra}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def plugin(tmp_path: Path, data: dict[str, object] | None = None) -> Path:
    root = tmp_path / "plugin"
    root.mkdir(parents=True)
    write_json(root / "plugin.json", data or manifest())
    return root


def test_minimal_plugin_loads_with_complete_portable_and_overall_coverage() -> None:
    inventory = load_agent_plugin(FIXTURES / "valid-minimal")

    assert inventory.format == "agent_plugins"
    assert inventory.spec_version == "1.0.0"
    assert inventory.status == "loaded"
    assert inventory.manifest.status == "valid"
    assert inventory.manifest.name == "minimal-plugin"
    assert inventory.skills == ()
    assert inventory.mcp.status == "absent"
    assert inventory.coverage.portable_core == "COMPLETE"
    assert inventory.coverage.overall_artifact == "COMPLETE"


def test_skills_use_immediate_child_discovery_only() -> None:
    inventory = load_agent_plugin(FIXTURES / "skills-only")

    assert [skill.path for skill in inventory.skills] == ["skills/summarize/SKILL.md"]
    assert inventory.skills[0].name == "summarize"
    assert inventory.skills[0].status == "valid"
    assert inventory.coverage.portable_core == "COMPLETE"


def test_mcp_inventory_keeps_transports_and_does_not_connect() -> None:
    inventory = load_agent_plugin(FIXTURES / "mcp-only")

    assert inventory.mcp.status == "valid"
    assert [(server.name, server.transport, server.status) for server in inventory.mcp.servers] == [
        ("local", "stdio", "valid"),
        ("remote", "streamable-http", "valid"),
    ]
    assert inventory.coverage.portable_core == "COMPLETE"


def test_compound_plugin_retains_extension_unknown_surface_and_provenance() -> None:
    inventory = load_agent_plugin(FIXTURES / "compound")

    assert len(inventory.skills) == 1
    assert inventory.mcp.servers[0].name == "reviewer"
    assert inventory.extensions[0].namespace == "com.github.copilot"
    assert inventory.extensions[0].manifest_data_present is True
    assert inventory.extensions[0].directory_present is True
    assert inventory.coverage.portable_core == "COMPLETE"
    assert inventory.coverage.overall_artifact == "INCOMPLETE"
    assert "com.github.copilot" in inventory.unknown_surfaces
    assert any(entry.component == "mcp_server" for entry in inventory.provenance.entries)


def test_unknown_manifest_field_is_non_fatal_and_ignored(tmp_path: Path) -> None:
    root = plugin(tmp_path, {**manifest(), "futureField": {"opaque": True}})

    inventory = load_agent_plugin(root)

    assert inventory.manifest.status == "valid"
    assert inventory.coverage.overall_artifact == "COMPLETE"
    assert any(item.code == "manifest_unknown_field" for item in inventory.diagnostics)


def test_non_object_extensions_is_non_fatal_and_does_not_hide_components(tmp_path: Path) -> None:
    root = plugin(tmp_path, {**manifest(), "extensions": ["ignored"]})
    (root / "skills" / "one").mkdir(parents=True)
    (root / "skills" / "one" / "SKILL.md").write_text(
        "---\nname: one\ndescription: One\nlicense: MIT\ncompatibility: local\n---\n",
        encoding="utf-8",
    )

    inventory = load_agent_plugin(root)

    assert inventory.manifest.status == "valid"
    assert [skill.name for skill in inventory.skills] == ["one"]
    assert any(item.code == "manifest_extensions_ignored" for item in inventory.diagnostics)


@pytest.mark.parametrize(
    ("case", "data", "expected_code"),
    [
        ("missing-schema", {"name": "test-plugin"}, "manifest_missing_schema"),
        (
            "unsupported-schema",
            {"$schema": "https://example.invalid/plugin.json", "name": "test-plugin"},
            "manifest_unsupported_schema",
        ),
        ("bad-name", manifest("Bad Name"), "manifest_invalid_name"),
        ("bad-author", {**manifest(), "author": {"name": 3}}, "manifest_invalid_field"),
        ("bad-keywords", {**manifest(), "keywords": ["ok", 3]}, "manifest_invalid_field"),
    ],
)
def test_fatal_manifest_validation_rejects_components(
    tmp_path: Path,
    case: str,
    data: dict[str, object],
    expected_code: str,
) -> None:
    root = plugin(tmp_path / case, data)
    (root / "skills").mkdir()
    (root / "skills" / "ignored").mkdir()

    inventory = load_agent_plugin(root)

    assert inventory.status == "rejected"
    assert inventory.manifest.status == "invalid"
    assert inventory.skills == ()
    assert inventory.mcp.status == "not_applicable"
    assert any(item.code == expected_code for item in inventory.diagnostics)
    assert inventory.coverage.portable_core == "REJECTED"


def test_invalid_json_and_non_object_manifest_are_rejected(tmp_path: Path) -> None:
    invalid_json = tmp_path / "invalid-json"
    invalid_json.mkdir()
    (invalid_json / "plugin.json").write_text("{", encoding="utf-8")
    non_object = tmp_path / "non-object"
    non_object.mkdir()
    (non_object / "plugin.json").write_text("[]", encoding="utf-8")

    invalid_inventory = load_agent_plugin(invalid_json)
    non_object_inventory = load_agent_plugin(non_object)

    assert invalid_inventory.status == non_object_inventory.status == "rejected"
    assert any(item.code == "json_invalid" for item in invalid_inventory.diagnostics)
    assert any(item.code == "manifest_not_object" for item in non_object_inventory.diagnostics)


def test_missing_skills_location_is_valid(tmp_path: Path) -> None:
    inventory = load_agent_plugin(plugin(tmp_path))

    assert inventory.skills_status == "absent"
    assert inventory.coverage.portable_core == "COMPLETE"


def test_skills_wrong_filesystem_kind_invalidates_only_skills(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    (root / "skills").write_text("not a directory", encoding="utf-8")

    inventory = load_agent_plugin(root)

    assert inventory.skills_status == "invalid"
    assert inventory.mcp.status == "absent"
    assert inventory.coverage.portable_core == "INCOMPLETE"
    assert any(item.code == "skills_location_invalid" for item in inventory.diagnostics)


def test_invalid_skill_does_not_erase_valid_skill(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    valid = root / "skills" / "valid"
    invalid = root / "skills" / "invalid"
    valid.mkdir(parents=True)
    invalid.mkdir(parents=True)
    (valid / "SKILL.md").write_text(
        "---\nname: valid\ndescription: Valid\nlicense: MIT\ncompatibility: local\n---\n",
        encoding="utf-8",
    )
    (invalid / "SKILL.md").write_text("not frontmatter", encoding="utf-8")

    inventory = load_agent_plugin(root)

    assert [(skill.path, skill.status) for skill in inventory.skills] == [
        ("skills/invalid/SKILL.md", "invalid"),
        ("skills/valid/SKILL.md", "valid"),
    ]
    assert inventory.coverage.portable_core == "INCOMPLETE"


def test_malformed_mcp_top_level_does_not_erase_skills(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    (root / "skills" / "valid").mkdir(parents=True)
    (root / "skills" / "valid" / "SKILL.md").write_text(
        "---\nname: valid\ndescription: Valid\nlicense: MIT\ncompatibility: local\n---\n",
        encoding="utf-8",
    )
    write_json(root / "mcp.json", {"$schema": MCP_SCHEMA, "mcpServers": []})

    inventory = load_agent_plugin(root)

    assert inventory.skills[0].status == "valid"
    assert inventory.mcp.status == "invalid"
    assert inventory.coverage.portable_core == "INCOMPLETE"


def test_mcp_schema_mismatch_invalidates_mcp_only(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_json(
        root / "mcp.json",
        {"$schema": "https://agent-plugins.org/schemas/2.0.0/mcp.schema.json", "mcpServers": {}},
    )

    inventory = load_agent_plugin(root)

    assert inventory.mcp.status == "invalid"
    assert inventory.coverage.portable_core == "INCOMPLETE"
    assert any(item.code == "mcp_schema_mismatch" for item in inventory.diagnostics)


def test_invalid_mcp_server_preserves_valid_sibling(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_json(
        root / "mcp.json",
        {
            "$schema": MCP_SCHEMA,
            "mcpServers": {
                "good": {"type": "stdio", "command": "node"},
                "bad": {"type": "stdio", "command": "./../escape"},
            },
        },
    )

    inventory = load_agent_plugin(root)

    assert [(server.name, server.status) for server in inventory.mcp.servers] == [
        ("bad", "invalid"),
        ("good", "valid"),
    ]
    assert inventory.coverage.portable_core == "INCOMPLETE"


@pytest.mark.parametrize(
    "server",
    [
        {"type": "stdio", "command": "./../escape"},
        {"type": "stdio", "command": "node", "cwd": "../escape"},
        {"type": "stdio", "command": "node", "cwd": "${PLUGIN_DATA}/../escape"},
        {"type": "stdio", "command": "node", "env": {"PLUGIN_ROOT": "bad"}},
        {"type": "stdio", "command": "node --bad"},
    ],
)
def test_stdio_static_containment_and_reserved_env_are_per_server(
    tmp_path: Path,
    server: dict[str, object],
) -> None:
    root = plugin(tmp_path)
    write_json(root / "mcp.json", {"$schema": MCP_SCHEMA, "mcpServers": {"bad": server}})

    inventory = load_agent_plugin(root)

    assert inventory.mcp.servers[0].status == "invalid"
    assert inventory.coverage.portable_core == "INCOMPLETE"


def test_mcp_http_url_and_headers_are_structurally_valid(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_json(
        root / "mcp.json",
        {
            "$schema": MCP_SCHEMA,
            "mcpServers": {
                "local": {"type": "sse", "url": "http://localhost/mcp"},
                "remote": {
                    "type": "streamable-http",
                    "url": "https://example.com/mcp",
                    "headers": {"X-Test": "value"},
                },
            },
        },
    )

    inventory = load_agent_plugin(root)

    assert all(server.status == "valid" for server in inventory.mcp.servers)


def test_client_extension_directory_without_manifest_data_is_unknown(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    (root / "com.example.client").mkdir()

    inventory = load_agent_plugin(root)

    assert inventory.extensions[0].namespace == "com.example.client"
    assert inventory.extensions[0].manifest_data_present is False
    assert inventory.extensions[0].directory_present is True
    assert inventory.coverage.portable_core == "COMPLETE"
    assert inventory.coverage.overall_artifact == "INCOMPLETE"


def test_unclassified_top_level_directory_is_unknown_not_a_portable_component(
    tmp_path: Path,
) -> None:
    root = plugin(tmp_path)
    (root / "vendor-data").mkdir()

    inventory = load_agent_plugin(root)

    assert "vendor-data" in inventory.unknown_surfaces
    assert not inventory.extensions
    assert inventory.coverage.overall_artifact == "INCOMPLETE"


def test_plugin_json_does_not_read_inline_or_alternate_mcp_paths(tmp_path: Path) -> None:
    root = plugin(tmp_path, {**manifest(), "mcpServers": {"ignored": {}}})
    (root / ".github").mkdir()
    write_json(root / ".github" / "mcp.json", {"mcpServers": {"ignored": {}}})

    inventory = load_agent_plugin(root)

    assert inventory.status == "loaded"
    assert inventory.mcp.status == "absent"
    assert inventory.skills == ()
    assert any(item.code == "manifest_unknown_field" for item in inventory.diagnostics)


def test_manifest_without_canonical_schema_does_not_fall_through_to_legacy(tmp_path: Path) -> None:
    root = plugin(tmp_path, {"name": "legacy-looking", "mcpServers": {"ignored": {}}})

    inventory = load_agent_plugin(root)

    assert inventory.status == "rejected"
    assert inventory.mcp.status == "not_applicable"
    assert inventory.skills == ()


def test_plugin_manifest_symlink_escape_rejects_interpretation(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(manifest("outside")), encoding="utf-8")
    (root / "plugin.json").unlink()
    (root / "plugin.json").symlink_to(outside)

    inventory = load_agent_plugin(root)

    assert inventory.status == "rejected"
    assert any(item.code == "manifest_path_outside_plugin_root" for item in inventory.diagnostics)


def test_skills_location_symlink_escape_is_component_invalid(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    outside = tmp_path / "outside-skills"
    outside.mkdir()
    (root / "skills").symlink_to(outside, target_is_directory=True)

    inventory = load_agent_plugin(root)

    assert inventory.skills_status == "invalid"
    assert inventory.coverage.portable_core == "INCOMPLETE"


def test_discovered_skill_symlink_escape_is_skipped(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    skills = root / "skills"
    skills.mkdir()
    outside = tmp_path / "outside-skill"
    outside.mkdir()
    (outside / "SKILL.md").write_text(
        "---\nname: outside\ndescription: Outside\n---\n", encoding="utf-8"
    )
    (skills / "escape").mkdir()
    (skills / "escape" / "SKILL.md").symlink_to(outside / "SKILL.md")

    inventory = load_agent_plugin(root)

    assert inventory.skills[0].status == "skipped"
    assert inventory.coverage.portable_core == "INCOMPLETE"


def test_mcp_location_symlink_escape_is_component_invalid(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    outside = tmp_path / "outside-mcp.json"
    write_json(outside, {"$schema": MCP_SCHEMA, "mcpServers": {}})
    (root / "mcp.json").symlink_to(outside)

    inventory = load_agent_plugin(root)

    assert inventory.mcp.status == "invalid"
    assert inventory.coverage.portable_core == "INCOMPLETE"
    assert any(item.code == "mcp_path_outside_plugin_root" for item in inventory.diagnostics)


def test_mcp_wrong_filesystem_kind_is_component_invalid(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    (root / "mcp.json").mkdir()

    inventory = load_agent_plugin(root)

    assert inventory.mcp.status == "invalid"
    assert any(item.code == "mcp_location_invalid" for item in inventory.diagnostics)


def test_inventory_data_is_deterministic_and_not_a_public_schema() -> None:
    first = agent_plugin_to_data(load_agent_plugin(FIXTURES / "compound"))
    second = agent_plugin_to_data(load_agent_plugin(FIXTURES / "compound"))

    assert first == second
    assert first["format"] == "agent_plugins"
    assert "capabilities" not in first
