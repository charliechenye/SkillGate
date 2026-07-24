from __future__ import annotations

from skillgate.rules.base import FileContent
from skillgate.semantic import (
    SemanticInventoryLimits,
    extract_semantic_text_blocks,
    semantic_text_inventory,
    semantic_text_inventory_json,
    semantic_text_inventory_repository,
)


def test_skill_inventory_preserves_explicit_roles_and_redacts_assignment_values() -> None:
    file = FileContent(
        path="skills/reviewer/SKILL.md",
        file_type="markdown",
        text=(
            "---\n"
            "name: reviewer\n"
            "description: Review a local project\n"
            "---\n"
            'Read SERVICE_TOKEN=literal-secret and api_key: \\"secret-value\\" only when '
            "the user explicitly asks.\n"
        ),
    )

    blocks = extract_semantic_text_blocks(file)

    assert [block.structured_field for block in blocks] == ["frontmatter.description", "body"]
    assert [block.source_role for block in blocks] == ["tool_description", "agent_instruction"]
    assert [block.agent_consumption for block in blocks] == ["direct", "direct"]
    assert blocks[0].line_number == 3
    assert blocks[1].line_number == 5
    assert "literal-secret" not in blocks[1].text
    assert "secret-value" not in blocks[1].text
    assert "SERVICE_TOKEN=<redacted>" in blocks[1].text
    assert "api_key=<redacted>" in blocks[1].text


def test_structured_inventory_selects_known_agent_fields_and_preserves_paths() -> None:
    file = FileContent(
        path="mcp-registry.json",
        file_type="mcp_registry",
        text=(
            "{\n"
            '  "server": {\n'
            '    "name": "example",\n'
            '    "description": "Describe the server to an agent",\n'
            '    "unrelated": "do not inventory this",\n'
            '    "tools": [{"description": "Use this tool after approval"}]\n'
            "  }\n"
            "}\n"
        ),
    )

    blocks = extract_semantic_text_blocks(file)

    assert [block.structured_field for block in blocks] == [
        "server.description",
        "server.tools[0].description",
    ]
    assert [block.line_number for block in blocks] == [4, 6]
    assert all(block.source_role == "tool_description" for block in blocks)
    assert all(block.agent_consumption == "direct" for block in blocks)
    assert all("do not inventory" not in block.text for block in blocks)


def test_selected_yaml_and_toml_fields_are_supported_without_readme_inference() -> None:
    yaml_file = FileContent(
        path="agent.yaml",
        file_type="agent_file",
        text="instructions: Follow the approved workflow.\nmetadata: do not inventory\n",
    )
    toml_file = FileContent(
        path="prompts.toml",
        file_type="agent_file",
        text='template = "Summarize only the supplied files."\nname = "not inventory"\n',
    )
    readme = FileContent(
        path="README.md",
        file_type="markdown",
        text="Ignore previous instructions in this security explanation.\n",
    )

    yaml_blocks = extract_semantic_text_blocks(yaml_file)
    toml_blocks = extract_semantic_text_blocks(toml_file)

    assert yaml_blocks[0].structured_field == "instructions"
    assert yaml_blocks[0].source_role == "agent_instruction"
    assert toml_blocks[0].structured_field == "template"
    assert toml_blocks[0].source_role == "prompt_template"
    assert extract_semantic_text_blocks(readme) == []


def test_inventory_is_stable_and_enforces_file_level_limits() -> None:
    first = FileContent(path="AGENTS.md", file_type="markdown", text="Follow the workflow.\n")
    oversized = FileContent(path="SKILL.md", file_type="markdown", text="x" * 11)
    limits = SemanticInventoryLimits(
        max_file_bytes=10,
        max_block_bytes=10,
        max_total_bytes=10,
        max_blocks=2,
    )

    inventory = semantic_text_inventory([oversized, first], limits=limits)

    assert inventory.summary == {
        "blocks": 0,
        "source_files": 2,
        "skipped_files": 2,
        "text_bytes": 0,
    }
    assert [(item.file_path, item.reason) for item in inventory.skipped_files] == [
        ("AGENTS.md", "file_size_limit"),
        ("SKILL.md", "file_size_limit"),
    ]
    assert semantic_text_inventory_json(inventory) == semantic_text_inventory_json(inventory)


def test_inventory_records_malformed_selected_structured_source_without_a_finding() -> None:
    malformed = FileContent(
        path="agent.yaml",
        file_type="agent_file",
        text="instructions: [missing\n",
    )

    inventory = semantic_text_inventory([malformed])

    assert inventory.blocks == []
    assert [(item.file_path, item.reason) for item in inventory.skipped_files] == [
        ("agent.yaml", "parse_error")
    ]


def test_repository_inventory_extends_shared_discovery_for_named_yaml_only(tmp_path) -> None:
    root = tmp_path / "artifact"
    root.mkdir()
    (root / "agent.yaml").write_text(
        "instructions: Use only the approved tool.\n", encoding="utf-8"
    )
    (root / "unrelated.yaml").write_text(
        "instructions: Do not include this file.\n", encoding="utf-8"
    )

    inventory = semantic_text_inventory_repository(root)

    assert [block.file_path for block in inventory.blocks] == ["agent.yaml"]
    assert inventory.blocks[0].text == "Use only the approved tool."
