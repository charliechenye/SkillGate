from __future__ import annotations

import json
from pathlib import Path

import pytest

import skillgate.agent_plugin_capabilities as capability_module
from skillgate.agent_plugin_capabilities import (
    agent_plugin_capabilities_to_data,
    review_agent_plugin_capabilities,
)
from skillgate.agent_plugins import MCP_SCHEMA, PLUGIN_SCHEMA


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


def write_skill(root: Path, name: str, script: str | None = None, *, body: str = "") -> None:
    skill_root = root / "skills" / name
    skill_root.mkdir(parents=True)
    content = f"---\nname: {name}\ndescription: {name} skill\ncompatibility: local\n---\n{body}"
    (skill_root / "SKILL.md").write_text(content, encoding="utf-8")
    if script is not None:
        (skill_root / "scripts").mkdir()
        (skill_root / "scripts" / f"{name}.py").write_text(script, encoding="utf-8")


def write_mcp(root: Path, servers: dict[str, object]) -> None:
    write_json(root / "mcp.json", {"$schema": MCP_SCHEMA, "mcpServers": servers})


def component(review, kind: str, component_id: str):
    return next(
        item
        for item in review.components
        if item.component_kind == kind and item.component_id == component_id
    )


def test_skill_capability_uses_parent_component_and_plugin_relative_source_path(
    tmp_path: Path,
) -> None:
    root = plugin(tmp_path)
    write_skill(
        root,
        "deploy",
        'subprocess.run(["deploy"])\n',
        body="Run scripts/deploy.py.\n",
    )

    review = review_agent_plugin_capabilities(root)
    deploy = component(review, "skill", "deploy")

    assert deploy.capability_scan_status == "reviewed"
    assert deploy.scanned_files == ("skills/deploy/SKILL.md", "skills/deploy/scripts/deploy.py")
    assert {item.type for item in deploy.capabilities} == {"shell_execution"}
    assert deploy.capabilities[0].source_file == "skills/deploy/scripts/deploy.py"
    evidence = review.observed_capabilities[0].evidence[0]
    assert evidence.component_id == "deploy"
    assert evidence.component_path == "skills/deploy"
    assert evidence.source_file == "skills/deploy/scripts/deploy.py"


def test_two_skills_with_same_semantic_capability_keep_two_evidence_records(
    tmp_path: Path,
) -> None:
    root = plugin(tmp_path)
    script = 'requests.get("https://api.example.com/data")\n'
    write_skill(root, "first", script, body="Run scripts/first.py.\n")
    write_skill(root, "second", script, body="Run scripts/second.py.\n")

    review = review_agent_plugin_capabilities(root)
    network = [
        item
        for item in review.observed_capabilities
        if item.type == "network_egress" and item.resource == "api.example.com"
    ]

    assert len(network) == 1
    assert {item.component_id for item in network[0].evidence} == {"first", "second"}
    assert {item.source_file for item in network[0].evidence} == {
        "skills/first/scripts/first.py",
        "skills/second/scripts/second.py",
    }


def test_two_skills_with_different_capabilities_remain_distinct(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "shell", 'subprocess.run(["echo"])\n', body="Run scripts/shell.py.\n")
    write_skill(
        root,
        "network",
        'requests.get("https://api.example.com/data")\n',
        body="Run scripts/network.py.\n",
    )

    review = review_agent_plugin_capabilities(root)

    assert {item.type for item in review.observed_capabilities} == {
        "network_egress",
        "shell_execution",
    }


def test_valid_mcp_servers_are_attributed_and_mcp_capabilities_are_preserved(
    tmp_path: Path,
) -> None:
    root = plugin(tmp_path)
    write_mcp(
        root,
        {
            "local-tools": {
                "type": "stdio",
                "command": "bash",
                "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
            },
            "deployment": {
                "type": "streamable-http",
                "url": "https://deploy.example.com/mcp",
            },
        },
    )

    review = review_agent_plugin_capabilities(root)
    local = component(review, "mcp_server", "local-tools")
    remote = component(review, "mcp_server", "deployment")

    assert {item.type for item in local.capabilities} >= {
        "mcp_server",
        "shell_execution",
        "secret_access",
    }
    assert any(
        item.type == "network_egress" and item.resource == "deploy.example.com"
        for item in remote.capabilities
    )
    assert all(
        evidence.component_id in {"local-tools", "deployment", "mcp.json"}
        for item in review.observed_capabilities
        for evidence in item.evidence
    )


def test_invalid_mcp_server_contributes_no_capabilities_but_valid_sibling_survives(
    tmp_path: Path,
) -> None:
    root = plugin(tmp_path)
    write_mcp(
        root,
        {
            "good": {"type": "stdio", "command": "bash"},
            "bad": {"type": "stdio", "command": "./../escape"},
        },
    )

    review = review_agent_plugin_capabilities(root)
    good = component(review, "mcp_server", "good")
    bad = component(review, "mcp_server", "bad")

    assert good.capability_scan_status == "reviewed"
    assert any(item.type == "shell_execution" for item in good.capabilities)
    assert bad.capabilities == ()
    assert not any(
        evidence.component_id == "bad"
        for item in review.observed_capabilities
        for evidence in item.evidence
    )
    assert review.capability_coverage.portable_core == "INCOMPLETE"


def test_unknown_extension_and_package_surface_are_blind_spots_not_scanned(
    tmp_path: Path,
) -> None:
    root = plugin(
        tmp_path,
        {
            **manifest(),
            "extensions": {"com.example.client": {"opaque": True}},
        },
    )
    (root / "com.example.client").mkdir()
    (root / "com.example.client" / "run.py").write_text(
        'subprocess.run(["extension"])\n', encoding="utf-8"
    )
    (root / "payload.sh").write_text("bash payload.sh\n", encoding="utf-8")

    review = review_agent_plugin_capabilities(root)

    assert review.capability_coverage.portable_core == "COMPLETE"
    assert review.capability_coverage.overall_artifact == "INCOMPLETE"
    assert not any(
        evidence.source_file in {"payload.sh", "com.example.client/run.py"}
        for item in review.observed_capabilities
        for evidence in item.evidence
    )
    assert {item.component_id for item in review.blind_spots} >= {
        "com.example.client",
        "payload.sh",
    }


def test_invalid_skill_is_a_blind_spot_without_erasing_valid_sibling_capabilities(
    tmp_path: Path,
) -> None:
    root = plugin(tmp_path)
    write_skill(root, "valid", 'subprocess.run(["echo"])\n', body="Run scripts/valid.py.\n")
    invalid_root = root / "skills" / "invalid"
    invalid_root.mkdir(parents=True)
    (invalid_root / "SKILL.md").write_text("Read scripts/invalid.sh.\n", encoding="utf-8")
    (invalid_root / "scripts").mkdir()
    (invalid_root / "scripts" / "invalid.sh").write_text("bash invalid.sh\n", encoding="utf-8")

    review = review_agent_plugin_capabilities(root)
    invalid = component(review, "skill", "invalid")

    assert any(item.type == "shell_execution" for item in review.observed_capabilities)
    assert invalid.capabilities == ()
    assert invalid.capability_scan_status == "invalid"
    assert review.capability_coverage.portable_core == "INCOMPLETE"


def test_zero_capability_skill_is_reviewed_not_skipped(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "documentation", body="This skill contains no detectable capability.\n")

    review = review_agent_plugin_capabilities(root)
    documentation = component(review, "skill", "documentation")

    assert documentation.capability_scan_status == "reviewed"
    assert documentation.capabilities == ()
    assert review.capability_coverage.portable_core == "COMPLETE"


def test_capability_review_serialization_is_deterministic_and_relative(tmp_path: Path) -> None:
    first = plugin(tmp_path / "first")
    second = plugin(tmp_path / "second")
    for root in (first, second):
        write_skill(root, "same", 'subprocess.run(["echo"])\n', body="Run scripts/same.py.\n")

    first_data = agent_plugin_capabilities_to_data(review_agent_plugin_capabilities(first))
    second_data = agent_plugin_capabilities_to_data(review_agent_plugin_capabilities(second))

    assert first_data == second_data
    assert first_data["claim_scope"] == "observed_static_capabilities"
    assert first_data["lower_bound"] is True
    serialized = json.dumps(first_data, sort_keys=True)
    assert str(first) not in serialized
    assert str(second) not in serialized
    assert "observed_capabilities" in serialized
    assert all(
        not Path(evidence["source_file"]).is_absolute()
        for item in first_data["observed_capabilities"]
        for evidence in item["evidence"]
    )


def test_capability_scan_failure_isolated_to_one_skill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = plugin(tmp_path)
    write_skill(root, "good", 'subprocess.run(["echo"])\n', body="Run scripts/good.py.\n")
    write_skill(root, "bad", 'subprocess.run(["bad"])\n', body="Run scripts/bad.py.\n")
    real_scan_paths = capability_module.scan_paths

    def fail_bad_component(scan_root: Path, paths: list[Path]):
        if any("skills/bad/" in path.as_posix() for path in paths):
            raise RuntimeError("simulated scanner failure")
        return real_scan_paths(scan_root, paths)

    monkeypatch.setattr(capability_module, "scan_paths", fail_bad_component)

    review = review_agent_plugin_capabilities(root)
    good = component(review, "skill", "good")
    bad = component(review, "skill", "bad")

    assert any(item.type == "shell_execution" for item in good.capabilities)
    assert bad.capabilities == ()
    assert bad.capability_scan_status == "incomplete"
    assert review.capability_coverage.portable_core == "INCOMPLETE"
