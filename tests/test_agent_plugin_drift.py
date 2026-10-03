from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import skillgate.agent_plugin_drift as drift_module
from skillgate.agent_plugin_capabilities import (
    AgentPluginCapabilityLimits,
    review_agent_plugin_capabilities,
)
from skillgate.agent_plugin_drift import (
    DRIFT_CHANGED,
    DRIFT_UNCHANGED,
    DRIFT_UNKNOWN,
    agent_plugin_drift_to_data,
    build_agent_plugin_drift_snapshot,
    compare_agent_plugin_drift,
)
from skillgate.agent_plugins import MCP_SCHEMA, PLUGIN_SCHEMA, load_agent_plugin


def manifest(name: str = "test-plugin", **extra: object) -> dict[str, object]:
    return {"$schema": PLUGIN_SCHEMA, "name": name, **extra}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def plugin(base: Path, data: dict[str, object] | None = None) -> Path:
    root = base / "plugin"
    root.mkdir(parents=True)
    write_json(root / "plugin.json", data or manifest())
    return root


def write_skill(
    root: Path,
    name: str,
    script: str | None = None,
    *,
    body: str = "",
    supporting: dict[str, str | bytes] | None = None,
) -> None:
    skill_root = root / "skills" / name
    skill_root.mkdir(parents=True, exist_ok=True)
    content = f"---\nname: {name}\ndescription: {name} skill\ncompatibility: local\n---\n{body}"
    (skill_root / "SKILL.md").write_text(content, encoding="utf-8")
    if script is not None:
        script_path = skill_root / "scripts" / f"{name}.py"
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text(script, encoding="utf-8")
    for relative, value in (supporting or {}).items():
        path = skill_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")


def write_mcp(root: Path, servers: dict[str, object]) -> None:
    write_json(root / "mcp.json", {"$schema": MCP_SCHEMA, "mcpServers": servers})


def snapshot_pair(
    tmp_path: Path,
    before_setup,
    after_setup,
    *,
    capability_limits: AgentPluginCapabilityLimits | None = None,
):
    before = plugin(tmp_path / "before")
    after = plugin(tmp_path / "after")
    before_setup(before)
    after_setup(after)
    kwargs = {} if capability_limits is None else {"capability_limits": capability_limits}
    return (
        build_agent_plugin_drift_snapshot(before, **kwargs),
        build_agent_plugin_drift_snapshot(after, **kwargs),
    )


def test_identical_plugins_are_deterministic_across_roots(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
    )

    assert before.to_data() == after.to_data()
    assert json.dumps(before.to_data(), sort_keys=True) == json.dumps(
        after.to_data(), sort_keys=True
    )
    assert str(tmp_path) not in json.dumps(before.to_data(), sort_keys=True)
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_UNCHANGED
    assert report.content.overall_artifact == DRIFT_UNCHANGED
    assert report.capability.portable_core == DRIFT_UNCHANGED
    assert report.capability.overall_artifact == DRIFT_UNCHANGED
    assert report.coverage.changed is False


def test_supporting_file_edit_is_content_drift_but_not_capability_drift(
    tmp_path: Path,
) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(
            root,
            "deploy",
            'subprocess.run(["deploy"])\n',
            supporting={"references/guide.txt": "old guide\n"},
        ),
        lambda root: write_skill(
            root,
            "deploy",
            'subprocess.run(["deploy"])\n',
            supporting={"references/guide.txt": "new guide\n"},
        ),
    )

    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_CHANGED
    assert "skills/deploy/references/guide.txt" in report.content.modified_files
    file_change = next(
        item
        for item in report.content.file_changes
        if item.path == "skills/deploy/references/guide.txt"
    )
    assert file_change.change == "modified"
    assert file_change.before is not None and file_change.after is not None
    assert "skill:deploy:skills/deploy" in file_change.after.owners
    assert file_change.after.sha256 == hashlib.sha256(b"new guide\n").hexdigest()
    assert report.capability.portable_core == DRIFT_UNCHANGED
    assert report.capability.added_capabilities == ()
    assert report.capability.removed_capabilities == ()


def test_source_line_relocation_does_not_change_capability_identity(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(
            root,
            "deploy",
            '# first\nsubprocess.run(["deploy"])\n',
        ),
        lambda root: write_skill(
            root,
            "deploy",
            '# first\n# moved comment\nsubprocess.run(["deploy"])\n',
        ),
    )

    before_capability = before.observed_capabilities[0]
    after_capability = after.observed_capabilities[0]
    assert before_capability.evidence[0].source_line != after_capability.evidence[0].source_line
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_CHANGED
    assert report.capability.portable_core == DRIFT_UNCHANGED


def test_added_and_removed_capabilities_are_reported_with_evidence(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
        lambda root: write_skill(
            root,
            "deploy",
            'subprocess.run(["deploy"])\nrequests.get("https://api.example.com/data")\n',
        ),
    )
    report = compare_agent_plugin_drift(before, after)
    assert report.capability.portable_core == DRIFT_CHANGED
    assert [item.type for item in report.capability.added_capabilities] == ["network_egress"]
    evidence = report.capability.added_capabilities[0].evidence[0]
    assert evidence.component_id == "deploy"
    assert evidence.source_file == "skills/deploy/scripts/deploy.py"

    removed_before, removed_after = snapshot_pair(
        tmp_path / "removed",
        lambda root: write_skill(
            root,
            "deploy",
            'subprocess.run(["deploy"])\nrequests.get("https://api.example.com/data")\n',
        ),
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
    )
    removed_report = compare_agent_plugin_drift(removed_before, removed_after)
    assert [item.type for item in removed_report.capability.removed_capabilities] == [
        "network_egress"
    ]


def test_same_capability_moving_between_skills_is_not_capability_drift(
    tmp_path: Path,
) -> None:
    def before_setup(root: Path) -> None:
        write_skill(root, "first", 'subprocess.run(["deploy"])\n')

    def after_setup(root: Path) -> None:
        write_skill(root, "second", 'subprocess.run(["deploy"])\n')

    before, after = snapshot_pair(tmp_path, before_setup, after_setup)
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_CHANGED
    assert report.capability.portable_core == DRIFT_UNCHANGED
    assert report.capability.added_capabilities == ()
    assert report.capability.removed_capabilities == ()


def test_zero_capability_skill_changes_content_not_coverage(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy"),
        lambda root: (
            write_skill(root, "deploy"),
            write_skill(root, "documentation", body="No detectable capability.\n"),
        ),
    )
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_CHANGED
    assert report.capability.portable_core == DRIFT_UNCHANGED
    assert report.coverage.changed is False
    assert any(item.component_id == "documentation" for item in report.content.added_membership)


def test_mcp_only_change_is_attributed_to_mcp_server(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_mcp(
            root,
            {"local": {"type": "stdio", "command": "bash"}},
        ),
        lambda root: write_mcp(
            root,
            {
                "local": {"type": "stdio", "command": "bash"},
                "remote": {"type": "streamable-http", "url": "https://api.example.com/mcp"},
            },
        ),
    )
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_CHANGED
    assert report.capability.portable_core == DRIFT_CHANGED
    assert any(item.type == "mcp_server" for item in report.capability.added_capabilities)
    assert any(item.component_id == "remote" for item in report.content.added_membership)


def test_fully_reviewed_mcp_membership_does_not_change_coverage(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: None,
        lambda root: write_mcp(root, {"local": {"type": "stdio", "command": "bash"}}),
    )
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_CHANGED
    assert report.coverage.changed is False


def test_first_fully_reviewed_zero_capability_skill_does_not_change_coverage(
    tmp_path: Path,
) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: None,
        lambda root: write_skill(root, "clean", body="Documentation only.\n"),
    )
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_CHANGED
    assert report.capability.portable_core == DRIFT_UNCHANGED
    assert report.coverage.changed is False


def test_known_package_metadata_is_content_only_drift(tmp_path: Path) -> None:
    def after_setup(root: Path) -> None:
        (root / "README.md").write_text("Known package metadata.\n", encoding="utf-8")

    before, after = snapshot_pair(tmp_path, lambda root: None, after_setup)
    report = compare_agent_plugin_drift(before, after)
    assert report.content.overall_artifact == DRIFT_CHANGED
    assert report.coverage.changed is False


def test_nonfatal_manifest_unknown_field_does_not_change_coverage(tmp_path: Path) -> None:
    def after_setup(root: Path) -> None:
        write_json(root / "plugin.json", manifest(futureField="opaque"))

    before, after = snapshot_pair(tmp_path, lambda root: None, after_setup)
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_CHANGED
    assert report.coverage.changed is False
    assert any(item.code == "manifest_unknown_field" for item in after.diagnostics)
    assert after.coverage_state.diagnostic_states == ()


def test_identical_invalid_mcp_bytes_keep_content_exact_but_capability_unknown(
    tmp_path: Path,
) -> None:
    invalid_servers = {"bad": {"type": "stdio", "command": "./../escape"}}
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_mcp(root, invalid_servers),
        lambda root: write_mcp(root, invalid_servers),
    )
    report = compare_agent_plugin_drift(before, after)
    assert before.content_identity_coverage.portable_core == "COMPLETE"
    assert report.content.portable_core == DRIFT_UNCHANGED
    assert report.content.overall_artifact == DRIFT_UNCHANGED
    assert report.capability.portable_core == DRIFT_UNKNOWN
    assert report.capability.overall_artifact == DRIFT_UNKNOWN
    assert report.coverage.changed is False


def test_identical_malformed_mcp_bytes_keep_known_content_identity(tmp_path: Path) -> None:
    def malformed(root: Path) -> None:
        (root / "mcp.json").write_text(
            '{"$schema":"' + MCP_SCHEMA + '","mcpServers":',
            encoding="utf-8",
        )

    before, after = snapshot_pair(tmp_path, malformed, malformed)
    report = compare_agent_plugin_drift(before, after)
    mcp_file = next(item for item in before.content_files if item.path == "mcp.json")
    assert mcp_file.identity_complete is True
    assert report.content.overall_artifact == DRIFT_UNCHANGED
    assert report.capability.overall_artifact == DRIFT_UNKNOWN
    assert report.coverage.changed is False


def test_snapshot_format_mismatch_forces_semantic_states_unknown(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "clean"),
        lambda root: write_skill(root, "clean"),
    )
    mismatched = replace(after, snapshot_format_version="future")
    report = compare_agent_plugin_drift(before, mismatched)
    assert report.content.portable_core == DRIFT_UNKNOWN
    assert report.content.overall_artifact == DRIFT_UNKNOWN
    assert report.capability.portable_core == DRIFT_UNKNOWN
    assert report.capability.overall_artifact == DRIFT_UNKNOWN
    assert any(item.code == "drift_snapshot_format_mismatch" for item in report.diagnostics)


def test_unknown_extension_is_overall_drift_and_coverage_drift(tmp_path: Path) -> None:
    def after_setup(root: Path) -> None:
        write_json(root / "plugin.json", manifest(extensions={"acme.tools": {}}))
        (root / "acme.tools").mkdir()

    before, after = snapshot_pair(tmp_path, lambda root: None, after_setup)
    report = compare_agent_plugin_drift(before, after)
    # Declaring an extension edits plugin.json, which is itself portable-core
    # content; the opaque extension surface is additionally overall-only.
    assert report.content.portable_core == DRIFT_CHANGED
    assert report.content.overall_artifact == DRIFT_CHANGED
    assert report.capability.portable_core == DRIFT_UNCHANGED
    assert report.capability.overall_artifact == DRIFT_UNKNOWN
    assert report.coverage.changed is True
    assert any(
        item.component_kind == "client_extension" for item in report.coverage.after.blind_spots
    )
    assert report.coverage.added_blind_spots


def test_unknown_package_surface_membership_is_content_drift(tmp_path: Path) -> None:
    def after_setup(root: Path) -> None:
        (root / "vendor-data").mkdir()

    before, after = snapshot_pair(tmp_path, lambda root: None, after_setup)
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_UNCHANGED
    assert report.content.overall_artifact == DRIFT_CHANGED
    assert report.capability.overall_artifact == DRIFT_UNKNOWN
    assert any(item.component_id == "vendor-data" for item in report.content.added_membership)


def test_unsupported_supporting_file_has_no_digest_and_keeps_content_unknown(
    tmp_path: Path,
) -> None:
    binary = b"\x00\xff" * 64
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy", supporting={"assets/blob.bin": binary}),
        lambda root: write_skill(root, "deploy", supporting={"assets/blob.bin": binary}),
    )
    record = next(
        item for item in before.content_files if item.path == "skills/deploy/assets/blob.bin"
    )
    assert record.sha256 is None
    assert record.identity_complete is False
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_UNKNOWN


def test_content_identity_is_deduplicated_by_path_and_retains_provenance_roles(
    tmp_path: Path,
) -> None:
    root = plugin(tmp_path)
    snapshot = build_agent_plugin_drift_snapshot(root)
    records = [item for item in snapshot.content_files if item.path == "plugin.json"]
    assert len(records) == 1
    assert records[0].identity_complete is True
    assert "provenance:manifest:plugin.json" in records[0].owners
    assert "provenance:package_surface:plugin.json" in records[0].owners


def test_conflicting_identity_is_incomplete_and_diagnostic(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy", 'subprocess.run(["deploy"])\n')
    inventory = load_agent_plugin(root)
    review = review_agent_plugin_capabilities(root, inventory=inventory)
    components = []
    for component in review.components:
        if component.component_kind != "skill":
            components.append(component)
            continue
        file_reviews = tuple(
            replace(file_review, sha256="0" * 64)
            if file_review.path.endswith("SKILL.md")
            else file_review
            for file_review in component.file_reviews
        )
        components.append(replace(component, file_reviews=file_reviews))
    conflicting_review = replace(review, components=tuple(components))
    snapshot = drift_module._build_snapshot(inventory, conflicting_review)
    skill_file = next(item for item in snapshot.content_files if item.path.endswith("SKILL.md"))
    assert skill_file.identity_complete is False
    assert skill_file.identity_skipped_reason == "conflicting_identity"
    assert any(item.code == "drift_identity_conflict" for item in snapshot.diagnostics)


def test_incomplete_identity_same_size_without_delta_is_unknown(tmp_path: Path) -> None:
    limits = AgentPluginCapabilityLimits(max_file_bytes=32)

    def setup(root: Path) -> None:
        write_skill(root, "deploy", 'subprocess.run(["deploy"])\n' + ("x" * 128))

    before, after = snapshot_pair(tmp_path, setup, setup, capability_limits=limits)
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_UNKNOWN
    assert report.content.overall_artifact == DRIFT_UNKNOWN
    assert report.capability.portable_core == DRIFT_UNKNOWN


def test_known_content_delta_wins_over_incomplete_identity(tmp_path: Path) -> None:
    limits = AgentPluginCapabilityLimits(max_file_bytes=32)

    def before_setup(root: Path) -> None:
        write_skill(root, "deploy", 'subprocess.run(["deploy"])\n' + ("x" * 128))

    def after_setup(root: Path) -> None:
        write_skill(root, "deploy", 'subprocess.run(["deploy"])\n' + ("x" * 160))

    before, after = snapshot_pair(
        tmp_path,
        before_setup,
        after_setup,
        capability_limits=limits,
    )
    report = compare_agent_plugin_drift(before, after)
    assert report.content.portable_core == DRIFT_CHANGED
    assert report.content.overall_artifact == DRIFT_CHANGED


def test_observed_capability_delta_wins_over_incomplete_coverage(tmp_path: Path) -> None:
    limits = AgentPluginCapabilityLimits(max_file_bytes=128)

    def before_setup(root: Path) -> None:
        write_skill(root, "deploy", 'subprocess.run(["deploy"])\n')
        write_skill(root, "opaque", body="ok\n", supporting={"blob.bin": b"0123456789" * 20})

    def after_setup(root: Path) -> None:
        write_skill(
            root,
            "deploy",
            'subprocess.run(["deploy"])\nrequests.get("https://api.example.com/data")\n',
        )
        write_skill(root, "opaque", body="ok\n", supporting={"blob.bin": b"0123456789" * 20})

    before, after = snapshot_pair(
        tmp_path,
        before_setup,
        after_setup,
        capability_limits=limits,
    )
    report = compare_agent_plugin_drift(before, after)
    assert report.capability.portable_core == DRIFT_CHANGED
    assert report.capability.overall_artifact == DRIFT_CHANGED


def test_coverage_improves_or_degrades_without_using_raw_counts(tmp_path: Path) -> None:
    limits = AgentPluginCapabilityLimits(max_file_bytes=128)

    def incomplete(root: Path) -> None:
        write_skill(root, "deploy", 'subprocess.run(["deploy"])\n')
        write_skill(root, "opaque", body="ok\n", supporting={"blob.bin": b"0123456789" * 20})

    def complete(root: Path) -> None:
        write_skill(root, "deploy", 'subprocess.run(["deploy"])\n')

    before, after = snapshot_pair(
        tmp_path,
        incomplete,
        complete,
        capability_limits=limits,
    )
    report = compare_agent_plugin_drift(before, after)
    assert report.coverage.changed is True
    assert report.coverage.before.capability_portable_core == "INCOMPLETE"
    assert report.coverage.after.capability_portable_core == "COMPLETE"


def test_drift_serialization_has_no_roots_or_policy_findings(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
    )
    data = agent_plugin_drift_to_data(compare_agent_plugin_drift(before, after))
    serialized = json.dumps(data, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "findings" not in data
    assert "policy" not in serialized.lower()
