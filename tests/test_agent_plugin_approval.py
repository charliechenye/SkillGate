from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from skillgate.agent_plugin_approval import (
    AGENT_PLUGIN_APPROVAL_BINDING_VERSION,
    APPROVAL_MATCHES,
    APPROVAL_NOT_BOUND,
    APPROVAL_SCOPE_OVERALL_ARTIFACT,
    APPROVAL_SCOPE_PORTABLE_CORE,
    APPROVAL_STALE,
    APPROVAL_UNKNOWN,
    ELIGIBILITY_ELIGIBLE,
    ELIGIBILITY_INELIGIBLE,
    ELIGIBILITY_NOT_BOUND,
    REBUILD_COMPATIBLE_REVIEW,
    RESOLVE_CAPABILITY_COVERAGE,
    RESOLVE_CONTENT_IDENTITY,
    REVIEW_CAPABILITY_CHANGE,
    REVIEW_CONTENT_CHANGE,
    AgentPluginApprovalContract,
    AgentPluginApprovalEligibilityError,
    assess_agent_plugin_approval_eligibility,
    create_agent_plugin_approval_binding,
    evaluate_agent_plugin_approval,
)
from skillgate.agent_plugin_capabilities import AgentPluginCapabilityLimits
from skillgate.agent_plugin_drift import (
    DRIFT_CHANGED,
    build_agent_plugin_drift_snapshot,
)
from skillgate.agent_plugins import (
    MCP_SCHEMA,
    PLUGIN_SCHEMA,
    AgentPluginLimits,
)


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


def snapshot(
    root: Path,
    *,
    limits: AgentPluginLimits | None = None,
    capability_limits: AgentPluginCapabilityLimits | None = None,
):
    kwargs: dict[str, object] = {}
    if limits is not None:
        kwargs["limits"] = limits
    if capability_limits is not None:
        kwargs["capability_limits"] = capability_limits
    return build_agent_plugin_drift_snapshot(root, **kwargs)


def snapshot_pair(
    tmp_path: Path,
    before_setup,
    after_setup,
    *,
    before_limits: AgentPluginLimits | None = None,
    after_limits: AgentPluginLimits | None = None,
    before_capability_limits: AgentPluginCapabilityLimits | None = None,
    after_capability_limits: AgentPluginCapabilityLimits | None = None,
):
    before = plugin(tmp_path / "before")
    after = plugin(tmp_path / "after")
    before_setup(before)
    after_setup(after)
    return (
        snapshot(
            before,
            limits=before_limits,
            capability_limits=before_capability_limits,
        ),
        snapshot(
            after,
            limits=after_limits,
            capability_limits=after_capability_limits,
        ),
    )


def test_contract_rejects_empty_or_unknown_scopes() -> None:
    with pytest.raises(ValueError, match="must bind"):
        AgentPluginApprovalContract()
    with pytest.raises(ValueError, match="portable_core"):
        AgentPluginApprovalContract(content_scope="arbitrary")


def test_complete_reference_snapshot_can_bind_both_dimensions(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy", 'subprocess.run(["deploy"])\n')
    current = snapshot(root)
    contract = AgentPluginApprovalContract(
        content_scope=APPROVAL_SCOPE_PORTABLE_CORE,
        capability_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )

    eligibility = assess_agent_plugin_approval_eligibility(current, contract)
    assert eligibility.eligible is True
    assert eligibility.content.status == ELIGIBILITY_ELIGIBLE
    assert eligibility.capability.status == ELIGIBILITY_ELIGIBLE
    binding = create_agent_plugin_approval_binding(current, contract)
    assert binding.binding_format_version == AGENT_PLUGIN_APPROVAL_BINDING_VERSION

    evaluation = evaluate_agent_plugin_approval(binding, current)
    assert evaluation.content_status == APPROVAL_MATCHES
    assert evaluation.capability_status == APPROVAL_MATCHES
    assert evaluation.current_eligibility.eligible is True
    assert evaluation.required_actions == ()


def test_eligibility_is_independent_by_dimension(tmp_path: Path) -> None:
    invalid_mcp = {"bad": {"type": "stdio", "command": "./../escape"}}
    root = plugin(tmp_path)
    write_mcp(root, invalid_mcp)
    current = snapshot(root)

    content_contract = AgentPluginApprovalContract(
        content_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    content_eligibility = assess_agent_plugin_approval_eligibility(current, content_contract)
    assert content_eligibility.content.status == ELIGIBILITY_ELIGIBLE
    assert content_eligibility.capability.status == ELIGIBILITY_NOT_BOUND

    capability_contract = AgentPluginApprovalContract(
        capability_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    capability_eligibility = assess_agent_plugin_approval_eligibility(
        current,
        capability_contract,
    )
    assert capability_eligibility.content.status == ELIGIBILITY_NOT_BOUND
    assert capability_eligibility.capability.status == ELIGIBILITY_INELIGIBLE
    assert capability_eligibility.reasons == ("capability_coverage_incomplete",)
    with pytest.raises(AgentPluginApprovalEligibilityError) as error:
        create_agent_plugin_approval_binding(current, capability_contract)
    assert error.value.eligibility == capability_eligibility


def test_content_and_capability_drift_statuses_are_independent(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(
            root,
            "deploy",
            'subprocess.run(["deploy"])\n',
            supporting={"references/guide.txt": "old\n"},
        ),
        lambda root: write_skill(
            root,
            "deploy",
            'subprocess.run(["deploy"])\n',
            supporting={"references/guide.txt": "new\n"},
        ),
    )
    contract = AgentPluginApprovalContract(
        content_scope=APPROVAL_SCOPE_PORTABLE_CORE,
        capability_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        after,
    )
    assert evaluation.content_status == APPROVAL_STALE
    assert evaluation.capability_status == APPROVAL_MATCHES
    assert evaluation.required_actions == (REVIEW_CONTENT_CHANGE,)


def test_added_capability_stales_both_dimensions_and_keeps_evidence(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
        lambda root: write_skill(
            root,
            "deploy",
            'subprocess.run(["deploy"])\nrequests.get("https://api.example.com")\n',
        ),
    )
    contract = AgentPluginApprovalContract(
        content_scope=APPROVAL_SCOPE_PORTABLE_CORE,
        capability_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        after,
    )
    assert evaluation.content_status == APPROVAL_STALE
    assert evaluation.capability_status == APPROVAL_STALE
    assert evaluation.required_actions == (
        REVIEW_CONTENT_CHANGE,
        REVIEW_CAPABILITY_CHANGE,
    )
    assert evaluation.drift.capability.added_capabilities[0].type == "network_egress"


def test_capability_removal_is_stale_with_reference_evidence(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(
            root,
            "deploy",
            'requests.get("https://api.example.com")\n',
        ),
        lambda root: write_skill(root, "deploy"),
    )
    contract = AgentPluginApprovalContract(capability_scope=APPROVAL_SCOPE_PORTABLE_CORE)
    evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        after,
    )
    assert evaluation.content_status == APPROVAL_NOT_BOUND
    assert evaluation.capability_status == APPROVAL_STALE
    assert evaluation.drift.capability.removed_capabilities[0].type == "network_egress"


def test_evidence_relocation_and_zero_capability_addition_only_stale_content(
    tmp_path: Path,
) -> None:
    before, moved = snapshot_pair(
        tmp_path / "moved",
        lambda root: write_skill(root, "first", 'subprocess.run(["deploy"])\n'),
        lambda root: write_skill(root, "second", 'subprocess.run(["deploy"])\n'),
    )
    contract = AgentPluginApprovalContract(
        content_scope=APPROVAL_SCOPE_PORTABLE_CORE,
        capability_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    moved_evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        moved,
    )
    assert moved_evaluation.content_status == APPROVAL_STALE
    assert moved_evaluation.capability_status == APPROVAL_MATCHES

    before, added = snapshot_pair(
        tmp_path / "zero-capability",
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
        lambda root: (
            write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
            write_skill(root, "documentation", body="No capability.\n"),
        ),
    )
    added_evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        added,
    )
    assert added_evaluation.content_status == APPROVAL_STALE
    assert added_evaluation.capability_status == APPROVAL_MATCHES
    assert added_evaluation.current_eligibility.eligible is True


def test_capability_coverage_degradation_is_unknown_and_ineligible(tmp_path: Path) -> None:
    limits = AgentPluginCapabilityLimits(max_file_bytes=128)
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
        lambda root: (
            write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
            write_skill(
                root,
                "opaque",
                body="No capability.\n",
                supporting={"blob.bin": b"0123456789" * 20},
            ),
        ),
        before_capability_limits=limits,
        after_capability_limits=limits,
    )
    contract = AgentPluginApprovalContract(capability_scope=APPROVAL_SCOPE_PORTABLE_CORE)
    evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        after,
    )
    assert evaluation.capability_status == APPROVAL_UNKNOWN
    assert evaluation.current_eligibility.capability.status == ELIGIBILITY_INELIGIBLE
    assert evaluation.required_actions == (RESOLVE_CAPABILITY_COVERAGE,)


def test_known_capability_delta_wins_over_incomplete_current_coverage(tmp_path: Path) -> None:
    limits = AgentPluginCapabilityLimits(max_file_bytes=128)
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
        lambda root: (
            write_skill(
                root,
                "deploy",
                'subprocess.run(["deploy"])\nrequests.get("https://api.example.com")\n',
            ),
            write_skill(
                root,
                "opaque",
                body="No capability.\n",
                supporting={"blob.bin": b"0123456789" * 20},
            ),
        ),
        before_capability_limits=limits,
        after_capability_limits=limits,
    )
    contract = AgentPluginApprovalContract(capability_scope=APPROVAL_SCOPE_PORTABLE_CORE)
    evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        after,
    )
    assert evaluation.drift.capability.portable_core == DRIFT_CHANGED
    assert evaluation.capability_status == APPROVAL_STALE
    assert evaluation.current_eligibility.capability.status == ELIGIBILITY_INELIGIBLE
    assert evaluation.required_actions == (REVIEW_CAPABILITY_CHANGE,)


def test_content_identity_degradation_is_unknown_and_ineligible(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy", body="x" * 128),
        lambda root: write_skill(root, "deploy", body="x" * 128),
        after_limits=AgentPluginLimits(max_skill_bytes=32),
    )
    contract = AgentPluginApprovalContract(content_scope=APPROVAL_SCOPE_PORTABLE_CORE)
    assert assess_agent_plugin_approval_eligibility(before, contract).eligible is True
    evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        after,
    )
    assert evaluation.content_status == APPROVAL_UNKNOWN
    assert evaluation.current_eligibility.content.status == ELIGIBILITY_INELIGIBLE
    assert evaluation.required_actions == (RESOLVE_CONTENT_IDENTITY,)


def test_known_content_change_wins_over_incomplete_current_identity(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy", body="x" * 128),
        lambda root: (
            write_json(root / "plugin.json", manifest(version="1.1")),
            write_skill(root, "deploy", body="x" * 128),
        ),
        after_limits=AgentPluginLimits(max_skill_bytes=32),
    )
    contract = AgentPluginApprovalContract(content_scope=APPROVAL_SCOPE_PORTABLE_CORE)
    evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        after,
    )
    assert evaluation.drift.content.portable_core == DRIFT_CHANGED
    assert evaluation.content_status == APPROVAL_STALE
    assert evaluation.current_eligibility.content.status == ELIGIBILITY_INELIGIBLE
    assert evaluation.required_actions == (REVIEW_CONTENT_CHANGE,)


def test_plugin_version_change_can_leave_capability_binding_matching(tmp_path: Path) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: (
            write_json(root / "plugin.json", manifest(version="1.0")),
            write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
        ),
        lambda root: (
            write_json(root / "plugin.json", manifest(version="1.1")),
            write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
        ),
    )
    contract = AgentPluginApprovalContract(
        content_scope=APPROVAL_SCOPE_PORTABLE_CORE,
        capability_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        after,
    )
    assert evaluation.content_status == APPROVAL_STALE
    assert evaluation.capability_status == APPROVAL_MATCHES


def test_invalid_mcp_content_only_binding_is_allowed_but_capability_is_not(
    tmp_path: Path,
) -> None:
    invalid_servers = {"bad": {"type": "stdio", "command": "./../escape"}}
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_mcp(root, invalid_servers),
        lambda root: write_mcp(root, invalid_servers),
    )
    content_contract = AgentPluginApprovalContract(
        content_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    binding = create_agent_plugin_approval_binding(before, content_contract)
    evaluation = evaluate_agent_plugin_approval(binding, after)
    assert evaluation.content_status == APPROVAL_MATCHES
    assert evaluation.capability_status == APPROVAL_NOT_BOUND

    capability_contract = AgentPluginApprovalContract(
        capability_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    with pytest.raises(AgentPluginApprovalEligibilityError):
        create_agent_plugin_approval_binding(before, capability_contract)


def test_portable_and_overall_scopes_do_not_poison_each_other(tmp_path: Path) -> None:
    def with_unknown_extension(root: Path) -> None:
        write_json(root / "plugin.json", manifest(extensions={"acme.tools": {}}))
        (root / "acme.tools").mkdir()

    root = plugin(tmp_path)
    with_unknown_extension(root)
    current = snapshot(root)

    portable_contract = AgentPluginApprovalContract(
        capability_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    portable = assess_agent_plugin_approval_eligibility(current, portable_contract)
    assert portable.capability.status == ELIGIBILITY_ELIGIBLE

    overall_contract = AgentPluginApprovalContract(
        capability_scope=APPROVAL_SCOPE_OVERALL_ARTIFACT,
    )
    overall = assess_agent_plugin_approval_eligibility(current, overall_contract)
    assert overall.capability.status == ELIGIBILITY_INELIGIBLE
    assert overall.reasons == ("capability_coverage_incomplete",)

    content_portable = assess_agent_plugin_approval_eligibility(
        current,
        AgentPluginApprovalContract(content_scope=APPROVAL_SCOPE_PORTABLE_CORE),
    )
    content_overall = assess_agent_plugin_approval_eligibility(
        current,
        AgentPluginApprovalContract(content_scope=APPROVAL_SCOPE_OVERALL_ARTIFACT),
    )
    assert content_portable.content.status == ELIGIBILITY_ELIGIBLE
    assert content_overall.content.status == ELIGIBILITY_INELIGIBLE


def test_snapshot_format_mismatch_maps_to_unknown_and_rebuild_action(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy")
    before = snapshot(root)
    current = replace(before, snapshot_format_version="future")
    contract = AgentPluginApprovalContract(
        content_scope=APPROVAL_SCOPE_PORTABLE_CORE,
        capability_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    evaluation = evaluate_agent_plugin_approval(
        create_agent_plugin_approval_binding(before, contract),
        current,
    )
    assert evaluation.content_status == APPROVAL_UNKNOWN
    assert evaluation.capability_status == APPROVAL_UNKNOWN
    assert REBUILD_COMPATIBLE_REVIEW in evaluation.required_actions
    assert evaluation.current_eligibility.eligible is True


def test_binding_and_evaluation_serialization_is_deterministic_and_path_free(
    tmp_path: Path,
) -> None:
    before, after = snapshot_pair(
        tmp_path,
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
        lambda root: write_skill(root, "deploy", 'subprocess.run(["deploy"])\n'),
    )
    contract = AgentPluginApprovalContract(
        content_scope=APPROVAL_SCOPE_PORTABLE_CORE,
        capability_scope=APPROVAL_SCOPE_PORTABLE_CORE,
    )
    binding = create_agent_plugin_approval_binding(before, contract)
    evaluation = evaluate_agent_plugin_approval(binding, after)
    binding_data = json.dumps(binding.to_data(), sort_keys=True)
    evaluation_data = json.dumps(evaluation.to_data(), sort_keys=True)
    assert str(tmp_path) not in binding_data
    assert str(tmp_path) not in evaluation_data
    assert "approved" not in evaluation_data
    assert "allow" not in evaluation_data
    assert "block" not in evaluation_data
