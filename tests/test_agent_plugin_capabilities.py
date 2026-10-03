from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import skillgate.agent_plugin_capabilities as capability_module
from skillgate.agent_plugin_capabilities import (
    AgentPluginCapabilityLimits,
    agent_plugin_capabilities_to_data,
    review_agent_plugin_capabilities,
)
from skillgate.agent_plugins import MCP_SCHEMA, PLUGIN_SCHEMA
from skillgate.models import Capability


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


def test_unreferenced_script_is_inventoried_and_scanned(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy")
    hidden = root / "skills" / "deploy" / "scripts" / "hidden.py"
    hidden.parent.mkdir()
    hidden.write_text('subprocess.run(["hidden"])\n', encoding="utf-8")

    review = review_agent_plugin_capabilities(root)
    deploy = component(review, "skill", "deploy")

    assert deploy.capability_scan_status == "reviewed"
    assert "skills/deploy/scripts/hidden.py" in deploy.scanned_files
    assert any(
        capability.source_file == "skills/deploy/scripts/hidden.py"
        for capability in deploy.capabilities
    )


def test_oversized_script_preserves_other_evidence_and_marks_incomplete(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy", 'subprocess.run(["small"])\n')
    oversized = root / "skills" / "deploy" / "scripts" / "oversized.py"
    oversized.write_text('subprocess.run(["oversized"])\n' + ("x" * 256), encoding="utf-8")

    review = review_agent_plugin_capabilities(
        root,
        capability_limits=AgentPluginCapabilityLimits(max_file_bytes=128),
    )
    deploy = component(review, "skill", "deploy")

    assert any(item.source_file.endswith("deploy.py") for item in deploy.capabilities)
    assert not any(item.source_file.endswith("oversized.py") for item in deploy.capabilities)
    oversized_review = next(
        item for item in deploy.file_reviews if item.path.endswith("oversized.py")
    )
    assert oversized_review.status == "limit_exceeded"
    assert deploy.capability_scan_status == "incomplete"
    assert review.capability_coverage.portable_core == "INCOMPLETE"


def test_file_count_limit_is_explicit_and_bounded(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy")
    scripts = root / "skills" / "deploy" / "scripts"
    scripts.mkdir()
    for name in ("a.py", "b.py", "c.py"):
        (scripts / name).write_text('subprocess.run(["limited"])\n', encoding="utf-8")

    review = review_agent_plugin_capabilities(
        root,
        capability_limits=AgentPluginCapabilityLimits(max_files_per_component=2),
    )
    deploy = component(review, "skill", "deploy")

    assert deploy.capability_scan_status == "incomplete"
    assert any(item.status == "limit_exceeded" for item in deploy.file_reviews)
    assert any(item.code == "capability_file_limit_exceeded" for item in deploy.diagnostics)
    assert review.capability_coverage.portable_core == "INCOMPLETE"


def test_total_byte_limit_preserves_prior_files_and_marks_later_file(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy")
    scripts = root / "skills" / "deploy" / "scripts"
    scripts.mkdir()
    first = scripts / "a.py"
    second = scripts / "b.py"
    first.write_text('subprocess.run(["first"])\n', encoding="utf-8")
    second.write_text('subprocess.run(["second"])\n', encoding="utf-8")
    skill_bytes = (root / "skills" / "deploy" / "SKILL.md").stat().st_size
    total_limit = skill_bytes + first.stat().st_size + 1

    review = review_agent_plugin_capabilities(
        root,
        capability_limits=AgentPluginCapabilityLimits(
            max_file_bytes=1_024,
            max_total_bytes_per_component=total_limit,
        ),
    )
    deploy = component(review, "skill", "deploy")

    assert any(item.source_file.endswith("a.py") for item in deploy.capabilities)
    assert not any(item.source_file.endswith("b.py") for item in deploy.capabilities)
    assert next(item for item in deploy.file_reviews if item.path.endswith("b.py")).status == (
        "limit_exceeded"
    )
    assert deploy.capability_scan_status == "incomplete"


@pytest.mark.parametrize(
    ("max_file_value", "remaining_value", "reported_value", "expected_reason"),
    [
        (100, 4, 4, "max_total_bytes_per_component"),
        ("skill", "skill", "max", "max_total_bytes_per_component"),
        ("skill", 1000, "max", "max_file_bytes"),
    ],
)
def test_raced_skill_file_reads_past_active_budget_without_analyzing_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    max_file_value: int | str,
    remaining_value: int | str,
    reported_value: int | str,
    expected_reason: str,
) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy", "bash " + ("x" * 256))
    script = root / "skills" / "deploy" / "scripts" / "deploy.py"
    skill_bytes = (root / "skills" / "deploy" / "SKILL.md").stat().st_size
    max_file_bytes = skill_bytes if max_file_value == "skill" else max_file_value
    remaining_bytes = skill_bytes if remaining_value == "skill" else remaining_value
    reported_size = max_file_bytes if reported_value == "max" else reported_value
    original_stat = Path.stat
    original_open = Path.open
    read_requests: list[int] = []

    def raced_stat(self: Path, *args: object, **kwargs: object):
        result = original_stat(self, *args, **kwargs)
        if self == script:
            return SimpleNamespace(st_mode=result.st_mode, st_size=reported_size)
        return result

    class TrackedStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args: object):
            return self.stream.__exit__(*args)

        def read(self, size: int = -1) -> bytes:
            read_requests.append(size)
            return self.stream.read(size)

    def tracked_open(self: Path, *args: object, **kwargs: object):
        stream = original_open(self, *args, **kwargs)
        return TrackedStream(stream) if self == script else stream

    monkeypatch.setattr(Path, "stat", raced_stat)
    monkeypatch.setattr(Path, "open", tracked_open)

    review = review_agent_plugin_capabilities(
        root,
        capability_limits=AgentPluginCapabilityLimits(
            max_file_bytes=max_file_bytes,
            max_total_bytes_per_component=skill_bytes + remaining_bytes,
        ),
    )
    deploy = component(review, "skill", "deploy")

    script_review = next(item for item in deploy.file_reviews if item.path.endswith("deploy.py"))
    assert read_requests[-1] == min(max_file_bytes, remaining_bytes) + 1
    assert script_review.status == "limit_exceeded"
    assert script_review.reason == expected_reason
    assert not any(item.source_file.endswith("deploy.py") for item in deploy.capabilities)
    assert not any(
        evidence.source_file.endswith("deploy.py")
        for item in review.observed_capabilities
        for evidence in item.evidence
    )
    assert deploy.capability_scan_status == "incomplete"
    assert review.capability_coverage.portable_core == "INCOMPLETE"


def test_references_are_scanned_and_binary_assets_are_accounted_as_blind_spots(
    tmp_path: Path,
) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy")
    references = root / "skills" / "deploy" / "references"
    assets = root / "skills" / "deploy" / "assets"
    references.mkdir()
    assets.mkdir()
    (references / "workflow.md").write_text(
        'Use requests.get("https://reference.example/data")\n', encoding="utf-8"
    )
    (assets / "blob.dat").write_bytes(b"\x00\xffbinary")

    review = review_agent_plugin_capabilities(root)
    deploy = component(review, "skill", "deploy")

    assert (
        next(item for item in deploy.file_reviews if item.path.endswith("workflow.md")).status
        == "scanned"
    )
    assert any(item.source_file.endswith("references/workflow.md") for item in deploy.capabilities)
    assert next(item for item in deploy.file_reviews if item.path.endswith("blob.dat")).status == (
        "unsupported"
    )
    assert deploy.capability_scan_status == "incomplete"
    assert review.capability_coverage.portable_core == "INCOMPLETE"


def test_misplaced_supported_script_is_scanned(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy")
    helper = root / "skills" / "deploy" / "helper.py"
    helper.write_text('subprocess.run(["helper"])\n', encoding="utf-8")

    review = review_agent_plugin_capabilities(root)
    deploy = component(review, "skill", "deploy")

    assert any(item.source_file == "skills/deploy/helper.py" for item in deploy.capabilities)
    assert deploy.capability_scan_status == "reviewed"


def test_skill_capability_source_escape_is_excluded_and_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy")
    real_analyze = capability_module._analyze_file_content

    def add_escape(file):
        capabilities = real_analyze(file)
        if file.path == "skills/deploy/SKILL.md":
            capabilities.append(
                Capability(
                    type="shell_execution",
                    resource=None,
                    source_file="skills/other/evil.py",
                    source_line=1,
                    details={},
                )
            )
        return capabilities

    monkeypatch.setattr(capability_module, "_analyze_file_content", add_escape)

    review = review_agent_plugin_capabilities(root)
    deploy = component(review, "skill", "deploy")

    assert not any(
        evidence.source_file == "skills/other/evil.py"
        for item in review.observed_capabilities
        for evidence in item.evidence
    )
    assert deploy.capability_scan_status == "incomplete"
    assert any(item.code == "capability_source_outside_component" for item in deploy.diagnostics)


def test_skill_does_not_follow_mcp_app_asset_outside_component(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy")
    outside = root / "outside.html"
    outside.write_text('<script>subprocess.run(["outside"])</script>', encoding="utf-8")
    skill_mcp = root / "skills" / "deploy" / "mcp.json"
    write_json(
        skill_mcp,
        {
            "resources": [
                {
                    "uri": "ui://outside.html",
                    "mimeType": "text/html;profile=mcp-app",
                }
            ]
        },
    )

    review = review_agent_plugin_capabilities(root)

    assert not any(
        evidence.source_file == "outside.html"
        for item in review.observed_capabilities
        for evidence in item.evidence
    )
    deploy = component(review, "skill", "deploy")
    assert deploy.capability_scan_status == "incomplete"
    assert review.capability_coverage.portable_core == "INCOMPLETE"
    assert any(
        item.reason == "associated_resource_outside_component"
        and item.component_id == "outside.html"
        for item in review.blind_spots
    )
    assert any(
        item.code == "associated_resource_outside_component"
        and item.path == "skills/deploy/mcp.json"
        for item in deploy.diagnostics
    )


@pytest.mark.parametrize(
    ("uri", "expected_reason"),
    [
        ("https://example.com/app.html", "associated_resource_external"),
        ("file:///tmp/app.html", "associated_resource_outside_plugin"),
        ("custom://resource", "associated_resource_unsupported"),
    ],
)
def test_skill_unfollowed_associated_resource_branches_are_explicit(
    tmp_path: Path,
    uri: str,
    expected_reason: str,
) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy", 'subprocess.run(["deploy"])\n')
    write_json(
        root / "skills" / "deploy" / "mcp.json",
        {
            "resources": [
                {
                    "uri": uri,
                    "mimeType": "text/html;profile=mcp-app",
                }
            ]
        },
    )

    review = review_agent_plugin_capabilities(root)
    deploy = component(review, "skill", "deploy")
    serialized = json.dumps(agent_plugin_capabilities_to_data(review), sort_keys=True)

    assert any(item.type == "shell_execution" for item in deploy.capabilities)
    assert deploy.capability_scan_status == "incomplete"
    assert review.capability_coverage.portable_core == "INCOMPLETE"
    assert any(item.reason == expected_reason for item in review.blind_spots)
    assert not any(
        uri in evidence.source_file
        for item in review.observed_capabilities
        for evidence in item.evidence
    )
    if uri.startswith("file:"):
        assert "/tmp/app.html" not in serialized


def test_skill_missing_associated_resource_is_incomplete_without_erasing_evidence(
    tmp_path: Path,
) -> None:
    root = plugin(tmp_path)
    write_skill(
        root,
        "deploy",
        'subprocess.run(["deploy"])\n',
        body="Run scripts/deploy.py.\n",
    )
    write_json(
        root / "skills" / "deploy" / "mcp.json",
        {
            "resources": [
                {
                    "uri": "ui://missing.html",
                    "mimeType": "text/html;profile=mcp-app",
                }
            ]
        },
    )

    review = review_agent_plugin_capabilities(root)
    deploy = component(review, "skill", "deploy")

    assert any(item.type == "shell_execution" for item in deploy.capabilities)
    assert deploy.capability_scan_status == "incomplete"
    assert review.capability_coverage.portable_core == "INCOMPLETE"
    assert any(
        item.reason == "associated_resource_missing" and item.component_id == "missing.html"
        for item in review.blind_spots
    )
    assert not any(
        evidence.source_file == "missing.html"
        for item in review.observed_capabilities
        for evidence in item.evidence
    )


def test_skill_in_component_associated_resource_is_scanned(tmp_path: Path) -> None:
    root = plugin(tmp_path)
    write_skill(root, "deploy")
    app = root / "skills" / "deploy" / "ui" / "app.html"
    app.parent.mkdir()
    app.write_text("<script>fetch('https://app.example/data')</script>", encoding="utf-8")
    write_json(
        root / "skills" / "deploy" / "mcp.json",
        {
            "resources": [
                {
                    "uri": "ui://ui/app.html",
                    "mimeType": "text/html;profile=mcp-app",
                }
            ]
        },
    )

    review = review_agent_plugin_capabilities(root)
    deploy = component(review, "skill", "deploy")

    assert deploy.capability_scan_status == "reviewed"
    assert "skills/deploy/ui/app.html" in deploy.scanned_files
    assert not any(item.reason.startswith("associated_resource_") for item in review.blind_spots)


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
    real_analyze = capability_module._analyze_file_content

    def fail_bad_component(file):
        if "skills/bad/" in file.path:
            raise RuntimeError("simulated scanner failure")
        return real_analyze(file)

    monkeypatch.setattr(capability_module, "_analyze_file_content", fail_bad_component)

    review = review_agent_plugin_capabilities(root)
    good = component(review, "skill", "good")
    bad = component(review, "skill", "bad")

    assert any(item.type == "shell_execution" for item in good.capabilities)
    assert bad.capabilities == ()
    assert bad.capability_scan_status == "incomplete"
    assert review.capability_coverage.portable_core == "INCOMPLETE"
