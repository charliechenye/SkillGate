from __future__ import annotations

import json

import pytest
from conftest import FIXTURES, ROOT, clean_test_dir

from skillgate.baseline import create_baseline, diff_against_baseline
from skillgate.discovery import discover_paths, scan_file_metadata
from skillgate.mcp_registry import collect_registry_servers, scan_registry_path
from skillgate.models import stable_json
from skillgate.policy import evaluate_policy, load_policy
from skillgate.scan import scan_repository


def rule_ids(path: str) -> set[str]:
    return {finding.rule_id for finding in scan_repository(FIXTURES / path).findings}


def test_recursive_discovery_includes_referenced_script() -> None:
    paths = [
        path.relative_to(FIXTURES / "02-shell-execution").as_posix()
        for path in discover_paths(FIXTURES / "02-shell-execution")
    ]
    assert paths == ["SKILL.md", "scripts/build.sh"]


def test_excluded_directories_are_skipped() -> None:
    workdir = clean_test_dir("excluded-directories")
    (workdir / "SKILL.md").write_text("Safe", encoding="utf-8")
    excluded = workdir / "node_modules" / "package" / "SKILL.md"
    excluded.parent.mkdir(parents=True)
    excluded.write_text("bash setup.sh", encoding="utf-8")
    paths = [path.relative_to(workdir).as_posix() for path in discover_paths(workdir)]
    assert paths == ["SKILL.md"]


def test_public_agent_layouts_are_discovered() -> None:
    workdir = clean_test_dir("public-agent-layouts")
    for rel_path in [
        "skills/review/SKILL.md",
        "agents/reviewer.md",
        ".claude/commands/review.md",
        ".gemini/commands/review.md",
        "hooks/pre-tool-use.sh",
    ]:
        path = workdir / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Safe\n", encoding="utf-8")
    paths = [path.relative_to(workdir).as_posix() for path in discover_paths(workdir)]
    assert paths == [
        ".claude/commands/review.md",
        ".gemini/commands/review.md",
        "agents/reviewer.md",
        "hooks/pre-tool-use.sh",
        "skills/review/SKILL.md",
    ]


def test_mcp_registry_server_json_is_discovered_when_schema_like() -> None:
    workdir = clean_test_dir("mcp-registry-discovery")
    (workdir / "server.json").write_text(
        json.dumps({"server": {"name": "io.example.discovery", "version": "0.1.0"}}),
        encoding="utf-8",
    )
    ignored = workdir / "nested" / "server.json"
    ignored.parent.mkdir()
    ignored.write_text(json.dumps({"service": "not-mcp"}), encoding="utf-8")
    paths = [path.relative_to(workdir).as_posix() for path in discover_paths(workdir)]
    assert paths == ["server.json"]


def test_stable_file_hashing() -> None:
    path = FIXTURES / "01-safe-documentation-skill" / "SKILL.md"
    first = scan_file_metadata(FIXTURES / "01-safe-documentation-skill", path)
    second = scan_file_metadata(FIXTURES / "01-safe-documentation-skill", path)
    assert first.sha256 == second.sha256
    assert len(first.sha256) == 64


@pytest.mark.parametrize(
    ("fixture", "rule_id"),
    [
        ("02-shell-execution", "SG001"),
        ("03-destructive-command", "SG002"),
        ("04-network-egress", "SG003"),
        ("05-remote-download-execute", "SG004"),
        ("06-secret-access", "SG005"),
        ("07-filesystem-write", "SG006"),
        ("08-prompt-override", "SG007"),
        ("09-unicode-obfuscation", "SG008"),
        ("10-mcp-config", "SG009"),
    ],
)
def test_required_rules(fixture: str, rule_id: str) -> None:
    assert rule_id in rule_ids(fixture)


def test_secret_values_are_not_reported() -> None:
    report = scan_repository(FIXTURES / "06-secret-access")
    rendered = stable_json(report)
    assert "GITHUB_TOKEN" in rendered
    assert "token[:4]" not in rendered


def test_mcp_config_parses_metadata() -> None:
    report = scan_repository(FIXTURES / "10-mcp-config")
    mcp = [capability for capability in report.capabilities if capability.type == "mcp_server"][0]
    assert mcp.resource == "github"
    assert mcp.details["command"] == "node"
    assert "GITHUB_TOKEN" in mcp.details["env"]


def test_mcp_registry_metadata_parser_extracts_declared_fields() -> None:
    fixture = FIXTURES / "27-public-pattern-mcp-registry-package-metadata"
    servers = collect_registry_servers(fixture)
    assert [server.name for server in servers] == ["io.example.registry-package"]
    report = scan_registry_path(fixture)
    registry = [
        capability for capability in report.capabilities if capability.type == "mcp_registry_server"
    ][0]
    assert registry.details["repository"] == "https://github.com/example/registry-package"
    assert registry.details["packages"] == ["npm:@example/registry-package"]
    assert registry.details["secret_headers"] == ["X-Registry-Token"]


def test_mcp_tool_metadata_and_transport_rules_detect_public_patterns() -> None:
    tool_report = scan_repository(FIXTURES / "24-public-pattern-mcp-tool-metadata-risk")
    transport_report = scan_repository(FIXTURES / "26-public-pattern-mcp-dangerous-transport")
    assert any(finding.rule_id == "SG011" for finding in tool_report.findings)
    assert any("delete_all_files" in finding.evidence for finding in tool_report.findings)
    assert any(finding.rule_id == "SG012" for finding in transport_report.findings)
    assert "literal-secret-value" not in stable_json(transport_report)


def test_policy_blocks_remote_download_execute() -> None:
    report = scan_repository(FIXTURES / "05-remote-download-execute")
    result = evaluate_policy(report, load_policy(ROOT / "skillgate.example.yaml"))
    assert result.blocked
    assert any("Shell execution is not allowed" in item.message for item in result.violations)


def test_lockfile_generation_is_stable_json() -> None:
    lock = create_baseline(FIXTURES / "11-mcp-capability-drift-before")
    data = json.loads(stable_json(lock))
    assert data["schema_version"] == "1"
    assert data["files"][0]["path"] == ".mcp.json"


def test_capability_diff_reports_mcp_change() -> None:
    baseline = create_baseline(FIXTURES / "11-mcp-capability-drift-before")
    diff, _report = diff_against_baseline(FIXTURES / "12-mcp-capability-drift-after", baseline)
    assert any(finding.rule_id == "SG010" for finding in diff.findings)
    assert "before=" in diff.findings[0].evidence
    assert "after=" in diff.findings[0].evidence


def test_json_report_is_machine_readable_and_stable() -> None:
    report = scan_repository(FIXTURES / "02-shell-execution")
    first = stable_json(report)
    second = stable_json(report)
    assert first == second
    assert json.loads(first)["findings"][0]["rule_id"] == "SG001"


def test_richer_filesystem_write_extraction() -> None:
    workdir = clean_test_dir("write-extraction")
    scripts = workdir / "scripts"
    scripts.mkdir()
    (workdir / "SKILL.md").write_text(
        "Run `scripts/write.py` and `scripts/write.js`.\n",
        encoding="utf-8",
    )
    (scripts / "write.py").write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "open('generated/open.txt', 'w')",
                "Path('generated/path.txt').write_text('ok')",
                "print('ok') > generated/redirect.txt",
            ]
        ),
        encoding="utf-8",
    )
    (scripts / "write.js").write_text(
        "\n".join(
            [
                "fs.writeFile('generated/node.txt', data)",
                "fs.appendFile('generated/append.txt', data)",
                "fs.createWriteStream('generated/stream.txt')",
            ]
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    resources = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "filesystem_write"
    }
    assert {
        "generated/open.txt",
        "generated/path.txt",
        "generated/redirect.txt",
        "generated/node.txt",
        "generated/append.txt",
        "generated/stream.txt",
    } <= resources


def test_more_real_world_extraction_patterns() -> None:
    workdir = clean_test_dir("real-world-extraction")
    (workdir / "SKILL.md").write_text("Run `patterns.ps1` and `patterns.js`.\n", encoding="utf-8")
    (workdir / "patterns.ps1").write_text(
        "\n".join(
            [
                "Invoke-RestMethod -Uri https://ps.example.com/api",
                "Set-Content -Path generated/powershell.txt -Value ok",
                "Remove-Item generated/cache -Recurse",
            ]
        ),
        encoding="utf-8",
    )
    (workdir / "patterns.js").write_text(
        "\n".join(
            [
                "got('https://got.example.com/data')",
                "undici.request('https://undici.example.com/data')",
                "fs.promises.writeFile('generated/promises.txt', data)",
                "fs.rmSync('generated/delete-me', { recursive: true })",
            ]
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    rule_ids = {finding.rule_id for finding in report.findings}
    hosts = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "network_egress"
    }
    write_resources = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "filesystem_write"
    }
    assert {"SG002", "SG003", "SG006"} <= rule_ids
    assert {"ps.example.com", "got.example.com", "undici.example.com"} <= hosts
    assert {"generated/powershell.txt", "generated/promises.txt"} <= write_resources


def test_ambiguous_network_resource_is_not_invented() -> None:
    workdir = clean_test_dir("ambiguous-network")
    (workdir / "SKILL.md").write_text("Run `net.py`.\n", encoding="utf-8")
    (workdir / "net.py").write_text("requests.get(api_url)\n", encoding="utf-8")
    report = scan_repository(workdir)
    network_caps = [
        capability for capability in report.capabilities if capability.type == "network_egress"
    ]
    assert network_caps
    assert all(capability.resource is None for capability in network_caps)


def test_safer_host_extraction_from_package_scripts_and_mcp() -> None:
    workdir = clean_test_dir("host-extraction")
    (workdir / "package.json").write_text(
        '{"scripts": {"setup": "curl api.example.com/install.sh"}}',
        encoding="utf-8",
    )
    (workdir / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "command": "node",
                        "args": ["server.js", "api.args.example.com/mcp"],
                        "transport": {"url": "https://nested.example.com/sse"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    hosts = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "network_egress"
    }
    assert {"api.example.com", "api.args.example.com", "nested.example.com"} <= hosts


def test_mcp_config_parses_nested_servers_and_transport_metadata() -> None:
    workdir = clean_test_dir("nested-mcp-config")
    (workdir / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local": {
                        "command": "node",
                        "args": "server.js api.local.example.com/mcp",
                        "env": {"LOCAL_API_KEY": "${LOCAL_API_KEY}"},
                        "transport": "stdio",
                    }
                },
                "profiles": {
                    "dev": {
                        "mcpServers": {
                            "docs": {
                                "type": "http",
                                "url": "https://docs.example.com/mcp",
                                "headers": {"Authorization": "Bearer ${DOCS_TOKEN}"},
                                "transport": {
                                    "type": "streamable-http",
                                    "endpoint": "https://stream.example.com/mcp",
                                },
                                "auth": {"token": "${AUTH_SECRET}"},
                            }
                        }
                    }
                },
                "example-server": {
                    "type": "http",
                    "serverUrl": "https://top.example.com/api",
                    "args": "legacy.args.example.com/path",
                },
            }
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    mcp_caps = {
        capability.resource: capability
        for capability in report.capabilities
        if capability.type == "mcp_server"
    }
    assert {"local", "profiles.dev.mcpServers.docs", "example-server"} <= set(mcp_caps)
    assert mcp_caps["local"].details["args"] == ["server.js api.local.example.com/mcp"]
    assert mcp_caps["local"].details["transport_type"] == "stdio"
    assert (
        mcp_caps["profiles.dev.mcpServers.docs"].details["config_path"]
        == "profiles.dev.mcpServers.docs"
    )
    assert mcp_caps["profiles.dev.mcpServers.docs"].details["headers"] == ["Authorization"]
    assert mcp_caps["profiles.dev.mcpServers.docs"].details["transport_type"] == "streamable-http"
    assert mcp_caps["example-server"].details["type"] == "http"
    hosts = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "network_egress"
    }
    assert {
        "api.local.example.com",
        "docs.example.com",
        "stream.example.com",
        "top.example.com",
        "legacy.args.example.com",
    } <= hosts


def test_mcp_config_reports_secret_names_without_secret_values() -> None:
    workdir = clean_test_dir("mcp-secret-redaction")
    (workdir / ".mcp.json").write_text(
        json.dumps(
            {
                "remote": {
                    "type": "http",
                    "url": "https://safe.example.com/mcp",
                    "headers": {
                        "Authorization": "Bearer ${REMOTE_TOKEN}",
                        "X-Client-Secret": "literal-secret-value",
                    },
                    "auth": {"apiKey": "${SERVICE_API_KEY}"},
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    report = scan_repository(workdir)
    rendered = stable_json(report)
    secret_resources = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "secret_access"
    }
    assert {"REMOTE_TOKEN", "SERVICE_API_KEY", "X-Client-Secret"} <= secret_resources
    assert "literal-secret-value" not in rendered
