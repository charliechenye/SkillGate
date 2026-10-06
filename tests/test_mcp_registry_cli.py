from __future__ import annotations

import http.client
import json

import pytest
from conftest import FIXTURES, REGISTRY_COMPARE_FIXTURE, clean_test_dir, runner

import skillgate.mcp_registry as mcp_registry
from skillgate.cli import app
from skillgate.mcp_registry import RegistryMetadataError


def test_cli_mcp_registry_scan_text_and_json() -> None:
    fixture = FIXTURES / "26-public-pattern-mcp-dangerous-transport"
    text = runner.invoke(app, ["mcp", "registry", "scan", str(fixture)])
    assert text.exit_code == 0
    assert "SkillGate MCP registry scan completed" in text.output
    assert "SG012" in text.output
    json_result = runner.invoke(
        app,
        ["mcp", "registry", "scan", str(fixture / "mcp-server.json"), "--format", "json"],
    )
    assert json_result.exit_code == 0
    data = json.loads(json_result.output)
    assert {finding["rule_id"] for finding in data["findings"]} == {"SG012"}


def test_cli_mcp_registry_compare_success_and_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    workdir = clean_test_dir("mcp-registry-compare")
    local = {
        "server": {
            "name": "io.example.compare",
            "version": "0.1.0",
            "repository": {"url": "https://github.com/example/compare"},
            "packages": [{"registryType": "npm", "identifier": "@example/compare"}],
        }
    }
    (workdir / "mcp-registry.json").write_text(json.dumps(local), encoding="utf-8")

    def matching_registry(_url: str) -> dict[str, object]:
        return {"servers": [local]}

    monkeypatch.setattr(mcp_registry, "fetch_registry_index", matching_registry)
    result = runner.invoke(
        app,
        ["mcp", "registry", "compare", str(workdir), "--server", "io.example.compare"],
    )
    assert result.exit_code == 0
    assert "SG013" not in result.output

    remote = json.loads(json.dumps(local))
    remote["server"]["repository"]["url"] = "https://github.com/example/other"

    def drifting_registry(_url: str) -> dict[str, object]:
        return {"servers": [remote]}

    monkeypatch.setattr(mcp_registry, "fetch_registry_index", drifting_registry)
    drift = runner.invoke(
        app,
        ["mcp", "registry", "compare", str(workdir), "--server", "io.example.compare"],
    )
    assert drift.exit_code == 0
    assert "SG013" in drift.output
    failed = runner.invoke(
        app,
        [
            "mcp",
            "registry",
            "compare",
            str(workdir),
            "--server",
            "io.example.compare",
            "--fail-on-drift",
        ],
    )
    assert failed.exit_code == 1


def test_cli_mcp_registry_compare_fetch_error_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    workdir = clean_test_dir("mcp-registry-compare-error")
    (workdir / "mcp-registry.json").write_text(
        json.dumps({"server": {"name": "io.example.compare", "version": "0.1.0"}}),
        encoding="utf-8",
    )

    def broken_registry(_url: str) -> dict[str, object]:
        raise RegistryMetadataError("registry unavailable")

    monkeypatch.setattr(mcp_registry, "fetch_registry_index", broken_registry)
    result = runner.invoke(
        app,
        ["mcp", "registry", "compare", str(workdir), "--server", "io.example.compare"],
    )
    assert result.exit_code == 2
    assert "registry unavailable" in result.output


@pytest.mark.parametrize(
    "registry_url",
    [
        "https://{HOST}/servers",
        "https://api.example.invalid:invalid/servers",
    ],
)
def test_cli_mcp_registry_compare_rejects_invalid_registry_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path, registry_url: str
) -> None:
    (tmp_path / "mcp-registry.json").write_text(
        json.dumps({"server": {"name": "io.example.compare", "version": "0.1.0"}}),
        encoding="utf-8",
    )

    def unexpected_request(*_args, **_kwargs):
        pytest.fail("Invalid registry URLs must fail before a network request")

    monkeypatch.setattr("urllib.request.urlopen", unexpected_request)
    result = runner.invoke(
        app,
        [
            "mcp",
            "registry",
            "compare",
            str(tmp_path),
            "--server",
            "io.example.compare",
            "--registry-url",
            registry_url,
        ],
    )
    assert result.exit_code == 2
    assert "invalid registry URL" in result.output
    assert "Traceback" not in result.output


def test_cli_mcp_registry_compare_normalizes_http_invalid_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    (tmp_path / "mcp-registry.json").write_text(
        json.dumps({"server": {"name": "io.example.compare", "version": "0.1.0"}}),
        encoding="utf-8",
    )

    def invalid_url(*_args, **_kwargs):
        raise http.client.InvalidURL("URL can't contain control characters")

    monkeypatch.setattr("urllib.request.urlopen", invalid_url)
    result = runner.invoke(
        app,
        [
            "mcp",
            "registry",
            "compare",
            str(tmp_path),
            "--server",
            "io.example.compare",
            "--registry-url",
            "https://registry.example.invalid/a b",
        ],
    )
    assert result.exit_code == 2
    assert "invalid registry URL" in result.output
    assert "Traceback" not in result.output


def test_cli_mcp_registry_compare_fixture_reports_sg013() -> None:
    result = runner.invoke(
        app,
        [
            "mcp",
            "registry",
            "compare",
            str(REGISTRY_COMPARE_FIXTURE / "local"),
            "--server",
            "io.example.registry-drift",
            "--registry-url",
            str(REGISTRY_COMPARE_FIXTURE / "registry.json"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    drift_findings = [finding for finding in data["findings"] if finding["rule_id"] == "SG013"]
    assert drift_findings
    assert any("repository" in finding["evidence"] for finding in drift_findings)
    assert any(capability["type"] == "mcp_registry_drift" for capability in data["capabilities"])
    assert data["summary"]["registry_drift"]
    assert "repository" in {row["field"] for row in data["summary"]["registry_drift"]}


def test_cli_mcp_registry_compare_markdown_renders_drift_table() -> None:
    result = runner.invoke(
        app,
        [
            "mcp",
            "registry",
            "compare",
            str(REGISTRY_COMPARE_FIXTURE / "local"),
            "--server",
            "io.example.registry-drift",
            "--registry-url",
            str(REGISTRY_COMPARE_FIXTURE / "registry.json"),
            "--format",
            "markdown",
        ],
    )
    assert result.exit_code == 0
    assert "# SkillGate MCP Registry Comparison" in result.output
    assert "| Field | Local | Registry | Source |" in result.output
    assert "repository" in result.output
    assert "remote_urls" in result.output


def test_cli_mcp_registry_compare_sarif_category_and_exit_codes() -> None:
    result = runner.invoke(
        app,
        [
            "mcp",
            "registry",
            "compare",
            str(REGISTRY_COMPARE_FIXTURE / "local"),
            "--server",
            "io.example.registry-drift",
            "--registry-url",
            str(REGISTRY_COMPARE_FIXTURE / "registry.json"),
            "--format",
            "sarif",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["runs"][0]["automationDetails"]["id"] == "skillgate/mcp-registry-compare"
    assert any(item["ruleId"] == "SG013" for item in data["runs"][0]["results"])

    failed = runner.invoke(
        app,
        [
            "mcp",
            "registry",
            "compare",
            str(REGISTRY_COMPARE_FIXTURE / "local"),
            "--server",
            "io.example.registry-drift",
            "--registry-url",
            str(REGISTRY_COMPARE_FIXTURE / "registry.json"),
            "--format",
            "sarif",
            "--fail-on-drift",
        ],
    )
    assert failed.exit_code == 1
