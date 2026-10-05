from __future__ import annotations

import json

import pytest
from conftest import FIXTURES, runner

from skillgate.cli import app
from skillgate.rules.base import make_capability


@pytest.mark.parametrize("format_aware", [False, True])
def test_scan_json_redacts_command_secrets(format_aware: bool) -> None:
    command = [
        "scan",
        str(FIXTURES / "35-command-secret-redaction"),
        "--format",
        "json",
    ]
    if format_aware:
        command.append("--format-aware")
    result = runner.invoke(app, command)
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert "skillgate_dummy_canary" not in result.output
    assert {
        item["resource"] for item in data["capabilities"] if item["type"] == "secret_access"
    } == {"GITHUB_TOKEN"}
    assert any(
        "<redacted>" in item.get("details", {}).get("command", "") for item in data["capabilities"]
    )


def test_nested_capability_details_are_redacted_without_changing_shape() -> None:
    capability = make_capability(
        "shell_execution",
        "helper.sh",
        1,
        options={"commands": ["GITHUB_TOKEN=skillgate_dummy_canary bash setup.sh", "echo done"]},
        secret_names=["GITHUB_TOKEN"],
        enabled=True,
        count=2,
    )
    assert capability.details == {
        "count": 2,
        "enabled": True,
        "options": {"commands": ["GITHUB_TOKEN=<redacted> bash setup.sh", "echo done"]},
        "secret_names": ["GITHUB_TOKEN"],
    }
