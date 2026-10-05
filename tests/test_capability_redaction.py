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


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("GITHUB_TOKEN=abc", "GITHUB_TOKEN=<redacted>"),
        ('GITHUB_TOKEN="abc def"', "GITHUB_TOKEN=<redacted>"),
        ("GITHUB_TOKEN='abc def'", "GITHUB_TOKEN=<redacted>"),
        ('OPENAI_API_KEY="abc def ghi"', "OPENAI_API_KEY=<redacted>"),
        ("AWS_SECRET_ACCESS_KEY='one two three'", "AWS_SECRET_ACCESS_KEY=<redacted>"),
        ("AZURE_CLIENT_SECRET=abc", "AZURE_CLIENT_SECRET=<redacted>"),
        ("SERVICE_PASSWORD='hello world'", "SERVICE_PASSWORD=<redacted>"),
        ('SERVICE_CREDENTIALS="credential value"', "SERVICE_CREDENTIALS=<redacted>"),
        ("GITHUB_TOKEN : abc", "GITHUB_TOKEN=<redacted>"),
        (
            'GITHUB_TOKEN="abc def" curl https://example.invalid/data',
            "GITHUB_TOKEN=<redacted> curl https://example.invalid/data",
        ),
    ],
)
def test_secret_assignment_redaction_consumes_complete_values(command: str, expected: str) -> None:
    capability = make_capability("shell_execution", "helper.sh", 1, command=command)

    assert capability.details["command"] == expected
    assert "abc" not in capability.details["command"]
    assert "def" not in capability.details["command"]


def test_secret_assignment_redaction_handles_escaped_quotes() -> None:
    command = r'TOKEN="abc \"def\" ghi" curl https://example.invalid/data'
    capability = make_capability("shell_execution", "helper.sh", 1, command=command)

    assert capability.details["command"] == "TOKEN=<redacted> curl https://example.invalid/data"


@pytest.mark.parametrize(
    "command",
    ["MONKEY=value bash setup.sh", "KEYBOARD_LAYOUT=qwerty", "HOCKEY=ice"],
)
def test_non_secret_assignment_names_remain_unchanged(command: str) -> None:
    capability = make_capability("shell_execution", "helper.sh", 1, command=command)

    assert capability.details["command"] == command


def test_scan_sarif_redacts_command_secrets() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "35-command-secret-redaction"),
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "skillgate_dummy_canary" not in result.output
    assert "GITHUB_TOKEN" in result.output


def test_preinstall_packet_json_redacts_command_secrets() -> None:
    result = runner.invoke(
        app,
        [
            "review",
            "preinstall",
            str(FIXTURES / "35-command-secret-redaction"),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "skillgate_dummy_canary" not in result.output
    assert "GITHUB_TOKEN" in result.output
