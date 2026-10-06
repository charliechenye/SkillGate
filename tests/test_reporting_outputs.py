from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import FIXTURES, runner

from skillgate.cli import app


@pytest.mark.parametrize(
    "command",
    [
        ["scan", str(FIXTURES / "01-safe-documentation-skill"), "--format", "json"],
        ["scan", str(FIXTURES / "05-remote-download-execute"), "--format", "sarif"],
        ["review", "schema"],
    ],
)
def test_common_report_writer_creates_nested_directories(
    tmp_path: Path, command: list[str]
) -> None:
    output = tmp_path / "reports" / "nested" / "result.json"
    result = runner.invoke(app, [*command, "--output", str(output)])
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())
