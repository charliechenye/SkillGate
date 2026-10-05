from __future__ import annotations

import pytest
from conftest import FIXTURES

from skillgate.policy import evaluate_policy
from skillgate.rules.base import FileContent
from skillgate.rules.script_rules import FilesystemWriteRule
from skillgate.scan import scan_repository


@pytest.mark.parametrize(
    "mode",
    [
        "w",
        "wb",
        "wt",
        "w+",
        "wb+",
        "w+b",
        "a",
        "ab",
        "a+",
        "ab+",
        "x",
        "xb",
        "x+",
        "r+",
        "rb+",
        "r+b",
    ],
)
@pytest.mark.parametrize("keyword", ["", "mode="])
def test_python_write_modes_keep_the_target(mode: str, keyword: str) -> None:
    file = FileContent("helper.py", "script", f'handle = open("forbidden.bin", {keyword}"{mode}")')
    result = FilesystemWriteRule().analyze(file)
    assert {item.resource for item in result.capabilities} == {"forbidden.bin"}


@pytest.mark.parametrize(
    "arguments",
    [
        '"input.txt"',
        '"input.txt", "r"',
        '"input.txt", "rb"',
        '"input.txt", mode="rt"',
        '"wax", "r"',
    ],
)
def test_python_read_modes_do_not_add_writes(arguments: str) -> None:
    result = FilesystemWriteRule().analyze(FileContent("helper.py", "script", f"open({arguments})"))
    assert result.capabilities == []


@pytest.mark.parametrize("format_aware", [False, True])
def test_write_modes_cannot_bypass_filesystem_policy(format_aware: bool) -> None:
    report = scan_repository(FIXTURES / "37-python-write-modes", format_aware=format_aware)
    assert {item.resource for item in report.capabilities} == {
        "binary.bin",
        "append.txt",
        "existing.bin",
        "exclusive.txt",
    }
    assert evaluate_policy(report, {"version": 1, "policy": {"filesystem": {"write": []}}}).blocked
