from __future__ import annotations

from pathlib import Path

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


@pytest.mark.parametrize(
    "call",
    [
        'child_process.exec("echo hello > " + output)',
        'child_process.execSync("echo hello > " + output)',
        "child_process.exec(`echo hello > ${output}`)",
        'child_process.spawn("echo", ["hello > " + output], {shell: true})',
        'child_process.spawnSync("echo", ["hello > " + output], {shell: true})',
    ],
)
def test_javascript_dynamic_shell_redirect_keeps_unknown_write(call: str) -> None:
    result = FilesystemWriteRule().analyze(FileContent("helper.js", "script", call))

    assert {item.resource for item in result.capabilities} == {None}


def test_javascript_spawn_argv_data_is_not_a_shell_redirect() -> None:
    text = 'child_process.spawn("echo", ["hello > " + output])'

    assert (
        FilesystemWriteRule().analyze(FileContent("helper.js", "script", text)).capabilities == []
    )


def test_javascript_dynamic_shell_redirect_cannot_bypass_filesystem_policy(tmp_path) -> None:
    (tmp_path / "SKILL.md").write_text("Review `helper.js`.\n", encoding="utf-8")
    (tmp_path / "helper.js").write_text(
        'child_process.exec("echo hello > " + output)\n', encoding="utf-8"
    )

    report = scan_repository(tmp_path)

    assert evaluate_policy(report, {"version": 1, "policy": {"filesystem": {"write": []}}}).blocked


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


@pytest.mark.parametrize(
    ("suffix", "text", "targets"),
    [
        (
            "py",
            'Path("generated/ok.txt").write_text("ok"); Path("forbidden.txt").write_text("bad")',
            {"generated/ok.txt", "forbidden.txt"},
        ),
        (
            "py",
            'open("generated/ok.txt", "w"); open("forbidden.txt", "wb")',
            {"generated/ok.txt", "forbidden.txt"},
        ),
        (
            "js",
            'fs.writeFile("generated/ok.txt", data); fs.appendFile("forbidden.txt", data)',
            {"generated/ok.txt", "forbidden.txt"},
        ),
        (
            "sh",
            "printf ok > generated/ok.txt; printf bad > forbidden.txt",
            {"generated/ok.txt", "forbidden.txt"},
        ),
        (
            "sh",
            "printf ok | tee generated/ok.txt forbidden.txt",
            {"generated/ok.txt", "forbidden.txt"},
        ),
        (
            "sh",
            "printf ok | tee generated/ok.txt > forbidden.txt",
            {"generated/ok.txt", "forbidden.txt"},
        ),
        (
            "py",
            'Path(output).write_text("bad"); Path("generated/ok.txt").write_text("ok")',
            {None, "generated/ok.txt"},
        ),
        ("js", 'fs.writeFile("generated/" + "../forbidden.txt", data)', {None}),
        ("js", 'fs.writeFile("generated/" + output, data)', {None}),
        ("py", r'Path("generated/\x2e\x2e/forbidden.txt").write_text("bad")', {None}),
        ("py", r'Path("generated/\x6futput.txt").write_text("ok")', {"generated/output.txt"}),
        ("js", r'fs.writeFile("generated/\x2e\x2e/forbidden.txt", data)', {None}),
        ("py", 'Path("generated/../forbidden.txt").write_text("bad")', {None}),
        (
            "py",
            'Path("generated/ok.txt").write_text("ok"); '
            'subprocess.run("echo bad > forbidden.txt", shell=True)',
            {"generated/ok.txt", "forbidden.txt"},
        ),
    ],
)
def test_write_targets_are_bound_to_each_operation(
    suffix: str, text: str, targets: set[str | None]
) -> None:
    result = FilesystemWriteRule().analyze(FileContent(f"helper.{suffix}", "script", text))
    assert {item.resource for item in result.capabilities} == targets


@pytest.mark.parametrize("format_aware", [False, True])
@pytest.mark.parametrize(
    ("suffix", "text", "blocked"),
    [
        (
            "py",
            'Path("generated/ok.txt").write_text("ok"); Path("forbidden.txt").write_text("bad")',
            True,
        ),
        ("sh", "printf ok > generated/ok.txt; printf bad > forbidden.txt", True),
        ("js", 'fs.writeFile("generated/" + "../forbidden.txt", data)', True),
        ("py", r'Path("generated/\x2e\x2e/forbidden.txt").write_text("bad")', True),
        ("py", r'Path("generated/\x6futput.txt").write_text("ok")', False),
        ("js", 'fs.writeFile("generated/ok.txt", data)', False),
    ],
)
def test_file_target_extraction_cannot_bypass_directory_allowlist(
    tmp_path: Path, suffix: str, text: str, blocked: bool, format_aware: bool
) -> None:
    (tmp_path / "SKILL.md").write_text(f"Review `helper.{suffix}` statically.\n")
    (tmp_path / f"helper.{suffix}").write_text(text)
    report = scan_repository(tmp_path, format_aware=format_aware)
    result = evaluate_policy(
        report, {"version": 1, "policy": {"filesystem": {"write": ["generated/**"]}}}
    )
    assert result.blocked is blocked
