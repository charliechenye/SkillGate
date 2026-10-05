from __future__ import annotations

import pytest
from conftest import FIXTURES

from skillgate.policy import evaluate_policy
from skillgate.rules.base import FileContent
from skillgate.rules.script_rules import FilesystemWriteRule
from skillgate.scan import scan_repository


@pytest.mark.parametrize(
    ("prefix", "clause"),
    [
        ("if ready:\n    pass\n", "else"),
        ("if ready:\n    pass\n", "elif other"),
        ("try:\n    pass\n", "except ValueError"),
        ("try:\n    pass\n", "finally"),
    ],
)
@pytest.mark.parametrize("format_aware", [False, True])
def test_python_control_clause_retains_shell_redirect(
    prefix: str, clause: str, format_aware: bool
) -> None:
    text = prefix + f'{clause}: subprocess.run("printf bad > forbidden.txt", shell=True)\n'
    result = FilesystemWriteRule().analyze(FileContent("helper.py", "script", text, format_aware))
    assert {(item.source_line, item.resource) for item in result.capabilities} == {
        (3, "forbidden.txt")
    }


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run(["echo", "value > limit"])',
        'subprocess.run("echo value > limit", shell=False)',
        'subprocess.run(["echo", "value > limit"], shell=True)',
    ],
)
def test_control_clause_argv_data_remains_clean(call: str) -> None:
    text = "if ready:\n    pass\nelse: " + call
    assert (
        FilesystemWriteRule().analyze(FileContent("helper.py", "script", text)).capabilities == []
    )


@pytest.mark.parametrize("format_aware", [False, True])
def test_fenced_python_control_clause_keeps_original_line(format_aware: bool) -> None:
    text = (
        "# Example\n\n```python\nif ready:\n    pass\n"
        'else: os.system("echo bad > forbidden.txt")\n```\n'
    )
    result = FilesystemWriteRule().analyze(FileContent("SKILL.md", "markdown", text, format_aware))
    assert {(item.source_line, item.resource) for item in result.capabilities} == {
        (6, "forbidden.txt")
    }


@pytest.mark.parametrize("format_aware", [False, True])
def test_contextual_redirects_are_blocked_by_filesystem_policy(format_aware: bool) -> None:
    report = scan_repository(FIXTURES / "39-python-shell-context", format_aware=format_aware)
    assert {item.resource for item in report.capabilities if item.type == "filesystem_write"} == {
        "else.txt",
        "except.txt",
    }
    assert evaluate_policy(report, {"version": 1, "policy": {"filesystem": {"write": []}}}).blocked
