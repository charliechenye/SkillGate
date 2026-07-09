from __future__ import annotations

import json

from conftest import ROOT, clean_test_dir, runner

from skillgate.cli import app

SKILLS_FIXTURES = ROOT / "fixtures" / "skills-validation"


def invoke(path: str, *args: str):
    return runner.invoke(app, ["skills", "validate", str(SKILLS_FIXTURES / path), *args])


def test_valid_minimal_skill_supports_direct_file_input() -> None:
    result = runner.invoke(
        app,
        [
            "skills",
            "validate",
            str(SKILLS_FIXTURES / "valid-minimal" / "SKILL.md"),
        ],
    )
    assert result.exit_code == 0
    assert "Skills: 1" in result.output
    assert "Findings: 0" in result.output


def test_valid_complex_skill_returns_structured_json() -> None:
    result = invoke("valid-complex", "--format", "json")
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1"
    assert payload["skills"][0]["name"] == "valid-complex"
    assert payload["findings"] == []


def test_directory_input_recursively_discovers_skills() -> None:
    result = runner.invoke(app, ["skills", "validate", str(SKILLS_FIXTURES), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"]["skills"] == 8
    assert {skill["name"] for skill in payload["skills"]} == {
        "broad-allowed-tools",
        "declared-name",
        None,
        "missing-reference",
        "misplaced-executable",
        "valid-complex",
        "valid-minimal",
    }


def test_validation_finds_malformed_and_missing_metadata() -> None:
    malformed = invoke("malformed-frontmatter", "--format", "json")
    missing = invoke("missing-required", "--format", "json")
    assert {finding["code"] for finding in json.loads(malformed.output)["findings"]} >= {
        "SKILL001",
        "SKILL002",
    }
    assert "SKILL002" in {finding["code"] for finding in json.loads(missing.output)["findings"]}


def test_validation_finds_name_reference_executable_and_broad_tool_findings() -> None:
    assert "SKILL004" in {
        finding["code"]
        for finding in json.loads(invoke("name-mismatch", "--format", "json").output)["findings"]
    }
    assert "SKILL008" in {
        finding["code"]
        for finding in json.loads(invoke("missing-reference", "--format", "json").output)[
            "findings"
        ]
    }
    assert "SKILL009" in {
        finding["code"]
        for finding in json.loads(invoke("misplaced-executable", "--format", "json").output)[
            "findings"
        ]
    }
    misplaced_findings = json.loads(invoke("misplaced-executable", "--format", "json").output)[
        "findings"
    ]
    assert {finding["evidence"] for finding in misplaced_findings} >= {
        "install.sh",
        ".hidden-helper",
    }
    assert "SKILL007" in {
        finding["code"]
        for finding in json.loads(invoke("broad-allowed-tools", "--format", "json").output)[
            "findings"
        ]
    }


def test_fail_on_low_blocks_advisory_findings() -> None:
    result = invoke("missing-required", "--fail-on", "low")
    assert result.exit_code == 1
    assert "FAILED" not in result.output


def test_output_option_writes_validation_report() -> None:
    workdir = clean_test_dir("skills-validation-output")
    output = workdir / "skills.json"
    result = invoke("valid-complex", "--format", "json", "--output", str(output))
    assert result.exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["findings"] == 0
    assert result.output == ""


def test_invalid_skill_validation_path_exits_two() -> None:
    result = runner.invoke(app, ["skills", "validate", str(SKILLS_FIXTURES / "missing")])
    assert result.exit_code == 2
    assert "does not exist" in result.output
