from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from conftest import ROOT, clean_test_dir, runner

from skillgate.cli import app
from skillgate.skills import validate_skill_file_result

SKILLS_FIXTURES = ROOT / "fixtures" / "skills-validation"
ARCHIVE_SKILL_FIXTURE = ROOT / "fixtures" / "skills-validation-archives" / "valid-archive"
PACKAGED_SKILL = """---
name: packaged-skill
description: A packaged skill.
license: MIT
compatibility: local
---

# Packaged
"""


def write_skill_zip(tmp_path: Path, entries: dict[str, str]) -> Path:
    archive_path = tmp_path / "skill.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return archive_path


def zip_skill_directory(tmp_path: Path, source: Path, name: str = "skill.zip") -> Path:
    archive_path = tmp_path / name
    with zipfile.ZipFile(archive_path, "w") as archive:
        for source_path in sorted(path for path in source.rglob("*") if path.is_file()):
            member = zipfile.ZipInfo(source_path.relative_to(source).as_posix())
            member.date_time = (1980, 1, 1, 0, 0, 0)
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, source_path.read_bytes())
    return archive_path


def invoke(path: str, *args: str):
    return runner.invoke(app, ["skills", "validate", str(SKILLS_FIXTURES / path), *args])


def write_skill(path: Path, frontmatter: str, body: str = "\nInstructions.\n") -> Path:
    path.mkdir(parents=True)
    skill = path / "SKILL.md"
    skill.write_text(f"---\n{frontmatter}\n---\n{body}", encoding="utf-8")
    return skill


def skill_result(tmp_path: Path, name: str, frontmatter: str):
    skill_path = write_skill(tmp_path / name, frontmatter)
    return validate_skill_file_result(skill_path, tmp_path)


def test_current_agent_skills_frontmatter_is_conformant(tmp_path: Path) -> None:
    result = skill_result(
        tmp_path,
        "unicode-данные",
        """name: unicode-данные
description: A skill with current Agent Skills metadata.
compatibility: local
metadata:
  owner: example
  version: '1.0'
allowed-tools: Bash(git:*) Bash(jq:*) Read""",
    )

    assert result.conformant is True
    assert result.conformance_diagnostics == ()
    assert not any(item["code"] == "SKILL006" for item in result.advisory_findings)


@pytest.mark.parametrize(
    ("name", "extra", "code"),
    [
        ("a" * 65, "", "skill_name_too_long"),
        ("Bad-name", "", "skill_invalid_name"),
        ("bad--name", "", "skill_invalid_name"),
        ("-bad", "", "skill_invalid_name"),
        ("bad-", "", "skill_invalid_name"),
        ("valid-name", "unknown: value", "skill_unknown_frontmatter_field"),
    ],
)
def test_agent_skills_name_and_field_constraints_are_conformance_errors(
    tmp_path: Path,
    name: str,
    extra: str,
    code: str,
) -> None:
    result = skill_result(
        tmp_path,
        name,
        f"name: {name}\ndescription: Valid description\n{extra}",
    )

    assert result.conformant is False
    assert code in {item["code"] for item in result.conformance_diagnostics}


def test_agent_skills_description_and_compatibility_bounds_are_enforced(tmp_path: Path) -> None:
    description = skill_result(
        tmp_path / "description",
        "valid-name",
        f"name: valid-name\ndescription: {'x' * 1025}",
    )
    compatibility = skill_result(
        tmp_path / "compatibility",
        "valid-name",
        f"name: valid-name\ndescription: Valid\ncompatibility: {'x' * 501}",
    )
    valid_compatibility = skill_result(
        tmp_path / "compatibility-valid",
        "valid-name",
        f"name: valid-name\ndescription: Valid\ncompatibility: {'x' * 500}",
    )

    assert "skill_description_too_long" in {
        item["code"] for item in description.conformance_diagnostics
    }
    assert "skill_invalid_compatibility" in {
        item["code"] for item in compatibility.conformance_diagnostics
    }
    assert valid_compatibility.conformant is True


def test_agent_skills_optional_types_and_allowed_tools_are_strict(tmp_path: Path) -> None:
    invalid = skill_result(
        tmp_path / "invalid",
        "valid-name",
        """name: valid-name
description: Valid
license: 3
metadata:
  owner: 3
allowed-tools:
  - Read""",
    )

    codes = {item["code"] for item in invalid.conformance_diagnostics}
    assert {
        "skill_invalid_license",
        "skill_invalid_metadata",
        "skill_invalid_allowed_tools",
    } <= codes
    assert {item["code"] for item in invalid.advisory_findings} >= {
        "SKILL006",
        "SKILL010",
        "SKILL011",
    }


def test_agent_skills_directory_name_mismatch_is_not_advisory_only(tmp_path: Path) -> None:
    result = skill_result(
        tmp_path,
        "directory-name",
        "name: declared-name\ndescription: Valid",
    )

    assert result.conformant is False
    assert "skill_directory_name_mismatch" in {
        item["code"] for item in result.conformance_diagnostics
    }


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


def test_valid_skill_zip_is_extracted_and_validated_without_directory_name_finding(
    tmp_path: Path,
) -> None:
    archive = zip_skill_directory(tmp_path, ARCHIVE_SKILL_FIXTURE)
    result = runner.invoke(app, ["skills", "validate", str(archive), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["root"] == "."
    assert payload["archive"]["archive"]["format"] == "zip"
    assert payload["skills"][0]["path"] == "SKILL.md"
    assert payload["skills"][0]["name"] == "packaged-skill"
    assert payload["findings"] == []


def test_fixture_skill_zip_manifest_is_deterministic(tmp_path: Path) -> None:
    first = zip_skill_directory(tmp_path, ARCHIVE_SKILL_FIXTURE, "first.zip")
    second = zip_skill_directory(tmp_path, ARCHIVE_SKILL_FIXTURE, "second.zip")
    first_result = runner.invoke(app, ["skills", "validate", str(first), "--format", "json"])
    second_result = runner.invoke(app, ["skills", "validate", str(second), "--format", "json"])

    assert first_result.exit_code == second_result.exit_code == 0
    first_payload = json.loads(first_result.output)
    second_payload = json.loads(second_result.output)
    assert (
        first_payload["archive"]["archive"]["sha256"]
        == second_payload["archive"]["archive"]["sha256"]
    )
    assert first_payload["archive"]["members"] == second_payload["archive"]["members"]


def test_skill_zip_keeps_static_findings_for_packaged_files(tmp_path: Path) -> None:
    archive = write_skill_zip(
        tmp_path,
        {
            "SKILL.md": PACKAGED_SKILL + "\nUse scripts/install.sh only when requested.\n",
            "install.sh": "#!/usr/bin/env bash\nprintf '%s\\n' packaged\n",
        },
    )
    result = runner.invoke(app, ["skills", "validate", str(archive), "--format", "json"])

    assert result.exit_code == 0
    assert "SKILL009" in {finding["code"] for finding in json.loads(result.output)["findings"]}


def test_skill_zip_requires_root_skill_file(tmp_path: Path) -> None:
    archive = write_skill_zip(
        tmp_path,
        {"packaged-skill/SKILL.md": "---\nname: packaged-skill\n---\n"},
    )
    result = runner.invoke(app, ["skills", "validate", str(archive), "--format", "json"])

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["error"]["code"] == "skills_validation_error"
    assert "root-level SKILL.md" in payload["error"]["message"]


def test_skill_zip_reports_archive_safety_errors(tmp_path: Path) -> None:
    archive = write_skill_zip(tmp_path, {"../SKILL.md": "malicious path"})
    result = runner.invoke(app, ["skills", "validate", str(archive), "--format", "json"])

    assert result.exit_code == 2
    assert json.loads(result.output)["error"]["code"] == "unsafe_path"
