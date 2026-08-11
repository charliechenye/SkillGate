from __future__ import annotations

import json
import zipfile
from pathlib import Path

from conftest import ROOT, clean_test_dir, runner

from skillgate.cli import app

SKILLS_FIXTURES = ROOT / "fixtures" / "skills-validation"
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


def test_valid_skill_zip_is_extracted_and_validated_without_directory_name_finding(
    tmp_path: Path,
) -> None:
    archive = write_skill_zip(
        tmp_path,
        {
            "SKILL.md": PACKAGED_SKILL,
            "references/guide.md": "# Guide\n",
        },
    )
    result = runner.invoke(app, ["skills", "validate", str(archive), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["root"] == "."
    assert payload["archive"]["archive"]["format"] == "zip"
    assert payload["skills"][0]["path"] == "SKILL.md"
    assert payload["findings"] == []


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
