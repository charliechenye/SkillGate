from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from skillgate import __version__
from skillgate.archive import archive_manifest, inspect_archive
from skillgate.discovery import EXCLUDED_DIRS, SCRIPT_EXTENSIONS
from skillgate.models import SEVERITY_ORDER, stable_json

SKILL_SCHEMA_VERSION = "1"
SKILL_FILE = "SKILL.md"
# Kept as a compatibility export for callers that imported the old helper. The
# validator uses _valid_skill_name because Python's regular-expression
# character classes do not express the spec's lowercase-Unicode constraint
# precisely enough.
SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SKILL_FRONTMATTER_FIELDS = frozenset(
    {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
)
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
SCRIPT_REFERENCE_RE = re.compile(
    r"(?P<path>(?:\.{1,2}/)?[A-Za-z0-9_./\\-]+"
    r"\.(?:sh|bash|py|js|ts|mjs|cjs|ps1))"
)
BROAD_ALLOWED_TOOLS = {"*", "bash", "shell", "python", "node"}

FINDING_DOCS = {
    "SKILL001": (
        "Malformed frontmatter",
        "The top-of-file YAML frontmatter could not be parsed.",
        "medium",
        "Fix the YAML between the opening and closing `---` delimiters.",
    ),
    "SKILL002": (
        "Missing required skill metadata",
        "A skill must declare a non-empty string `name` and `description`.",
        "high",
        "Add `name` and `description` to the skill frontmatter.",
    ),
    "SKILL003": (
        "Invalid skill name",
        "Skill names should use lowercase slug-style characters.",
        "medium",
        "Use lowercase letters, digits, and single hyphens between words.",
    ),
    "SKILL004": (
        "Skill directory does not match name",
        "The skill directory name should match its declared `name`.",
        "medium",
        "Rename the directory or update the frontmatter name.",
    ),
    "SKILL005": (
        "Recommended skill metadata is missing",
        "`license` and `compatibility` help downstream users understand reuse and "
        "runtime expectations.",
        "low",
        "Add `license` and `compatibility` when publishing the skill.",
    ),
    "SKILL006": (
        "Invalid allowed-tools metadata",
        "`allowed-tools` must be a space-separated string.",
        "medium",
        "Use a YAML string containing narrowly scoped tool names separated by spaces.",
    ),
    "SKILL007": (
        "Broad allowed tool",
        "The declared tool access is broad enough to require author review.",
        "medium",
        "Replace broad tool access with the smallest set of required tools.",
    ),
    "SKILL008": (
        "Missing referenced skill file",
        "A local path under scripts, references, or assets was referenced but was not found.",
        "medium",
        "Add the referenced file or correct the local path.",
    ),
    "SKILL009": (
        "Executable outside scripts directory",
        "Script-like or executable files outside `scripts/` are easy to overlook during review.",
        "high",
        "Move executable content under `scripts/` or remove the executable bit.",
    ),
    "SKILL010": (
        "Invalid optional skill metadata",
        "Optional Agent Skills fields must use the types and bounds defined by the specification.",
        "medium",
        "Fix the type or length of `license` or `compatibility`.",
    ),
    "SKILL011": (
        "Invalid metadata map",
        "`metadata` must be a mapping whose keys and values are strings.",
        "medium",
        "Use string keys and string values under `metadata`.",
    ),
    "SKILL012": (
        "Unknown frontmatter field",
        "The Agent Skills specification only permits its defined frontmatter fields.",
        "medium",
        "Move client-specific data under `metadata` or remove the unknown field.",
    ),
    "SKILL013": (
        "Invalid skill description",
        "The required skill description must be non-empty and at most 1024 characters.",
        "medium",
        "Shorten the description to 1024 characters or fewer.",
    ),
}


class SkillsValidationError(ValueError):
    """Raised when a skills validation input cannot be read or discovered."""


@dataclass(frozen=True)
class SkillValidationResult:
    """Separate specification conformance from SkillGate review signals."""

    skill: dict[str, Any]
    conformant: bool
    conformance_diagnostics: tuple[dict[str, Any], ...]
    advisory_findings: tuple[dict[str, Any], ...]


def discover_skill_files(path: Path) -> list[Path]:
    path = path.expanduser().resolve()
    if not path.exists():
        raise SkillsValidationError(f"path does not exist: {path}")
    if path.is_file():
        if path.name != SKILL_FILE:
            raise SkillsValidationError(f"expected a SKILL.md file or directory: {path}")
        return [path]
    if not path.is_dir():
        raise SkillsValidationError(f"path is not readable: {path}")

    direct = path / SKILL_FILE
    if direct.is_file():
        return [direct]

    found: list[Path] = []
    for current, dirnames, filenames in os.walk(path):
        current_path = Path(current)
        dirnames[:] = sorted(name for name in dirnames if name not in EXCLUDED_DIRS)
        if SKILL_FILE in filenames:
            found.append(current_path / SKILL_FILE)
    return sorted(found)


def _line_number(text: str, needle: str) -> int:
    if not needle:
        return 1
    index = text.find(needle)
    return text.count("\n", 0, max(index, 0)) + 1


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], int | None, str | None]:
    if not text.startswith("---"):
        return {}, None, None
    first_line_end = text.find("\n")
    if first_line_end < 0 or text[:first_line_end].strip() != "---":
        return {}, None, None
    lines = text.splitlines()
    closing_index = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
        None,
    )
    if closing_index is None:
        return {}, 1, "frontmatter is missing the closing --- delimiter"
    raw = "\n".join(lines[1:closing_index])
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return {}, 1, str(exc).splitlines()[0]
    if data is None:
        return {}, 1, "frontmatter must contain a YAML mapping"
    if not isinstance(data, dict):
        return {}, 1, "frontmatter must contain a YAML mapping"
    # Keep the parsed values intact for conformance checks. Converting values
    # to JSON-safe strings here would make invalid YAML types look valid (for
    # example, a date-valued metadata entry).
    return data, None, None


def _finding(
    code: str,
    skill_path: Path,
    root: Path,
    *,
    line: int | None = None,
    evidence: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    title, default_description, severity, remediation = FINDING_DOCS[code]
    file_path = skill_path.relative_to(root).as_posix()
    fingerprint_source = f"{code}:{file_path}:{line or 1}:{evidence or ''}"
    finding_id = hashlib.sha256(fingerprint_source.encode()).hexdigest()[:16]
    return {
        "id": finding_id,
        "code": code,
        "rule_id": code,
        "title": title,
        "description": description or default_description,
        "severity": severity,
        "capability": "skill_structure",
        "file_path": file_path,
        "line_number": line or 1,
        "evidence": evidence,
        "remediation": remediation,
    }


def _local_reference(raw: str) -> str | None:
    value = raw.strip().strip("<>").split("#", 1)[0].split("?", 1)[0]
    if not value or "://" in value or value.startswith(("/", "#")):
        return None
    value = value.replace("\\", "/")
    parts = Path(value).parts
    if any(part == ".." for part in parts):
        return None
    if not any(part in {"scripts", "references", "assets"} for part in parts):
        return None
    return value


def _referenced_paths(content: str) -> list[str]:
    references = [match.group(1) for match in MARKDOWN_LINK_RE.finditer(content)]
    references.extend(match.group("path") for match in SCRIPT_REFERENCE_RE.finditer(content))
    paths = {_local_reference(reference) for reference in references}
    return sorted(path for path in paths if path is not None)


def _conformance_diagnostic(
    code: str,
    message: str,
    *,
    line: int | None = None,
    evidence: str | None = None,
) -> dict[str, Any]:
    diagnostic: dict[str, Any] = {"code": code, "message": message}
    if line is not None:
        diagnostic["line_number"] = line
    if evidence is not None:
        diagnostic["evidence"] = evidence
    return diagnostic


def _normalise_skill_name(value: str) -> str:
    return unicodedata.normalize("NFKC", value.strip())


def _valid_skill_name(value: str) -> bool:
    name = _normalise_skill_name(value)
    if not 1 <= len(name) <= 64:
        return False
    if not name[0].isalnum() or not name[-1].isalnum() or "--" in name:
        return False
    if name != name.lower():
        return False
    return all(character == "-" or character.isalnum() for character in name)


def _validate_skill_result(
    skill_path: Path,
    root: Path,
    *,
    check_directory_name: bool = True,
    directory_name: str | None = None,
    max_bytes: int | None = None,
    scan_advisories: bool = True,
) -> SkillValidationResult:
    try:
        if max_bytes is not None and skill_path.stat().st_size > max_bytes:
            raise SkillsValidationError("skill file exceeds the validation size limit")
        content = skill_path.read_text(encoding="utf-8")
    except SkillsValidationError:
        raise
    except (OSError, UnicodeError) as exc:
        raise SkillsValidationError(f"unable to read {skill_path}: {exc}") from exc

    metadata, frontmatter_line, frontmatter_error = _parse_frontmatter(content)
    findings: list[dict[str, Any]] = []
    conformance: list[dict[str, Any]] = []
    if frontmatter_error:
        findings.append(
            _finding(
                "SKILL001",
                skill_path,
                root,
                line=frontmatter_line,
                evidence=frontmatter_error,
            )
        )
        conformance.append(
            _conformance_diagnostic(
                "skill_frontmatter_invalid",
                "SKILL.md frontmatter could not be parsed as a YAML mapping",
                line=frontmatter_line,
                evidence=frontmatter_error,
            )
        )
    elif not content.startswith("---"):
        conformance.append(
            _conformance_diagnostic(
                "skill_frontmatter_missing",
                "SKILL.md must start with YAML frontmatter",
                line=1,
            )
        )

    unknown_fields = sorted(
        (field for field in metadata if field not in SKILL_FRONTMATTER_FIELDS),
        key=str,
    )
    for field in unknown_fields:
        field_text = str(field)
        conformance.append(
            _conformance_diagnostic(
                "skill_unknown_frontmatter_field",
                (
                    f"frontmatter field {field_text!r} is not defined by the "
                    "Agent Skills specification"
                ),
                line=frontmatter_line,
                evidence=field_text,
            )
        )
        findings.append(
            _finding(
                "SKILL012",
                skill_path,
                root,
                line=frontmatter_line,
                evidence=field_text,
            )
        )

    name = metadata.get("name")
    description = metadata.get("description")
    missing = [
        field
        for field, value in (("name", name), ("description", description))
        if not isinstance(value, str) or not value.strip()
    ]
    if missing:
        findings.append(
            _finding(
                "SKILL002",
                skill_path,
                root,
                line=frontmatter_line,
                evidence=f"missing or invalid: {', '.join(missing)}",
            )
        )
        conformance.append(
            _conformance_diagnostic(
                "skill_missing_required_field",
                "name and description must be non-empty strings",
                line=frontmatter_line,
                evidence=", ".join(missing),
            )
        )

    normalised_name: str | None = None
    if isinstance(name, str) and name.strip():
        normalised_name = _normalise_skill_name(name)
        if len(normalised_name) > 64:
            conformance.append(
                _conformance_diagnostic(
                    "skill_name_too_long",
                    "skill name must be at most 64 characters",
                    line=frontmatter_line,
                    evidence=str(len(normalised_name)),
                )
            )
        if not _valid_skill_name(name):
            findings.append(
                _finding("SKILL003", skill_path, root, line=frontmatter_line, evidence=name)
            )
            conformance.append(
                _conformance_diagnostic(
                    "skill_invalid_name",
                    "skill name must use lowercase Unicode letters, numbers, and single hyphens",
                    line=frontmatter_line,
                    evidence=name,
                )
            )
        if (
            check_directory_name
            and normalised_name
            and unicodedata.normalize("NFKC", directory_name or skill_path.parent.name)
            != normalised_name
        ):
            findings.append(
                _finding(
                    "SKILL004",
                    skill_path,
                    root,
                    line=frontmatter_line,
                    evidence=(
                        f"directory={directory_name or skill_path.parent.name}, name={name.strip()}"
                    ),
                )
            )
            conformance.append(
                _conformance_diagnostic(
                    "skill_directory_name_mismatch",
                    "skill name must match its parent directory name",
                    line=frontmatter_line,
                    evidence=(
                        f"directory={directory_name or skill_path.parent.name}, name={name.strip()}"
                    ),
                )
            )

    if isinstance(description, str):
        if not description.strip():
            # The required-field finding above covers the empty case.
            pass
        elif len(description) > 1024:
            conformance.append(
                _conformance_diagnostic(
                    "skill_description_too_long",
                    "skill description must be at most 1024 characters",
                    line=frontmatter_line,
                    evidence=str(len(description)),
                )
            )
            findings.append(
                _finding(
                    "SKILL013",
                    skill_path,
                    root,
                    line=frontmatter_line,
                    evidence=str(len(description)),
                )
            )

    if "license" in metadata and not isinstance(metadata["license"], str):
        conformance.append(
            _conformance_diagnostic(
                "skill_invalid_license",
                "license must be a string when provided",
                line=frontmatter_line,
            )
        )
        findings.append(
            _finding("SKILL010", skill_path, root, line=frontmatter_line, evidence="license")
        )

    compatibility = metadata.get("compatibility")
    if "compatibility" in metadata and (
        not isinstance(compatibility, str) or not 1 <= len(compatibility) <= 500
    ):
        conformance.append(
            _conformance_diagnostic(
                "skill_invalid_compatibility",
                "compatibility must be a 1-500 character string when provided",
                line=frontmatter_line,
            )
        )
        findings.append(
            _finding(
                "SKILL010",
                skill_path,
                root,
                line=frontmatter_line,
                evidence="compatibility",
            )
        )

    frontmatter_metadata = metadata.get("metadata")
    if "metadata" in metadata and (
        not isinstance(frontmatter_metadata, dict)
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in frontmatter_metadata.items()
        )
    ):
        conformance.append(
            _conformance_diagnostic(
                "skill_invalid_metadata",
                "metadata must be a mapping of string keys to string values",
                line=frontmatter_line,
            )
        )
        findings.append(
            _finding("SKILL011", skill_path, root, line=frontmatter_line, evidence="metadata")
        )

    allowed_tools = metadata.get("allowed-tools")
    if allowed_tools is not None:
        if not isinstance(allowed_tools, str):
            conformance.append(
                _conformance_diagnostic(
                    "skill_invalid_allowed_tools",
                    "allowed-tools must be a space-separated string",
                    line=frontmatter_line,
                )
            )
            findings.append(
                _finding(
                    "SKILL006",
                    skill_path,
                    root,
                    line=frontmatter_line,
                    evidence="allowed-tools must be a string",
                )
            )
            # Preserve the existing advisory signal for legacy list-shaped
            # declarations while no longer treating it as spec-conformant.
            tools = allowed_tools if isinstance(allowed_tools, list) else []
        else:
            tools = allowed_tools.split()
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, str) and tool.strip().lower() in BROAD_ALLOWED_TOOLS:
                    findings.append(
                        _finding(
                            "SKILL007",
                            skill_path,
                            root,
                            line=frontmatter_line,
                            evidence=tool,
                        )
                    )

    if scan_advisories:
        for reference in _referenced_paths(content):
            target = (skill_path.parent / reference).resolve()
            if not target.is_file():
                findings.append(_finding("SKILL008", skill_path, root, evidence=reference))

        for current, dirnames, filenames in os.walk(skill_path.parent):
            dirnames[:] = sorted(name for name in dirnames if name not in EXCLUDED_DIRS)
            for filename in sorted(filenames):
                candidate = Path(current) / filename
                relative = candidate.relative_to(skill_path.parent)
                if relative.parts and relative.parts[0] == "scripts":
                    continue
                is_script_like = candidate.suffix.lower() in SCRIPT_EXTENSIONS
                try:
                    is_executable = bool(candidate.stat().st_mode & 0o111)
                except OSError:
                    is_executable = False
                if is_script_like or is_executable:
                    findings.append(
                        _finding(
                            "SKILL009",
                            skill_path,
                            root,
                            evidence=relative.as_posix(),
                        )
                    )

    skill = {
        "path": skill_path.relative_to(root).as_posix(),
        "name": name if isinstance(name, str) else None,
        "description": description if isinstance(description, str) else None,
        "metadata": _json_safe(metadata),
    }
    findings.sort(
        key=lambda item: (item["file_path"], item["line_number"], item["code"], item["id"])
    )
    conformance.sort(key=lambda item: (item["code"], str(item.get("evidence", ""))))
    return SkillValidationResult(
        skill=skill,
        conformant=not conformance,
        conformance_diagnostics=tuple(conformance),
        advisory_findings=tuple(findings),
    )


def _validate_skill(
    skill_path: Path,
    root: Path,
    *,
    check_directory_name: bool = True,
    directory_name: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result = _validate_skill_result(
        skill_path,
        root,
        check_directory_name=check_directory_name,
        directory_name=directory_name,
    )
    return result.skill, list(result.advisory_findings)


def validate_skill_file(
    skill_path: Path,
    root: Path,
    *,
    check_directory_name: bool = True,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate one already-discovered skill file without recursive discovery.

    Agent Plugins has a narrower discovery rule than the general skills
    validator. This wrapper lets its loader reuse the existing validation
    logic after it has selected one immediate-child ``SKILL.md`` safely.
    """
    resolved_root = root.expanduser().resolve()
    resolved_skill = skill_path.expanduser().resolve()
    try:
        resolved_skill.relative_to(resolved_root)
    except ValueError as exc:
        raise SkillsValidationError("skill file resolves outside its validation root") from exc
    if not resolved_skill.is_file():
        raise SkillsValidationError(f"skill file is not a regular file: {skill_path}")
    result = _validate_skill_result(
        resolved_skill,
        resolved_root,
        check_directory_name=check_directory_name,
    )
    return result.skill, list(result.advisory_findings)


def validate_skill_file_result(
    skill_path: Path,
    root: Path,
    *,
    check_directory_name: bool = True,
    directory_name: str | None = None,
    max_bytes: int | None = None,
    scan_advisories: bool = True,
) -> SkillValidationResult:
    """Return spec conformance and advisory findings for one safe skill file."""
    resolved_root = root.expanduser().resolve()
    resolved_skill = skill_path.expanduser().resolve()
    try:
        resolved_skill.relative_to(resolved_root)
    except ValueError as exc:
        raise SkillsValidationError("skill file resolves outside its validation root") from exc
    if not resolved_skill.is_file():
        raise SkillsValidationError(f"skill file is not a regular file: {skill_path}")
    return _validate_skill_result(
        resolved_skill,
        resolved_root,
        check_directory_name=check_directory_name,
        directory_name=directory_name,
        max_bytes=max_bytes,
        scan_advisories=scan_advisories,
    )


def validate_skills(
    path: Path, *, check_directory_name: bool = True, root_directory_name: str | None = None
) -> dict[str, Any]:
    """Validate skills, preserving the source name of a materialized root skill."""
    path = path.expanduser().resolve()
    skill_files = discover_skill_files(path)
    root = path.parent if path.is_file() else path
    if not skill_files:
        raise SkillsValidationError(f"no SKILL.md files found under: {path}")
    skills: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for skill_file in skill_files:
        skill, skill_findings = _validate_skill(
            skill_file,
            root,
            check_directory_name=check_directory_name,
            directory_name=root_directory_name if skill_file.parent == root else None,
        )
        skills.append(skill)
        findings.extend(skill_findings)
    findings.sort(
        key=lambda item: (item["file_path"], item["line_number"], item["code"], item["id"])
    )
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    return {
        "schema_version": SKILL_SCHEMA_VERSION,
        "tool_version": __version__,
        "root": root.as_posix(),
        "skills": skills,
        "findings": findings,
        "summary": {
            "skills": len(skills),
            "findings": len(findings),
            "by_severity": counts,
        },
    }


def validate_skill_archive(path: Path) -> dict[str, Any]:
    """Validate a safely extracted ZIP containing a root-level SKILL.md."""
    archive_path = path.expanduser().resolve()
    with inspect_archive(archive_path) as archive:
        root_skill = next(
            (
                member
                for member in archive.members
                if member.normalized_path == SKILL_FILE and member.member_type == "file"
            ),
            None,
        )
        if root_skill is None:
            raise SkillsValidationError("skill archive must contain a root-level SKILL.md file")

        payload = validate_skills(
            archive.extraction_root,
            check_directory_name=False,
        )
        payload["root"] = "."
        payload["archive"] = archive_manifest(archive)
        return payload


def skills_text(payload: dict[str, Any]) -> str:
    lines = [
        "SkillGate skills validation completed",
        "",
        f"Skills: {payload['summary']['skills']}",
        f"Findings: {payload['summary']['findings']}",
    ]
    if payload.get("archive"):
        lines.insert(2, "Source: ZIP archive")
    for finding in payload["findings"]:
        lines.extend(
            [
                "",
                f"{finding['severity'].upper():<13}  {finding['code']}  {finding['title']}",
                f"             {finding['file_path']}:{finding['line_number']}",
            ]
        )
        if finding.get("evidence"):
            lines.append(f"             {finding['evidence']}")
    if not payload["findings"]:
        lines.extend(["", "No validation findings."])
    return "\n".join(lines) + "\n"


def skills_failed(payload: dict[str, Any], fail_on: str | None) -> bool:
    if fail_on is None:
        return False
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[item["severity"]] >= threshold for item in payload["findings"])


def skills_json(payload: dict[str, Any]) -> str:
    return stable_json(payload)
