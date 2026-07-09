from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

import yaml

from skillgate import __version__
from skillgate.discovery import EXCLUDED_DIRS, SCRIPT_EXTENSIONS
from skillgate.models import SEVERITY_ORDER, stable_json

SKILL_SCHEMA_VERSION = "1"
SKILL_FILE = "SKILL.md"
SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
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
        "`allowed-tools` must be a list containing only strings.",
        "medium",
        "Use a YAML list of narrowly scoped tool names.",
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
}


class SkillsValidationError(ValueError):
    """Raised when a skills validation input cannot be read or discovered."""


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
    return _json_safe(data), None, None


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


def _validate_skill(skill_path: Path, root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        content = skill_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SkillsValidationError(f"unable to read {skill_path}: {exc}") from exc

    metadata, frontmatter_line, frontmatter_error = _parse_frontmatter(content)
    findings: list[dict[str, Any]] = []
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
    if isinstance(name, str) and name.strip() and not SKILL_NAME_RE.fullmatch(name.strip()):
        findings.append(
            _finding("SKILL003", skill_path, root, line=frontmatter_line, evidence=name)
        )
    if isinstance(name, str) and name.strip() and skill_path.parent.name != name.strip():
        findings.append(
            _finding(
                "SKILL004",
                skill_path,
                root,
                line=frontmatter_line,
                evidence=f"directory={skill_path.parent.name}, name={name.strip()}",
            )
        )
    missing_recommended = [
        field for field in ("license", "compatibility") if not metadata.get(field)
    ]
    for field in missing_recommended:
        findings.append(
            _finding("SKILL005", skill_path, root, line=frontmatter_line, evidence=field)
        )

    allowed_tools = metadata.get("allowed-tools")
    if allowed_tools is not None:
        if not isinstance(allowed_tools, list) or not all(
            isinstance(tool, str) for tool in allowed_tools
        ):
            findings.append(
                _finding(
                    "SKILL006",
                    skill_path,
                    root,
                    line=frontmatter_line,
                    evidence="allowed-tools must be a list of strings",
                )
            )
        else:
            for tool in allowed_tools:
                if tool.strip().lower() in BROAD_ALLOWED_TOOLS:
                    findings.append(
                        _finding(
                            "SKILL007",
                            skill_path,
                            root,
                            line=frontmatter_line,
                            evidence=tool,
                        )
                    )

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
            is_executable = bool(candidate.stat().st_mode & 0o111)
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
        "metadata": metadata,
    }
    return skill, findings


def validate_skills(path: Path) -> dict[str, Any]:
    path = path.expanduser().resolve()
    skill_files = discover_skill_files(path)
    root = path.parent if path.is_file() else path
    if not skill_files:
        raise SkillsValidationError(f"no SKILL.md files found under: {path}")
    skills: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for skill_file in skill_files:
        skill, skill_findings = _validate_skill(skill_file, root)
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


def skills_text(payload: dict[str, Any]) -> str:
    lines = [
        "SkillGate skills validation completed",
        "",
        f"Skills: {payload['summary']['skills']}",
        f"Findings: {payload['summary']['findings']}",
    ]
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
