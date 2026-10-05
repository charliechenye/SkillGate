from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Protocol

from skillgate.models import Capability, Finding, Severity


@dataclass(frozen=True)
class FileContent:
    path: str
    file_type: str
    text: str
    format_aware: bool = False


@dataclass
class RuleResult:
    findings: list[Finding] = field(default_factory=list)
    capabilities: list[Capability] = field(default_factory=list)


class Rule(Protocol):
    rule_id: str
    title: str
    default_severity: Severity

    def analyze(self, file: FileContent) -> RuleResult: ...


SECRET_ASSIGNMENT_START_RE = re.compile(
    r"(?i)(?<![A-Z0-9_])(?P<name>[A-Z_][A-Z0-9_]*)[ \t]*[:=][ \t]*"
)
SECRET_NAME_PARTS = frozenset({"TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIALS"})
SHELL_WORD_OPERATORS = frozenset(";&|<>")


def _is_secret_assignment_name(name: str) -> bool:
    return any(part in SECRET_NAME_PARTS for part in name.upper().split("_"))


def _command_substitution_end(text: str, start: int, kind: str) -> int:
    """Find the end of a command substitution with a bounded context stack."""
    contexts: list[tuple[str, str, int]] = [(kind, "unquoted", 1)]
    index = start + (2 if kind == "paren" else 1)
    while index < len(text):
        context_kind, state, depth = contexts[-1]
        character = text[index]

        if state == "single":
            if character == "'":
                contexts[-1] = (context_kind, "unquoted", depth)
            index += 1
            continue

        if state == "double":
            if character == "\\":
                index = min(index + 2, len(text))
                continue
            if character == '"':
                contexts[-1] = (context_kind, "unquoted", depth)
                index += 1
                continue
            if character == "$" and text.startswith("$(", index):
                contexts.append(("paren", "unquoted", 1))
                index += 2
                continue
            if character == "`":
                contexts.append(("backtick", "unquoted", 1))
                index += 1
                continue
            index += 1
            continue

        if character == "\\":
            index = min(index + 2, len(text))
            continue
        if character == "'":
            contexts[-1] = (context_kind, "single", depth)
            index += 1
            continue
        if character == '"':
            contexts[-1] = (context_kind, "double", depth)
            index += 1
            continue
        if character == "$" and text.startswith("$(", index):
            contexts.append(("paren", "unquoted", 1))
            index += 2
            continue
        if context_kind == "backtick" and character == "`":
            contexts.pop()
            index += 1
            if not contexts:
                return index
            continue
        if character == "`":
            contexts.append(("backtick", "unquoted", 1))
            index += 1
            continue
        if context_kind == "paren" and character == "(":
            contexts[-1] = (context_kind, state, depth + 1)
            index += 1
            continue
        if context_kind == "paren" and character == ")":
            if depth > 1:
                contexts[-1] = (context_kind, state, depth - 1)
                index += 1
                continue
            contexts.pop()
            index += 1
            if not contexts:
                return index
            continue
        index += 1
    return len(text)


def _assignment_value_end(text: str, start: int) -> int | None:
    if start >= len(text):
        return None
    if text[start].isspace() or text[start] in SHELL_WORD_OPERATORS:
        return None

    index = start
    state = "unquoted"
    while index < len(text):
        character = text[index]
        if state == "unquoted":
            if character.isspace() or character in SHELL_WORD_OPERATORS:
                return index
            if character == "\\":
                if index + 1 >= len(text):
                    return len(text)
                index += 2
                continue
            if character == "$" and text.startswith("$(", index):
                index = _command_substitution_end(text, index, "paren")
                continue
            if character == "`":
                index = _command_substitution_end(text, index, "backtick")
                continue
            if character == "'":
                state = "single"
            elif character == '"':
                state = "double"
        elif state == "single":
            if character == "'":
                state = "unquoted"
        else:
            if character == "\\":
                if index + 1 >= len(text):
                    return len(text)
                index += 2
                continue
            if character == "$" and text.startswith("$(", index):
                index = _command_substitution_end(text, index, "paren")
                continue
            if character == "`":
                index = _command_substitution_end(text, index, "backtick")
                continue
            if character == '"':
                state = "unquoted"
        index += 1
    return index


def _redact_secret_assignments(text: str) -> str:
    pieces: list[str] = []
    cursor = 0
    covered_until = 0
    for match in SECRET_ASSIGNMENT_START_RE.finditer(text):
        if match.start() < covered_until:
            continue
        if not _is_secret_assignment_name(match["name"]):
            continue
        value_end = _assignment_value_end(text, match.end())
        if value_end is None:
            continue
        pieces.append(text[cursor : match.start()])
        pieces.append(f"{match['name']}=<redacted>")
        cursor = value_end
        covered_until = value_end
    return "".join((*pieces, text[cursor:]))


def redact_evidence(evidence: str) -> str:
    evidence = _redact_secret_assignments(evidence)
    return evidence.strip()[:1000]


def redact_details(value: object) -> object:
    if isinstance(value, str):
        return _redact_secret_assignments(value)
    if isinstance(value, dict):
        return {key: redact_details(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_details(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_details(item) for item in value)
    return value


def finding_id(rule_id: str, path: str, line_number: int | None, evidence: str | None) -> str:
    seed = f"{rule_id}|{path}|{line_number or 0}|{evidence or ''}".encode()
    return f"{rule_id}-{hashlib.sha256(seed).hexdigest()[:12]}"


def make_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    capability: str,
    file_path: str,
    line_number: int | None,
    evidence: str | None,
    remediation: str | None = None,
) -> Finding:
    redacted = redact_evidence(evidence or "") if evidence else None
    return Finding(
        id=finding_id(rule_id, file_path, line_number, redacted),
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        capability=capability,
        file_path=file_path,
        line_number=line_number,
        evidence=redacted,
        remediation=remediation,
    )


def make_capability(
    capability_type: str,
    source_file: str,
    source_line: int | None,
    resource: str | None = None,
    **details: object,
) -> Capability:
    return Capability(
        type=capability_type,
        resource=resource,
        source_file=source_file,
        source_line=source_line,
        details={
            key: redact_details(details[key]) for key in sorted(details) if details[key] is not None
        },
    )
