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


@dataclass
class RuleResult:
    findings: list[Finding] = field(default_factory=list)
    capabilities: list[Capability] = field(default_factory=list)


class Rule(Protocol):
    rule_id: str
    title: str
    default_severity: Severity

    def analyze(self, file: FileContent) -> RuleResult: ...


SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIALS)[A-Z0-9_]*)\s*[:=]\s*['\"]?[^'\"\s]+"
)


def redact_evidence(evidence: str) -> str:
    evidence = SECRET_ASSIGNMENT_RE.sub(r"\1=<redacted>", evidence)
    return evidence.strip()[:1000]


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
        details={key: details[key] for key in sorted(details) if details[key] is not None},
    )
