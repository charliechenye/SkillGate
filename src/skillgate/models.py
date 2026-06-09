from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1"
SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
Severity = Literal["informational", "low", "medium", "high", "critical"]


class StableModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScannedFile(StableModel):
    path: str
    file_type: str
    sha256: str
    size_bytes: int


class Finding(StableModel):
    id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    capability: str
    file_path: str
    line_number: int | None = None
    evidence: str | None = None
    remediation: str | None = None


class Capability(StableModel):
    type: str
    resource: str | None = None
    source_file: str
    source_line: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ScanReport(StableModel):
    schema_version: str
    tool_version: str
    scan_root: str
    scanned_files: list[ScannedFile]
    capabilities: list[Capability]
    findings: list[Finding]
    summary: dict[str, Any]


class BaselineLock(StableModel):
    schema_version: str
    created_at: str
    files: list[ScannedFile]
    capabilities: list[Capability]


class DiffReport(StableModel):
    schema_version: str
    tool_version: str
    scan_root: str
    added_files: list[str]
    removed_files: list[str]
    modified_files: list[str]
    added_capabilities: list[Capability]
    removed_capabilities: list[Capability]
    findings: list[Finding]
    summary: dict[str, Any]


class PolicyViolation(StableModel):
    message: str
    severity: Severity
    finding_id: str | None = None
    capability: Capability | None = None


class PolicyResult(StableModel):
    blocked: bool
    violations: list[PolicyViolation]


def model_to_data(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [model_to_data(item) for item in value]
    if isinstance(value, dict):
        return {key: model_to_data(value[key]) for key in sorted(value)}
    return value


def stable_json(value: Any) -> str:
    return json.dumps(model_to_data(value), indent=2, sort_keys=True) + "\n"


def severity_at_or_above(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, -1) >= SEVERITY_ORDER.get(threshold, 999)
