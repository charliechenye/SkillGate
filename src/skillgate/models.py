from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "1"
SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
Severity = Literal["informational", "low", "medium", "high", "critical"]
SemanticImpact = Literal["low", "medium", "high", "critical"]
SemanticConfidence = Literal["low", "medium", "high"]
SemanticSourceRole = Literal[
    "agent_instruction",
    "tool_description",
    "prompt_template",
    "manifest_metadata",
    "documentation",
    "test_fixture",
    "source_comment",
    "unknown",
]
AgentConsumption = Literal["direct", "possible", "unlikely"]


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


class SemanticTextBlock(StableModel):
    """A bounded, redacted agent-facing text block selected by a source adapter."""

    file_path: str
    line_number: int
    end_line: int
    text: str
    source_role: SemanticSourceRole
    structured_field: str | None = None
    agent_consumption: AgentConsumption


class SemanticInventorySkip(StableModel):
    file_path: str
    reason: str


class SemanticTextInventory(StableModel):
    """Deterministic semantic input inventory; it intentionally contains no findings."""

    schema_version: str
    tool_version: str
    blocks: list[SemanticTextBlock]
    skipped_files: list[SemanticInventorySkip]
    summary: dict[str, int]


class SemanticBlockSnapshot(StableModel):
    """A redacted semantic block retained in an internal approval baseline."""

    fingerprint: str
    file_path: str
    line_number: int
    end_line: int
    text: str
    source_role: SemanticSourceRole
    structured_field: str | None = None
    agent_consumption: AgentConsumption


class SemanticBaseline(StableModel):
    """Internal advisory baseline for source-selected semantic text blocks."""

    schema_version: str
    tool_version: str
    created_at: str
    blocks: list[SemanticBlockSnapshot]
    skipped_files: list[SemanticInventorySkip] = Field(default_factory=list)


class SemanticInstructionDrift(StableModel):
    """One advisory semantic instruction change between an internal baseline and inventory."""

    change_type: Literal["added", "removed", "modified"]
    before: SemanticBlockSnapshot | None = None
    after: SemanticBlockSnapshot | None = None

    @model_validator(mode="after")
    def validate_sides(self) -> SemanticInstructionDrift:
        valid = {
            "added": (self.before is None and self.after is not None),
            "removed": (self.before is not None and self.after is None),
            "modified": (self.before is not None and self.after is not None),
        }
        if not valid[self.change_type]:
            raise ValueError(
                f"{self.change_type} semantic drift must contain the appropriate before/after block"
            )
        return self


class SemanticDriftReport(StableModel):
    """Separate advisory semantic drift result; it is not a capability DiffReport."""

    schema_version: str
    tool_version: str
    baseline_created_at: str
    baseline_skipped_files: list[SemanticInventorySkip] = Field(default_factory=list)
    current_skipped_files: list[SemanticInventorySkip] = Field(default_factory=list)
    coverage_changed: bool = False
    incomplete: bool = False
    changes: list[SemanticInstructionDrift]
    summary: dict[str, int]


class SemanticFinding(StableModel):
    """An advisory finding derived from source-selected agent-facing text."""

    id: str
    rule_id: str
    title: str
    potential_impact: SemanticImpact
    confidence: SemanticConfidence
    applicability: AgentConsumption
    file_path: str
    line_number: int
    end_line: int
    evidence: str
    category: str
    source_role: SemanticSourceRole
    structured_field: str | None = None
    related_rule_ids: list[str] = Field(default_factory=list)
    review_guidance: str


class SemanticAnalysis(StableModel):
    """Separate advisory semantic result family; it is not a ScanReport."""

    schema_version: str
    tool_version: str
    findings: list[SemanticFinding]
    summary: dict[str, int]


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
    reason: str | None = None
    approval_hint: str | None = None
    suggested_policy: dict[str, Any] | None = None


class PolicyResult(StableModel):
    blocked: bool
    violations: list[PolicyViolation]
    active_waivers: list[dict[str, Any]] = Field(default_factory=list)
    expired_waivers: list[dict[str, Any]] = Field(default_factory=list)
    waived_violations: list[dict[str, Any]] = Field(default_factory=list)


def model_to_data(value: Any) -> Any:
    if isinstance(value, BaseModel):
        data = value.model_dump(mode="json")
        if isinstance(value, Finding):
            from skillgate.identity import finding_fingerprint

            data["fingerprint"] = finding_fingerprint(value)
        if isinstance(value, ScanReport | DiffReport):
            from skillgate.identity import finding_fingerprint

            data["findings"] = [
                {**item, "fingerprint": finding_fingerprint(finding)}
                for item, finding in zip(data["findings"], value.findings, strict=True)
            ]
        return data
    if isinstance(value, list):
        return [model_to_data(item) for item in value]
    if isinstance(value, dict):
        return {key: model_to_data(value[key]) for key in sorted(value)}
    return value


def stable_json(value: Any) -> str:
    return json.dumps(model_to_data(value), indent=2, sort_keys=True) + "\n"


def severity_at_or_above(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, -1) >= SEVERITY_ORDER.get(threshold, 999)
