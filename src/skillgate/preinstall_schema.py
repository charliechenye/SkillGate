from __future__ import annotations

PREINSTALL_REVIEW_JSON_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/charliechenye/SkillGate/blob/main/schemas/skillgate-review.schema.json",
    "title": "SkillGate pre-install review packet",
    "description": (
        "A redacted, deterministic review record for an AI-agent skill, MCP source, "
        "GitHub repository, or MCPB bundle."
    ),
    "type": "object",
    "additionalProperties": False,
    "required": [
        "packet_type",
        "schema_version",
        "tool_version",
        "packet_digest",
        "source",
        "source_manifest",
        "metadata",
        "capabilities",
        "findings",
        "skills",
        "reviewer",
    ],
    "properties": {
        "packet_type": {"const": "preinstall_review"},
        "schema_version": {"const": "2"},
        "tool_version": {"type": "string"},
        "packet_digest": {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"},
        "source": {
            "type": "object",
            "required": ["kind", "reference"],
            "additionalProperties": True,
            "properties": {
                "kind": {"type": "string", "enum": ["local", "github", "mcpb"]},
                "reference": {"type": "string"},
                "path": {"type": "string"},
                "revision": {"type": "string"},
                "digest": {"type": "string"},
                "metadata": {"type": "object"},
            },
        },
        "source_manifest": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "scanned_files",
                "skipped_files",
                "manifest_sha256",
                "scanned_file_count",
                "skipped_file_count",
            ],
            "properties": {
                "scanned_files": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["path", "file_type", "sha256", "size_bytes"],
                        "properties": {
                            "path": {"type": "string"},
                            "file_type": {"type": "string"},
                            "sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
                            "size_bytes": {"type": "integer", "minimum": 0},
                        },
                    },
                },
                "skipped_files": {"type": "array", "items": {}},
                "manifest_sha256": {
                    "type": "string",
                    "pattern": r"^sha256:[0-9a-f]{64}$",
                },
                "scanned_file_count": {"type": "integer", "minimum": 0},
                "skipped_file_count": {"type": "integer", "minimum": 0},
            },
        },
        "metadata": {"type": "object"},
        "capabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["type", "resource", "source_file", "source_line", "trust_boundary"],
                "properties": {
                    "type": {"type": "string"},
                    "resource": {"type": ["string", "null"]},
                    "source_file": {"type": ["string", "null"]},
                    "source_line": {"type": ["integer", "null"]},
                    "trust_boundary": {"type": "string"},
                },
            },
        },
        "findings": {
            "type": "object",
            "additionalProperties": False,
            "required": ["total", "by_severity", "groups"],
            "properties": {
                "total": {"type": "integer", "minimum": 0},
                "by_severity": {"$ref": "#/$defs/severityCounts"},
                "groups": {
                    "type": "object",
                    "additionalProperties": {"$ref": "#/$defs/findingList"},
                },
            },
        },
        "skills": {
            "type": "object",
            "additionalProperties": False,
            "required": ["validated", "summary", "findings"],
            "properties": {
                "validated": {"type": "boolean"},
                "summary": {"type": "object"},
                "findings": {"$ref": "#/$defs/findingList"},
            },
        },
        "reviewer": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "decision",
                "next_actions",
                "limitations",
                "no_execution",
                "network_access",
            ],
            "properties": {
                "decision": {"type": "string", "enum": ["no_findings", "review_required"]},
                "next_actions": {"type": "array", "items": {"type": "string"}},
                "limitations": {"type": "array", "items": {"type": "string"}},
                "no_execution": {"const": True},
                "network_access": {"type": "boolean"},
            },
        },
    },
    "$defs": {
        "severityCounts": {
            "type": "object",
            "additionalProperties": {"type": "integer", "minimum": 0},
        },
        "findingList": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "id",
                    "rule_id",
                    "title",
                    "severity",
                    "capability",
                    "file_path",
                    "line_number",
                    "evidence",
                    "remediation",
                ],
                "properties": {
                    "id": {"type": "string"},
                    "rule_id": {"type": "string"},
                    "title": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["informational", "low", "medium", "high", "critical"],
                    },
                    "capability": {"type": "string"},
                    "file_path": {"type": ["string", "null"]},
                    "line_number": {"type": ["integer", "null"]},
                    "evidence": {"type": ["string", "null"]},
                    "remediation": {"type": ["string", "null"]},
                },
            },
        },
    },
}
