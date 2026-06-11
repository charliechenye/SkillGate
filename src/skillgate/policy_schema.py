from __future__ import annotations

from typing import Any

POLICY_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/charliechenye/SkillGate/schemas/skillgate-policy.schema.json",
    "title": "SkillGate policy",
    "description": "Policy schema for SkillGate static trust checks.",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "version": {
            "const": 1,
            "description": "SkillGate policy schema version.",
        },
        "policy": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "shell": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "allow": {
                            "type": "boolean",
                            "description": "Set to false to block shell execution capabilities.",
                        }
                    },
                },
                "filesystem": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "read": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Reserved allowlist for future filesystem read checks.",
                        },
                        "write": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Allowlisted POSIX-style glob patterns for write targets."
                            ),
                        },
                    },
                },
                "network": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "allow": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Allowed network hostnames.",
                        }
                    },
                },
                "secrets": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "deny": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                'Denied secret patterns. Use ["*"] to block all detected secrets.'
                            ),
                        }
                    },
                },
                "mcp": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "require_review_on_change": {
                            "type": "boolean",
                            "description": (
                                "Block MCP drift findings produced by baseline diff checks."
                            ),
                        }
                    },
                },
                "risk_threshold": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "block": {
                            "type": "string",
                            "enum": ["informational", "low", "medium", "high", "critical"],
                            "description": "Block findings at or above this severity.",
                        }
                    },
                },
            },
        },
    },
}
