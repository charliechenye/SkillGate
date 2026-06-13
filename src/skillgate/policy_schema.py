from __future__ import annotations

from typing import Any

CAPABILITY_GROUPS = [
    "mcp.remote_http",
    "network.ai_api",
    "network.any",
    "network.cloud_metadata",
    "network.localhost",
    "network.package_registry",
    "network.private_network",
    "network.public_internet",
    "network.source_control",
    "secrets.cloud",
    "shell.local_script",
]

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
                "capabilities": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "allow": {
                            "type": "array",
                            "items": {"type": "string", "enum": CAPABILITY_GROUPS},
                            "description": "Allowed named capability groups.",
                            "examples": [["network.package_registry", "shell.local_script"]],
                        },
                        "deny": {
                            "type": "array",
                            "items": {"type": "string", "enum": CAPABILITY_GROUPS},
                            "description": (
                                "Denied named capability groups. Deny groups take precedence "
                                "over allow groups and exact allowlists."
                            ),
                            "examples": [["network.cloud_metadata"]],
                        },
                    },
                },
                "shell": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "allow": {
                            "type": "boolean",
                            "description": "Set to false to block shell execution capabilities.",
                        },
                        "commands": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "allow": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": (
                                        "Allowlisted POSIX-style glob patterns for shell "
                                        "command strings."
                                    ),
                                }
                            },
                        },
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
                        },
                        "allow_categories": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": [
                                    "ai_api",
                                    "cloud_metadata",
                                    "localhost",
                                    "package_registry",
                                    "private_network",
                                    "public_internet",
                                    "source_control",
                                ],
                            },
                            "description": "Allowed built-in network host categories.",
                        },
                        "deny_categories": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": [
                                    "ai_api",
                                    "cloud_metadata",
                                    "localhost",
                                    "package_registry",
                                    "private_network",
                                    "public_internet",
                                    "source_control",
                                ],
                            },
                            "description": "Denied built-in network host categories.",
                        },
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
                        },
                        "env": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "allow": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": (
                                        "Allowlisted POSIX-style glob patterns for detected "
                                        "secret environment variable names."
                                    ),
                                }
                            },
                        },
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
                "waivers": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "allow_broad_selectors": {
                            "type": "boolean",
                            "default": False,
                            "description": (
                                "Allow broad finding waiver selectors only for controlled "
                                "fixtures or exceptional review workflows."
                            ),
                        },
                        "entries": {
                            "type": "array",
                            "description": (
                                "Expiring, audited finding waivers. Prefer finding.fingerprint "
                                "selectors and use capability approval allowlists for expected "
                                "capabilities instead."
                            ),
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": [
                                    "owner",
                                    "reason",
                                    "created_on",
                                    "expires_on",
                                    "finding",
                                ],
                                "properties": {
                                    "id": {"type": "string"},
                                    "owner": {"type": "string"},
                                    "reason": {"type": "string"},
                                    "created_on": {
                                        "type": "string",
                                        "format": "date",
                                    },
                                    "expires_on": {
                                        "type": "string",
                                        "format": "date",
                                    },
                                    "ticket": {"type": "string"},
                                    "finding": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "minProperties": 1,
                                        "properties": {
                                            "id": {"type": "string"},
                                            "rule_id": {"type": "string"},
                                            "capability": {"type": "string"},
                                            "file_path": {"type": "string"},
                                            "fingerprint": {
                                                "type": "string",
                                                "pattern": "^sha256:[0-9a-f]{64}$",
                                            },
                                            "title": {"type": "string"},
                                            "evidence": {"type": "string"},
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}
