from __future__ import annotations

from typing import Any

import yaml

POLICY_PROFILES: dict[str, dict[str, Any]] = {
    "audit": {
        "version": 1,
        "policy": {
            "risk_threshold": {
                "block": "high",
            },
        },
    },
    "preinstall": {
        "version": 1,
        "policy": {
            "shell": {
                "allow": False,
            },
            "filesystem": {
                "write": [],
            },
            "network": {
                "allow": [],
            },
            "secrets": {
                "deny": ["*"],
            },
            "mcp": {
                "require_review_on_change": True,
            },
            "risk_threshold": {
                "block": "high",
            },
        },
    },
    "strict": {
        "version": 1,
        "policy": {
            "shell": {
                "allow": False,
            },
            "filesystem": {
                "write": [],
            },
            "network": {
                "allow": [],
            },
            "secrets": {
                "deny": ["*"],
            },
            "mcp": {
                "require_review_on_change": True,
            },
            "risk_threshold": {
                "block": "medium",
            },
        },
    },
    "mcp": {
        "version": 1,
        "policy": {
            "network": {
                "allow": [],
            },
            "secrets": {
                "deny": ["*"],
            },
            "mcp": {
                "require_review_on_change": True,
            },
            "risk_threshold": {
                "block": "high",
            },
        },
    },
}


class PolicyTemplateDumper(yaml.SafeDumper):
    def increase_indent(self, flow: bool = False, indentless: bool = False):
        return super().increase_indent(flow, False)


def policy_template(profile: str) -> dict[str, Any]:
    return POLICY_PROFILES[profile]


def policy_template_yaml(profile: str) -> str:
    return yaml.dump(
        policy_template(profile),
        Dumper=PolicyTemplateDumper,
        sort_keys=False,
        default_flow_style=False,
    )
