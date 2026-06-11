from __future__ import annotations

from skillgate.models import ScanReport
from skillgate.rule_docs import RULE_DOCS

RULES = {
    "SG001": ("Shell execution detected", "The file appears to invoke shell execution."),
    "SG002": ("Destructive command detected", "The file contains a destructive command pattern."),
    "SG003": ("Network egress detected", "The file appears to access a network resource."),
    "SG004": ("Remote download followed by execution", "Remote content is executed."),
    "SG005": ("Secret or credential access detected", "A likely secret is referenced."),
    "SG006": ("Filesystem write capability detected", "The file may write to the filesystem."),
    "SG007": ("Prompt override language detected", "Instruction-conflict language is present."),
    "SG008": (
        "Suspicious Unicode or obfuscation detected",
        "Hidden or encoded content is present.",
    ),
    "SG009": ("MCP server configuration discovered", "An MCP server configuration is present."),
    "SG010": ("MCP capability changed from baseline", "An MCP capability changed."),
    "SG011": ("MCP tool metadata risk detected", "Declared MCP tool metadata is risky."),
    "SG012": ("MCP transport risk detected", "Declared MCP transport metadata is risky."),
    "SG013": ("MCP registry metadata drift detected", "Local MCP registry metadata drifted."),
}
LEVELS = {
    "informational": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}
RULE_DOC_BY_ID = {rule.rule_id: rule for rule in RULE_DOCS}


def rule_tags(rule_id: str) -> list[str]:
    rule = RULE_DOC_BY_ID.get(rule_id)
    if rule is None:
        return ["skillgate"]
    return ["skillgate", f"capability:{rule.capability}", f"severity:{rule.severity}"]


def capability_taxa() -> list[dict[str, object]]:
    capabilities = sorted({rule.capability for rule in RULE_DOCS})
    return [
        {
            "id": capability,
            "name": capability,
            "shortDescription": {"text": f"SkillGate capability: {capability}"},
        }
        for capability in capabilities
    ]


def sarif_report(report: ScanReport) -> dict[str, object]:
    used_rule_ids = {finding.rule_id for finding in report.findings}
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": title},
            "fullDescription": {"text": description},
            "properties": {"tags": rule_tags(rule_id)},
        }
        for rule_id, (title, description) in sorted(RULES.items())
        if rule_id in used_rule_ids or rule_id != "SG010"
    ]
    results = []
    for finding in report.findings:
        result = {
            "ruleId": finding.rule_id,
            "level": LEVELS[finding.severity],
            "message": {"text": f"{finding.title}: {finding.evidence or finding.description}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {"startLine": finding.line_number or 1},
                    }
                }
            ],
            "properties": {
                "capability": finding.capability,
                "severity": finding.severity,
                "tags": [
                    "skillgate",
                    f"capability:{finding.capability}",
                    f"severity:{finding.severity}",
                ],
            },
            "taxa": [
                {
                    "id": finding.capability,
                    "toolComponent": {"name": "SkillGate capabilities"},
                }
            ],
        }
        results.append(result)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillGate",
                        "semanticVersion": report.tool_version,
                        "informationUri": "https://github.com/OpenEvalGate/skillgate",
                        "rules": rules,
                    }
                },
                "taxonomies": [
                    {
                        "name": "SkillGate capabilities",
                        "organization": "OpenEvalGate",
                        "taxa": capability_taxa(),
                    }
                ],
                "results": results,
            }
        ],
    }
