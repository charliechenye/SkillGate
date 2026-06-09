from __future__ import annotations

from skillgate.models import ScanReport

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
}
LEVELS = {
    "informational": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def sarif_report(report: ScanReport) -> dict[str, object]:
    used_rule_ids = {finding.rule_id for finding in report.findings}
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": title},
            "fullDescription": {"text": description},
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
                "results": results,
            }
        ],
    }
