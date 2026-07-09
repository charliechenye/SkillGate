from __future__ import annotations

from typing import Literal

from skillgate.identity import finding_fingerprint, normalized_path
from skillgate.models import Finding, PolicyResult, ScanReport
from skillgate.rule_docs import RULE_DOCS

RULES = {rule.rule_id: (rule.title, rule.description) for rule in RULE_DOCS}
LEVELS = {
    "informational": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}
RULE_DOC_BY_ID = {rule.rule_id: rule for rule in RULE_DOCS}
SARIF_RUN_CATEGORIES = {
    "local_repository": "skillgate/local-repository",
    "remote_github": "skillgate/remote-github",
    "mcp_registry_compare": "skillgate/mcp-registry-compare",
    "mcp_bundle": "skillgate/mcp-bundle",
}
SarifRunCategory = Literal[
    "local_repository",
    "remote_github",
    "mcp_registry_compare",
    "mcp_bundle",
]
FINGERPRINT_KEY = "skillgateFinding/v1"


def rule_tags(rule_id: str) -> list[str]:
    rule = RULE_DOC_BY_ID.get(rule_id)
    if rule is None:
        return ["skillgate"]
    return ["skillgate", f"capability:{rule.capability}", f"severity:{rule.severity}"]


def capability_taxa() -> list[dict[str, object]]:
    capabilities = sorted(
        {RULE_DOC_BY_ID[rule_id].capability for rule_id in RULES if rule_id in RULE_DOC_BY_ID}
    )
    return [
        {
            "id": capability,
            "name": capability,
            "shortDescription": {"text": f"SkillGate capability: {capability}"},
        }
        for capability in capabilities
    ]


def sarif_run_category(category: SarifRunCategory | str = "local_repository") -> str:
    return SARIF_RUN_CATEGORIES.get(category, category)


def sarif_report(
    report: ScanReport,
    category: SarifRunCategory | str = "local_repository",
    policy_result: PolicyResult | None = None,
) -> dict[str, object]:
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
            "partialFingerprints": {FINGERPRINT_KEY: finding_fingerprint(finding)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": normalized_path(finding.file_path)},
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
        if policy_result is not None:
            suppressions = result_suppressions(finding, policy_result)
            if suppressions:
                result["suppressions"] = suppressions
        results.append(result)
    run: dict[str, object] = {
        "automationDetails": {"id": sarif_run_category(category)},
        "tool": {
            "driver": {
                "name": "SkillGate",
                "semanticVersion": report.tool_version,
                "informationUri": "https://github.com/charliechenye/SkillGate",
                "rules": rules,
            }
        },
        "taxonomies": [
            {
                "name": "SkillGate capabilities",
                "organization": "Chenye Zhu / SkillGate",
                "taxa": capability_taxa(),
            }
        ],
        "results": results,
    }
    if policy_result is not None:
        run["properties"] = {
            "policyWaivers": {
                "active": policy_result.active_waivers,
                "expired": policy_result.expired_waivers,
                "waivedViolations": policy_result.waived_violations,
            }
        }
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }


def result_suppressions(finding: Finding, policy_result: PolicyResult) -> list[dict[str, object]]:
    suppressions = []
    fingerprint = finding_fingerprint(finding)
    for item in policy_result.waived_violations:
        if item.get("finding_id") != finding.id and item.get("fingerprint") != fingerprint:
            continue
        waiver = item.get("waiver")
        if not isinstance(waiver, dict):
            continue
        suppression = {
            "kind": "external",
            "justification": str(waiver.get("reason") or "Policy finding waiver"),
            "properties": {
                "waiver": waiver,
                "violation": item.get("message"),
            },
        }
        suppressions.append(suppression)
    return suppressions
