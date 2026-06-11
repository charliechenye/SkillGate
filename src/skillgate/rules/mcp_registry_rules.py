from __future__ import annotations

from skillgate.models import Severity
from skillgate.rules.base import FileContent, RuleResult


class McpRegistryMetadataRule:
    rule_id = "SG011"
    title = "MCP registry and tool metadata risk detected"
    default_severity: Severity = "high"

    def analyze(self, file: FileContent) -> RuleResult:
        from skillgate.mcp_registry import analyze_registry_file

        return analyze_registry_file(file)
