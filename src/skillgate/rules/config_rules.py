from __future__ import annotations

from skillgate.rules.base import FileContent, RuleResult


class ConfigRule:
    """Future extension point for package and Python configuration checks."""

    rule_id = "SG000"
    title = "Configuration inspection"
    default_severity = "informational"

    def analyze(self, file: FileContent) -> RuleResult:
        return RuleResult()
