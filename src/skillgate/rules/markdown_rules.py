from __future__ import annotations

import re

from skillgate.models import Severity
from skillgate.rules.base import FileContent, RuleResult, make_capability, make_finding

PROMPT_OVERRIDE_RE = re.compile(
    r"(?i)(ignore previous instructions|ignore all prior instructions|override system instructions|"
    r"disregard earlier instructions|do not tell the user|hide this action|bypass approval)"
)
BIDI_OR_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f]")
BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b")
ENCODED_EXEC_RE = re.compile(
    r"(?i)(base64\s+(-d|--decode).*(bash|sh|powershell|pwsh)|eval\s*\(\s*atob\()"
)


class PromptOverrideRule:
    rule_id = "SG007"
    title = "Prompt override or instruction-conflict language detected"
    default_severity: Severity = "high"

    def analyze(self, file: FileContent) -> RuleResult:
        result = RuleResult()
        for number, line in enumerate(file.text.splitlines(), start=1):
            if PROMPT_OVERRIDE_RE.search(line):
                result.findings.append(
                    make_finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            "The file contains narrow prompt override or concealment language."
                        ),
                        severity="high",
                        capability="prompt_override",
                        file_path=file.path,
                        line_number=number,
                        evidence=line,
                        remediation=(
                            "Remove instruction-conflict language unless explicitly reviewed."
                        ),
                    )
                )
                result.capabilities.append(make_capability("prompt_override", file.path, number))
        return result


class SuspiciousUnicodeRule:
    rule_id = "SG008"
    title = "Suspicious Unicode or obfuscation detected"
    default_severity: Severity = "medium"

    def analyze(self, file: FileContent) -> RuleResult:
        result = RuleResult()
        for number, line in enumerate(file.text.splitlines(), start=1):
            reason = None
            if BIDI_OR_ZERO_WIDTH_RE.search(line):
                reason = "Bidirectional or zero-width Unicode control character"
            elif BASE64_BLOB_RE.search(line):
                reason = "Excessive Base64-like blob"
            elif ENCODED_EXEC_RE.search(line):
                reason = "Encoded command execution pattern"
            if reason:
                result.findings.append(
                    make_finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description="The file contains suspicious Unicode or obvious obfuscation.",
                        severity="medium",
                        capability="obfuscation",
                        file_path=file.path,
                        line_number=number,
                        evidence=reason,
                        remediation="Remove hidden characters or encoded command execution.",
                    )
                )
                result.capabilities.append(
                    make_capability("obfuscation", file.path, number, resource=reason)
                )
        return result
