from __future__ import annotations

import re
from urllib.parse import urlparse

from skillgate.models import Severity
from skillgate.rules.base import FileContent, RuleResult, make_capability, make_finding

SHELL_RE = re.compile(
    r"(?i)(?:(?<![.\w/-])(?:bash|sh|zsh|powershell|pwsh|cmd\.exe)(?![\w.-])|"
    r"subprocess\.|os\.system|child_process\.(?:exec|spawn))"
)
DESTRUCTIVE_RE = re.compile(
    r"(?i)(rm\s+-[a-z]*r[a-z]*f|del\s+/s|Remove-Item\s+.*-Recurse\s+.*-Force|"
    r"\bformat\b|\bmkfs\b|drop\s+database|truncate\s+table|git\s+clean\s+-fdx)"
)
NETWORK_RE = re.compile(
    r"(?i)(?:\b(?:curl|wget|Invoke-WebRequest|axios)\b|requests\.(?:get|post)|"
    r"\bfetch\s*\(|https?\.get|http\.get|https?://[^\s'\"<>]+)"
)
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
REMOTE_EXEC_RE = re.compile(
    r"(?i)(curl\b.*\|\s*(?:bash|sh|zsh)|wget\b.*\|\s*(?:bash|sh|zsh)|"
    r"\biex\s*\(\s*iwr\b|python\s+-c\s+['\"]?\$?\(?(?:curl|wget)\b)"
)
SECRET_RE = re.compile(
    r"(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|OPENAI_API_KEY|"
    r"ANTHROPIC_API_KEY|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|"
    r"~/.ssh/|~/.aws/|(?:^|[\s'\"/])\.env(?:$|[\s'\"/]))"
)
WRITE_RE = re.compile(
    r"(?i)(?:\b(?:write|append|overwrite)\b|open\s*\([^)]*['\"][wa]['\"]|"
    r"fs\.(?:writeFile|appendFile)|\btee\b|cat\s+>\s*([^\s]+)|>\s*([A-Za-z0-9_./-]+))"
)


def line_matches(text: str, pattern: re.Pattern[str]) -> list[tuple[int, str, re.Match[str]]]:
    matches = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if match:
            matches.append((number, line, match))
    return matches


def extract_host(text: str) -> str | None:
    match = URL_RE.search(text)
    if not match:
        return None
    parsed = urlparse(match.group(0))
    return parsed.hostname


class ShellExecutionRule:
    rule_id = "SG001"
    title = "Shell execution detected"
    default_severity: Severity = "medium"

    def analyze(self, file: FileContent) -> RuleResult:
        result = RuleResult()
        for number, line, _match in line_matches(file.text, SHELL_RE):
            severity: Severity = (
                "high" if DESTRUCTIVE_RE.search(line) or REMOTE_EXEC_RE.search(line) else "medium"
            )
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description="The file appears to invoke a shell or process execution API.",
                    severity=severity,
                    capability="shell_execution",
                    file_path=file.path,
                    line_number=number,
                    evidence=line,
                    remediation="Review whether shell execution is necessary and policy-approved.",
                )
            )
            result.capabilities.append(
                make_capability("shell_execution", file.path, number, command=line.strip())
            )
        return result


class DestructiveCommandRule:
    rule_id = "SG002"
    title = "Destructive command detected"
    default_severity: Severity = "high"

    def analyze(self, file: FileContent) -> RuleResult:
        result = RuleResult()
        for number, line, _match in line_matches(file.text, DESTRUCTIVE_RE):
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        "The file contains a command pattern that may delete or destroy data."
                    ),
                    severity="high",
                    capability="destructive_action",
                    file_path=file.path,
                    line_number=number,
                    evidence=line,
                    remediation="Remove the destructive action or require explicit review.",
                )
            )
            result.capabilities.append(
                make_capability("destructive_action", file.path, number, command=line.strip())
            )
        return result


class NetworkEgressRule:
    rule_id = "SG003"
    title = "Network egress detected"
    default_severity: Severity = "medium"

    def analyze(self, file: FileContent) -> RuleResult:
        result = RuleResult()
        for number, line, _match in line_matches(file.text, NETWORK_RE):
            host = extract_host(line)
            evidence = f"Host: {host}" if host else line
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description="The file appears to access a network resource.",
                    severity="medium",
                    capability="network_egress",
                    file_path=file.path,
                    line_number=number,
                    evidence=evidence,
                    remediation="Allowlist the host or remove the network access.",
                )
            )
            result.capabilities.append(
                make_capability(
                    "network_egress", file.path, number, resource=host, command=line.strip()
                )
            )
        return result


class RemoteDownloadExecutionRule:
    rule_id = "SG004"
    title = "Remote download followed by execution"
    default_severity: Severity = "high"

    def analyze(self, file: FileContent) -> RuleResult:
        result = RuleResult()
        for number, line, _match in line_matches(file.text, REMOTE_EXEC_RE):
            host = extract_host(line)
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description="The file downloads remote content and executes it.",
                    severity="high",
                    capability="remote_download_execution",
                    file_path=file.path,
                    line_number=number,
                    evidence=line,
                    remediation="Pin and review downloaded artifacts before execution.",
                )
            )
            result.capabilities.append(
                make_capability(
                    "remote_download_execution",
                    file.path,
                    number,
                    resource=host,
                    command=line.strip(),
                )
            )
        return result


class SecretAccessRule:
    rule_id = "SG005"
    title = "Secret or credential access detected"
    default_severity: Severity = "high"

    def analyze(self, file: FileContent) -> RuleResult:
        result = RuleResult()
        for number, _line, match in line_matches(file.text, SECRET_RE):
            secret_name = match.group(1).strip("'\"/ ")
            evidence = (
                f"Environment variable: {secret_name}" if secret_name.isupper() else secret_name
            )
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        "The file references a likely secret, credential, or secret-bearing path."
                    ),
                    severity="high",
                    capability="secret_access",
                    file_path=file.path,
                    line_number=number,
                    evidence=evidence,
                    remediation="Avoid broad secret access or require explicit review.",
                )
            )
            result.capabilities.append(
                make_capability("secret_access", file.path, number, resource=secret_name)
            )
        return result


class FilesystemWriteRule:
    rule_id = "SG006"
    title = "Filesystem write capability detected"
    default_severity: Severity = "medium"

    def analyze(self, file: FileContent) -> RuleResult:
        result = RuleResult()
        for number, line, match in line_matches(file.text, WRITE_RE):
            target = next((group for group in match.groups() if group), None)
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description="The file appears to write to the filesystem.",
                    severity="medium",
                    capability="filesystem_write",
                    file_path=file.path,
                    line_number=number,
                    evidence=f"Target: {target}" if target else line,
                    remediation="Constrain writes to policy-approved paths.",
                )
            )
            result.capabilities.append(
                make_capability(
                    "filesystem_write", file.path, number, resource=target, command=line.strip()
                )
            )
        return result
