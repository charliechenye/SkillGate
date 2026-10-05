from __future__ import annotations

import re
import shlex
from collections import Counter
from pathlib import PurePosixPath
from urllib.parse import urlparse

from skillgate.logical import LogicalSpan, iter_logical_spans
from skillgate.mcp_apps import inventory_from_json_text
from skillgate.models import Severity
from skillgate.rules.base import FileContent, RuleResult, make_capability, make_finding
from skillgate.rules.xml_context import without_xml_identifiers

SHELL_RE = re.compile(
    r"(?i)(?:(?<![.\w/-])(?:bash|sh|zsh|powershell|pwsh|cmd\.exe)(?![\w.-])|"
    r"subprocess\.|os\.system|child_process\.(?:exec|spawn))"
)
DESTRUCTIVE_RE = re.compile(
    r"(?i)(rm\s+-[a-z]*r[a-z]*f|del\s+/s|Remove-Item\s+.*-Recurse\s+.*-Force|"
    r"Remove-Item\s+.*-Recurse|sudo\s+rm\s+-[a-z]*r[a-z]*f|rm\s+-r\b|"
    r"shutil\.rmtree|Path\s*\([^)]*\)\.(?:unlink|rmdir)\s*\(|"
    r"fs\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\s*\(|"
    r"\bformat\s+(?:/[a-z]+\s+)*[a-z]:|\bmkfs(?:\.[a-z0-9]+)?\s+|"
    r"drop\s+database|truncate\s+table|git\s+clean\s+-fdx)"
)
NETWORK_RE = re.compile(
    r"(?i)(?:\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|"
    r"axios|node-fetch)\b|\bgot\s*(?:\.\s*[A-Za-z_$][\w$]*)?\s*\(|"
    r"requests\.(?:get|post)|httpx\.(?:get|post)|\burlopen\s*\(|"
    r"aiohttp\.ClientSession|undici\.request|\bfetch\s*\(|https?\.(?:get|request)|"
    r"https?://[^\s'\"<>]+)"
)
URL_RE = re.compile(r"https?://[^\s'\"`<>()]+")
REMOTE_EXEC_RE = re.compile(
    r"(?i)(curl\b.*\|\s*(?:bash|sh|zsh)|wget\b.*\|\s*(?:bash|sh|zsh)|"
    r"\biex\s*\(\s*iwr\b|python\s+-c\s+['\"]?\$?\(?(?:curl|wget)\b)"
)
DOWNLOAD_COMMAND_RE = re.compile(r"(?i)\b(?P<command>curl|wget)\b(?P<args>.*)")
DOWNLOAD_OUTPUT_RE = re.compile(r"(?i)(?:^|\s)(?:--output|-o)\s+(?P<target>[^\s;&|]+)")
REMOTE_NAME_FLAG_RE = re.compile(r"(?i)(?:^|\s)(?:-[^\s;&|]*O[^\s;&|]*|--remote-name)(?:\s|$)")
SHELL_FILE_RE = re.compile(r"(?i)\b(?:bash|sh|zsh)\s+(?P<target>[^\s;&|]+)")
SECRET_RE = re.compile(
    r"(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|OPENAI_API_KEY|"
    r"ANTHROPIC_API_KEY|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|"
    r"~/.ssh/|~/.aws/|(?:^|[\s'\"/])\.env(?:$|[\s'\"/]))"
)
WRITE_RE = re.compile(
    r"(?i)(?:\b(?:write|append|overwrite)\b|open\s*\([^)]*['\"][wa]['\"]|"
    r"Path\s*\([^)]*\)\.write_(?:text|bytes)\s*\(|"
    r"fs\.(?:promises\.)?(?:writeFile|appendFile|createWriteStream)|"
    r"\b(?:Out-File|Set-Content|Add-Content|New-Item)\b|\btee\b|"
    r"cat\s+>\s*([^\s]+)|>\s*([A-Za-z0-9_./-]+))"
)
PY_OPEN_TARGET_RE = re.compile(
    r"""open\s*\(\s*['"](?P<target>[^'"]+)['"]\s*,\s*['"][^'"]*[wa][^'"]*['"]"""
)
PATH_WRITE_TARGET_RE = re.compile(
    r"""Path\s*\(\s*['"](?P<target>[^'"]+)['"]\s*\)\.write_(?:text|bytes)\s*\("""
)
NODE_FS_TARGET_RE = re.compile(
    r"""fs\.(?:promises\.)?(?:writeFile|appendFile|createWriteStream)\s*"""
    r"""\(\s*['"](?P<target>[^'"]+)['"]"""
)
TEE_TARGET_RE = re.compile(r"""(?i)\btee(?:\s+-a)?\s+(?P<target>[^\s|;&]+)""")
REDIRECT_TARGET_RE = re.compile(r"""(?<![0-9])>\s*(?P<target>[A-Za-z0-9_./-]+)""")
CAT_REDIRECT_TARGET_RE = re.compile(r"""(?i)cat\s+>\s*(?P<target>[^\s|;&]+)""")
SHELL_STRING_RE = re.compile(r"""(['"`])(?P<command>(?:\\.|(?!\1).)*?)\1""")
POWERSHELL_WRITE_TARGET_RE = re.compile(
    r"""(?ix)\b(?:Out-File|Set-Content|Add-Content|New-Item)\b"""
    r""".*?-(?:FilePath|Path)\s+['"]?(?P<target>[A-Za-z0-9_./\\:-]+)['"]?"""
)
NETWORK_CALL_TARGET_RE = re.compile(
    r"""(?i)\b(?:requests\.(?:get|post)|httpx\.(?:get|post)|urlopen|fetch|"""
    r"""axios(?:\.get|\.post)?|got\s*(?:\.\s*[A-Za-z_$][\w$]*)?|"""
    r"""undici\.request|https?\.(?:get|request))\s*"""
    r"""\(\s*(?:['"](?P<target>[^'"]*)['"])?"""
)
NETWORK_COMMAND_RE = re.compile(
    r"""(?i)\b(?P<command>curl|wget|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b"""
)
NETWORK_OPTION_VALUES = {
    "-H",
    "--header",
    "-e",
    "--referer",
    "-A",
    "--user-agent",
    "-u",
    "--user",
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--json",
    "-F",
    "--form",
    "--form-string",
    "-o",
    "--output",
    "--output-document",
    "-X",
    "--request",
    "-b",
    "--cookie",
    "-c",
    "--cookie-jar",
    "-x",
    "--proxy",
    "--connect-to",
    "--resolve",
    "--cacert",
    "--cert",
    "--key",
    "--config",
    "-K",
    "--max-time",
    "--connect-timeout",
    "--retry",
    "--request-body",
    "--post-data",
    "--post-file",
    "--body-data",
    "--body-file",
    "-OutFile",
    "-Headers",
    "-Body",
    "-Method",
    "-Destination",
    "-Credential",
    "-ContentType",
}
FENCE_RE = re.compile(r"^\s*(?P<marker>`{3,}|~{3,})(?P<language>[^\s`~]*)\s*$")
FENCE_SUFFIXES = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "js": ".js",
    "typescript": ".ts",
    "ts": ".ts",
    "bash": ".sh",
    "sh": ".sh",
    "shell": ".sh",
    "zsh": ".sh",
    "powershell": ".ps1",
    "ps1": ".ps1",
    "html": ".html",
    "xml": ".xml",
}


def script_sections(file: FileContent) -> list[tuple[int, FileContent]]:
    """Separate Markdown prose and fenced code with physical-line offsets."""
    if file.file_type != "markdown":
        return [(0, file)]
    sections = []
    lines: list[str] = []
    marker = ""
    suffix = ""
    start = 0
    for index, raw in enumerate(file.text.splitlines(keepends=True)):
        line = re.sub(r"^ {0,3}>\s?", "", raw) if not marker else raw
        fence = FENCE_RE.match(line.rstrip("\r\n"))
        if fence and (
            not marker
            or (
                fence["marker"][0] == marker[0]
                and not fence["language"]
                and len(fence["marker"]) >= len(marker)
            )
        ):
            if lines:
                sections.append(
                    (
                        start,
                        FileContent(
                            path=file.path + suffix,
                            file_type="script" if marker else "markdown",
                            text="".join(lines),
                            format_aware=file.format_aware,
                        ),
                    )
                )
            lines = []
            start = index + 1
            if marker:
                marker, suffix = "", ""
            else:
                marker = fence["marker"]
                suffix = FENCE_SUFFIXES.get(fence["language"].lower(), ".txt")
        else:
            lines.append(line)
    if lines:
        sections.append(
            (
                start,
                FileContent(
                    path=file.path + suffix,
                    file_type="script" if marker else "markdown",
                    text="".join(lines),
                    format_aware=file.format_aware,
                ),
            )
        )
    return sections


def line_matches(text: str, pattern: re.Pattern[str]) -> list[tuple[int, str, re.Match[str]]]:
    matches = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if match:
            matches.append((number, line, match))
    return matches


def logical_matches(
    file: FileContent, pattern: re.Pattern[str]
) -> list[tuple[LogicalSpan, re.Match[str]]]:
    if not file.format_aware:
        return []
    matches = []
    for span in iter_logical_spans(file.text, file.file_type):
        match = pattern.search(span.text)
        if match:
            matches.append((span, match))
    return matches


def extract_host(text: str) -> str | None:
    hosts = extract_hosts(text)
    return hosts[0] if len(hosts) == 1 else None


def extract_hosts(text: str) -> list[str | None]:
    """Bind hosts to request targets before considering incidental URL literals."""
    hosts: list[str | None] = []
    calls = list(NETWORK_CALL_TARGET_RE.finditer(text))
    for call in calls:
        target = call["target"]
        remainder = text[call.end() :].lstrip()
        literal_argument = not remainder or remainder.startswith((",", ")"))
        hosts.append(host_from_token(target) if target is not None and literal_argument else None)
    commands = list(NETWORK_COMMAND_RE.finditer(text))
    for command in commands:
        # A command inside a source string ends at that string's delimiter.
        container = next(
            (
                item
                for item in SHELL_STRING_RE.finditer(text)
                if item.start("command") <= command.start() < item.end("command")
            ),
            None,
        )
        end = container.end("command") if container else len(text)
        args = text[command.end() : end]
        hosts.extend(_command_hosts(args, command["command"]))
    if not calls and not commands:
        hosts = [host_from_token(match[0]) for match in URL_RE.finditer(text)]
    return list(dict.fromkeys(hosts)) or [None]


def _command_hosts(args: str, command: str) -> list[str | None]:
    try:
        lexer = shlex.shlex(args, posix=True, punctuation_chars="|;&<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return [None]
    hosts: list[str | None] = []
    skip_value = False
    option_values = NETWORK_OPTION_VALUES | ({"-O"} if command.lower() == "wget" else set())
    powershell = command.lower() not in {"curl", "wget"}
    if powershell:
        option_values = {option.lower() for option in option_values}
    for token in tokens:
        if token and token[0] in "|;&<>":
            break
        if skip_value:
            skip_value = False
            continue
        option, _, value = token.partition("=")
        if powershell:
            option = option.lower()
        if option in option_values:
            skip_value = not bool(value)
            continue
        if option.lower() in {"--url", "-uri", "-source"}:
            if value:
                hosts.append(host_from_token(value))
            continue
        if token.startswith("-"):
            continue
        host = host_from_token(token)
        if host is not None or "://" in token or token.startswith(("$", "@")):
            hosts.append(host)
    return hosts or [None]


def host_from_token(token: str) -> str | None:
    cleaned = token.strip().strip("'\"`,;()")
    if not cleaned or cleaned.startswith("-") or cleaned.startswith((".", "/")):
        return None
    try:
        parsed = urlparse(cleaned if "://" in cleaned else f"//{cleaned}")
        host = parsed.hostname
        # Accessing port also validates malformed authorities.
        _ = parsed.port
    except ValueError:
        return None
    if host and not re.search(r"[^a-z0-9.:-]", host) and ("://" in cleaned or "." in host):
        return host
    return None


def extract_write_target(line: str, fallback_match: re.Match[str]) -> str | None:
    for pattern in [
        PY_OPEN_TARGET_RE,
        PATH_WRITE_TARGET_RE,
        NODE_FS_TARGET_RE,
        CAT_REDIRECT_TARGET_RE,
        POWERSHELL_WRITE_TARGET_RE,
        TEE_TARGET_RE,
        REDIRECT_TARGET_RE,
    ]:
        match = pattern.search(line)
        if match:
            return match.group("target").strip("'\"")
    return next((group for group in fallback_match.groups() if group), None)


def normalize_file_target(value: str) -> str:
    return PurePosixPath(value.strip("'\"` ").replace("\\", "/")).name


def downloaded_file_target(line: str) -> str | None:
    command_match = DOWNLOAD_COMMAND_RE.search(line)
    if not command_match:
        return None
    command = command_match.group("command").lower()
    args = command_match.group("args")
    output_match = DOWNLOAD_OUTPUT_RE.search(args)
    if output_match:
        return normalize_file_target(output_match.group("target"))
    if command == "curl" and not REMOTE_NAME_FLAG_RE.search(args):
        return None
    url_match = URL_RE.search(args)
    if not url_match:
        return None
    try:
        path = urlparse(url_match.group(0)).path.rstrip("/")
    except ValueError:
        return None
    target = PurePosixPath(path).name
    return target or None


def multiline_remote_execution_matches(
    text: str, window: int = 3
) -> list[tuple[int, str, int, str]]:
    lines = text.splitlines()
    matches: list[tuple[int, str, int, str]] = []
    for index, line in enumerate(lines):
        downloaded = downloaded_file_target(line)
        if not downloaded:
            continue
        for execution_index in range(index + 1, min(index + window + 1, len(lines))):
            execution = SHELL_FILE_RE.search(lines[execution_index])
            if execution and normalize_file_target(execution.group("target")) == downloaded:
                matches.append((index + 1, line, execution_index + 1, lines[execution_index]))
                break
    return matches


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
        for span, _match in logical_matches(file, SHELL_RE):
            severity: Severity = (
                "high"
                if DESTRUCTIVE_RE.search(span.text) or REMOTE_EXEC_RE.search(span.text)
                else "medium"
            )
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description="The file appears to invoke a shell or process execution API.",
                    severity=severity,
                    capability="shell_execution",
                    file_path=file.path,
                    line_number=span.start_line,
                    evidence=span.evidence,
                    remediation="Review whether shell execution is necessary and policy-approved.",
                )
            )
            result.capabilities.append(
                make_capability(
                    "shell_execution", file.path, span.start_line, command=span.evidence.strip()
                )
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
        for span, _match in logical_matches(file, DESTRUCTIVE_RE):
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
                    line_number=span.start_line,
                    evidence=span.evidence,
                    remediation="Remove the destructive action or require explicit review.",
                )
            )
            result.capabilities.append(
                make_capability(
                    "destructive_action", file.path, span.start_line, command=span.evidence.strip()
                )
            )
        return result


class NetworkEgressRule:
    rule_id = "SG003"
    title = "Network egress detected"
    default_severity: Severity = "medium"

    def analyze(self, file: FileContent) -> RuleResult:
        result = RuleResult()
        for offset, section in script_sections(file):
            text = _network_scan_text(section)
            logical_file = FileContent(
                path=section.path,
                file_type=section.file_type,
                text=text,
                format_aware=section.format_aware,
            )
            matches = [
                (offset + number, line, line) for number, line, _ in line_matches(text, NETWORK_RE)
            ]
            matches.extend(
                (offset + span.start_line, span.text, span.evidence)
                for span, _ in logical_matches(logical_file, NETWORK_RE)
                if file.file_type != "markdown" or section.file_type == "markdown"
            )
            for number, scan_text, evidence in matches:
                for host in extract_hosts(scan_text):
                    result.findings.append(
                        make_finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description="The file appears to access a network resource.",
                            severity="medium",
                            capability="network_egress",
                            file_path=file.path,
                            line_number=number,
                            evidence=f"Host: {host}" if host else evidence,
                            remediation="Allowlist the host or remove the network access.",
                        )
                    )
                    result.capabilities.append(
                        make_capability(
                            "network_egress",
                            file.path,
                            number,
                            resource=host,
                            command=evidence.strip(),
                        )
                    )
        return result


def _network_scan_text(file: FileContent) -> str:
    if PurePosixPath(file.path).suffix.lower() == ".py":
        return without_xml_identifiers(file.text)
    if file.file_type not in {"mcp_config", "mcp_registry", "json_config"}:
        return file.text
    inventory = inventory_from_json_text(file.text)
    text = file.text
    declared_origins = Counter(
        origin.origin for resource in inventory.resources for origin in resource.origins
    )
    for origin, declaration_count in sorted(declared_origins.items()):
        if text.count(origin) == declaration_count:
            text = text.replace(origin, "")
    return text


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
        for (
            download_line_number,
            download_line,
            execution_line_number,
            execution_line,
        ) in multiline_remote_execution_matches(file.text):
            host = extract_host(download_line)
            evidence = (
                f"download line {download_line_number}: {download_line.strip()} -> "
                f"execution line {execution_line_number}: {execution_line.strip()}"
            )
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description="The file downloads remote content and executes it.",
                    severity="high",
                    capability="remote_download_execution",
                    file_path=file.path,
                    line_number=execution_line_number,
                    evidence=evidence,
                    remediation="Pin and review downloaded artifacts before execution.",
                )
            )
            result.capabilities.append(
                make_capability(
                    "remote_download_execution",
                    file.path,
                    execution_line_number,
                    resource=host,
                    command=evidence,
                )
            )
        if file.format_aware:
            for span in iter_logical_spans(file.text, file.file_type):
                if span.reason != "script-continuation":
                    continue
                downloaded = downloaded_file_target(span.text)
                execution = SHELL_FILE_RE.search(span.text)
                if not downloaded or not execution:
                    continue
                if normalize_file_target(execution.group("target")) != downloaded:
                    continue
                host = extract_host(span.text)
                result.findings.append(
                    make_finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description="The file downloads remote content and executes it.",
                        severity="high",
                        capability="remote_download_execution",
                        file_path=file.path,
                        line_number=span.start_line,
                        evidence=span.evidence,
                        remediation="Pin and review downloaded artifacts before execution.",
                    )
                )
                result.capabilities.append(
                    make_capability(
                        "remote_download_execution",
                        file.path,
                        span.start_line,
                        resource=host,
                        command=span.evidence.strip(),
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
        for span, match in logical_matches(file, SECRET_RE):
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
                    line_number=span.start_line,
                    evidence=evidence,
                    remediation="Avoid broad secret access or require explicit review.",
                )
            )
            result.capabilities.append(
                make_capability("secret_access", file.path, span.start_line, resource=secret_name)
            )
        return result


class FilesystemWriteRule:
    rule_id = "SG006"
    title = "Filesystem write capability detected"
    default_severity: Severity = "medium"

    def analyze(self, file: FileContent) -> RuleResult:
        result = RuleResult()
        for number, line, match in line_matches(file.text, WRITE_RE):
            target = extract_write_target(line, match)
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
        for span, match in logical_matches(file, WRITE_RE):
            target = extract_write_target(span.text, match)
            result.findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description="The file appears to write to the filesystem.",
                    severity="medium",
                    capability="filesystem_write",
                    file_path=file.path,
                    line_number=span.start_line,
                    evidence=f"Target: {target}" if target else span.evidence,
                    remediation="Constrain writes to policy-approved paths.",
                )
            )
            result.capabilities.append(
                make_capability(
                    "filesystem_write",
                    file.path,
                    span.start_line,
                    resource=target,
                    command=span.evidence.strip(),
                )
            )
        return result
