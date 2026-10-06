from __future__ import annotations

import ast
import re
import shlex
import textwrap
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
PY_WRITE_MODE = r"""['"][rwaxbt+]*[wax+][rwaxbt+]*['"]"""
WRITE_RE = re.compile(
    r"(?i)(?:\b(?:write|overwrite)\b|(?<![.\w])append\b(?!\s*\()|"
    rf"\bopen\s*\(\s*[^,\n)]+,\s*(?:mode\s*=\s*)?{PY_WRITE_MODE}|"
    r"Path\s*\([^)]*\)\.write_(?:text|bytes)\s*\(|"
    r"fs\.(?:promises\.)?(?:writeFile|appendFile|createWriteStream)|"
    r"\b(?:Out-File|Set-Content|Add-Content|New-Item)\b|\btee\b)"
)
PY_OPEN_TARGET_RE = re.compile(
    r"""\bopen\s*\(\s*(?:file\s*=\s*)?(?P<target>.+?)\s*,\s*"""
    rf"(?:mode\s*=\s*)?{PY_WRITE_MODE}"
)
PATH_WRITE_TARGET_RE = re.compile(
    r"""\bPath\s*\(\s*(?P<target>.*?)\s*\)\.write_(?:text|bytes)\s*\("""
)
NODE_FS_TARGET_RE = re.compile(
    r"""fs\.(?:promises\.)?(?:writeFile|appendFile|createWriteStream)\s*"""
    r"""\(\s*"""
)
TEE_TARGET_RE = re.compile(r"""(?i)\btee\s+(?P<args>[^|;&<>\n]+)""")
REDIRECT_TARGET_RE = re.compile(
    r"""(?<![<=>])>{1,2}(?![=>])\s*(?P<target>"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[^\s|;&<>`]+)"""
)
SHELL_STRING_RE = re.compile(r"""(['"`])(?P<command>(?:\\.|(?!\1)[^\\\n])*)\1""")
PROCESS_CALL_RE = re.compile(
    r"\b(?:exec|execSync|spawn|spawnSync|run|call|check_call|check_output|Popen|system)\s*\("
)
ANGLE_PLACEHOLDER_RE = re.compile(r"<[^<>\s]+>")
SOURCE_LANGUAGE_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs", ".html", ".xml"}
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
CURL_PROXY_OPTIONS = {
    "-x",
    "--proxy",
    "--preproxy",
    "--socks4",
    "--socks4a",
    "--socks5",
    "--socks5-hostname",
}
CURL_PEER_OPTIONS = CURL_PROXY_OPTIONS | {"--connect-to", "--resolve"}
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
    "--noproxy",
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
    peer_option: str | None = None
    option_values = NETWORK_OPTION_VALUES | ({"-O"} if command.lower() == "wget" else set())
    powershell = command.lower() not in {"curl", "wget"}
    if powershell:
        option_values = {option.lower() for option in option_values}
    for token in tokens:
        if token and token[0] in "|;&<>":
            break
        if peer_option is not None:
            hosts.extend(_connection_hosts(peer_option, token))
            peer_option = None
            continue
        if skip_value:
            skip_value = False
            continue
        option, separator, value = token.partition("=")
        if command.lower() == "curl" and token.startswith("-x") and token not in {"-x", "-x="}:
            option, separator, value = "-x", "=", token[2:].removeprefix("=")
        if powershell:
            option = option.lower()
        if command.lower() == "curl" and option in CURL_PEER_OPTIONS:
            if separator:
                hosts.extend(_connection_hosts(option, value))
            else:
                peer_option = option
            continue
        if option in option_values:
            skip_value = not bool(separator)
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
    if peer_option is not None:
        hosts.append(None)
    return hosts or [None]


def _connection_hosts(option: str, value: str) -> list[str | None]:
    if option in CURL_PROXY_OPTIONS:
        if not value:
            return []
        return [host_from_token(value if "://" in value else f"http://{value}")]
    if option == "--connect-to":
        match = re.fullmatch(
            r"(?:\[[^\]]+\]|[^:]*):[0-9]*:(?P<host>\[[^\]]+\]|[^:]*):[0-9]*", value
        )
        if match is None:
            return [None]
        host = match["host"]
        return [host_from_token(f"https://{host}")] if host else []
    match = re.fullmatch(r"\+?(?:\[[^\]]+\]|[^:]+):[0-9]+:(?P<hosts>.+)", value)
    if match is None:
        return [None]
    return [host_from_token(f"https://{host}") for host in match["hosts"].split(",")]


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


def _file_target(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    # Parent traversal depends on runtime directories and symlinks. Never
    # approve it by matching a literal prefix against a directory allowlist.
    if ".." in value.replace("\\", "/").split("/"):
        return None
    return value


def _python_file_target(expression: str) -> str | None:
    try:
        value = ast.literal_eval(expression)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return None
    return _file_target(value)


def _shell_file_target(token: str) -> str | None:
    if token.startswith("-") or any(char in token for char in "$%{}*`\\"):
        return None
    return _file_target(token.strip("'\""))


def extract_write_targets(
    file: FileContent, text: str, *, markdown: bool = False
) -> list[str | None]:
    targets: list[str | None] = []
    for pattern in [PY_OPEN_TARGET_RE, PATH_WRITE_TARGET_RE]:
        targets.extend(_python_file_target(match["target"]) for match in pattern.finditer(text))
    for call in NODE_FS_TARGET_RE.finditer(text):
        literal = SHELL_STRING_RE.match(text, call.end())
        complete = literal is not None and text[literal.end() :].lstrip().startswith((",", ")"))
        value = literal["command"] if complete else None
        if value is not None and ("\\" in value or (literal[1] == "`" and "${" in value)):
            value = None
        targets.append(_file_target(value))

    candidates = [text]
    if PurePosixPath(file.path).suffix.lower() in SOURCE_LANGUAGE_SUFFIXES:
        candidates = process_shell_strings(text, PurePosixPath(file.path).suffix.lower())
    for candidate in candidates:
        targets.extend(
            _shell_file_target(match["target"])
            for match in POWERSHELL_WRITE_TARGET_RE.finditer(candidate)
        )
        for match in TEE_TARGET_RE.finditer(candidate):
            try:
                tokens = shlex.split(match["args"])
            except ValueError:
                targets.append(None)
                continue
            targets.extend(_shell_file_target(token) for token in tokens if token != "-a")
        placeholders = (
            list(ANGLE_PLACEHOLDER_RE.finditer(candidate))
            if markdown or file.file_type == "markdown"
            else []
        )
        for match in REDIRECT_TARGET_RE.finditer(candidate):
            if any(
                item.start() <= match.start() < item.end()
                and (item.start() == 0 or candidate[item.start() - 1].isspace())
                and (
                    not candidate[item.end() :].strip()
                    or candidate[item.end() :].lstrip().startswith("-")
                    or candidate[item.end() :].startswith(("`", "]"))
                )
                and re.search(r"\b(?:npx|npm|pnpm|yarn|uvx|skills)\b", candidate[: item.start()])
                for item in placeholders
            ):
                continue
            targets.append(_shell_file_target(match["target"]))
    if not targets and WRITE_RE.search(text):
        targets.append(None)
    return list(dict.fromkeys(targets))


def python_shell_strings(text: str) -> list[tuple[int, int, str]]:
    try:
        tree = ast.parse(textwrap.dedent(text))
    except (SyntaxError, ValueError, RecursionError):
        return []
    commands = []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        name = (
            call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
        )
        if name not in {
            "run",
            "call",
            "check_call",
            "check_output",
            "Popen",
            "system",
            "getoutput",
            "getstatusoutput",
        }:
            continue
        shell = next((item.value for item in call.keywords if item.arg == "shell"), None)
        uses_shell = name in {"system", "getoutput", "getstatusoutput"} or (
            shell is not None and not (isinstance(shell, ast.Constant) and not shell.value)
        )
        argument = (
            call.args[0]
            if call.args
            else next((item.value for item in call.keywords if item.arg == "args"), None)
        )
        if argument is None:
            continue
        call_commands = []
        command = _python_command_string(argument)
        if command is not None:
            if uses_shell:
                call_commands.append(command)
        elif isinstance(argument, ast.List | ast.Tuple):
            argv = [_python_command_string(item) for item in argument.elts]
            if argv and uses_shell and argv[0]:
                call_commands.append(argv[0])
            call_commands.extend(_explicit_shell_command(argv))
        commands.extend(
            (call.lineno, call.end_lineno or call.lineno, command) for command in call_commands
        )
    return commands


def _javascript_shell_fragments(expression: str) -> list[str]:
    literals = list(SHELL_STRING_RE.finditer(expression))
    if not literals:
        return []
    if any(char in expression[: literals[0].start()] for char in "()[]{}"):
        return []
    fragments = []
    for index, literal in enumerate(literals):
        previous_end = literals[index - 1].end() if index else 0
        next_start = literals[index + 1].start() if index + 1 < len(literals) else len(expression)
        if any(char in expression[previous_end : literal.start()] for char in "()[]{}"):
            continue
        fragment = literal["command"]
        if re.search(r"\+\s*$", expression[previous_end : literal.start()]):
            fragment = "${unknown}" + fragment
        if re.match(r"\s*\+", expression[literal.end() : next_start]):
            fragment += "${unknown}"
        fragments.append(fragment)
    return fragments


def _javascript_matching_close(text: str, open_index: int) -> int | None:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = [text[open_index]]
    quote: str | None = None
    escaped = False
    for index in range(open_index + 1, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in pairs:
            if not stack or stack[-1] != pairs[char]:
                return None
            stack.pop()
            if not stack:
                return index
    return None


def _strip_javascript_grouping(expression: str) -> str:
    expression = expression.strip()
    while expression.startswith("("):
        close = _javascript_matching_close(expression, 0)
        if close != len(expression) - 1:
            break
        expression = expression[1:close].strip()
    return expression


def _javascript_call_arguments(text: str, open_index: int) -> list[str] | None:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = ["("]
    arguments: list[str] = []
    start = open_index + 1
    quote: str | None = None
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in pairs:
            if not stack or stack[-1] != pairs[char]:
                return None
            stack.pop()
            if not stack:
                arguments.append(text[start:index])
                return arguments
        elif char == "," and len(stack) == 1:
            arguments.append(text[start:index])
            start = index + 1
    return None


def _javascript_argument_fragments(expression: str) -> list[str]:
    expression = _strip_javascript_grouping(expression)
    array = re.fullmatch(r"\s*\[(?P<items>.*)\]\s*", expression, re.DOTALL)
    return _javascript_shell_fragments(array["items"] if array else expression)


def process_shell_strings(text: str, suffix: str) -> list[str]:
    if suffix == ".py":
        return [command for _start, _end, command in python_shell_strings(text)]
    commands = []
    for call in PROCESS_CALL_RE.finditer(text):
        arguments = _javascript_call_arguments(text, call.end() - 1)
        if not arguments:
            continue
        name = call[0].split("(")[0].strip()
        executable = _javascript_argument_fragments(arguments[0])
        if not executable:
            continue
        if name in {"exec", "execSync", "system"}:
            commands.extend(executable)
        elif name in {"spawn", "spawnSync"}:
            argv = executable + [
                fragment
                for argument in arguments[1:]
                for fragment in _javascript_argument_fragments(argument)
            ]
            shell_true = any(
                re.search(r"\bshell\s*:\s*true\b", argument) for argument in arguments[2:]
            )
            if shell_true:
                # Node joins argv into the shell command when shell=true.
                commands.extend(executable)
                if len(arguments) > 1:
                    commands.extend(_javascript_argument_fragments(arguments[1]))
            commands.extend(_explicit_shell_command(argv))
    return commands


def _python_command_string(node: ast.AST, depth: int = 0) -> str | None:
    if depth >= 32:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            value.value if isinstance(value, ast.Constant) else "${unknown}"
            for value in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        left = _python_command_string(node.left, depth + 1)
        if left is not None:
            if isinstance(node.op, ast.Mod):
                return left
            right = _python_command_string(node.right, depth + 1)
            return left + ("${unknown}" if right is None else right)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return _python_command_string(node.func.value, depth + 1)
    return None


def _explicit_shell_command(argv: list[str | None]) -> list[str]:
    if not argv or not argv[0]:
        return []
    executable = PurePosixPath(argv[0].replace("\\", "/")).name.lower()
    if executable not in {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}:
        return []
    for index, argument in enumerate(argv[:-1]):
        if argument in {"-c", "-lc", "/c", "-Command", "-command"} and argv[index + 1]:
            return [argv[index + 1]]
    return []


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
        sections = script_sections(file)
        physical = [
            (offset + number, line, match)
            for offset, section in sections
            for number, line, match in line_matches(section.text, SHELL_RE)
        ]
        for number, line, _match in physical:
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
        logical = logical_matches(file, SHELL_RE)
        for span, _match in logical:
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
        sections = script_sections(file)
        views = [
            (section, offset + number, line, line)
            for offset, section in sections
            for number, line in enumerate(section.text.splitlines(), start=1)
        ]
        spans = [
            (offset, section, span)
            for offset, section in sections
            if file.format_aware
            for span in iter_logical_spans(section.text, section.file_type)
        ]
        for offset, section, span in spans:
            if file.file_type == "markdown" and section.file_type == "script":
                # Fences did not previously add logical source spans. Add only
                # shell strings here; prose-like argv data must not gain writes.
                commands = process_shell_strings(span.text, PurePosixPath(section.path).suffix)
                if not any(REDIRECT_TARGET_RE.search(command) for command in commands):
                    continue
            views.append((section, offset + span.start_line, span.text, span.evidence))
        for offset, section in sections:
            if PurePosixPath(section.path).suffix.lower() != ".py":
                continue
            lines = section.text.splitlines()
            for start, end, command in python_shell_strings(section.text):
                if end > start and not file.format_aware:
                    continue
                evidence = "\n".join(lines[start - 1 : end])
                shell_section = FileContent(section.path + ".sh", "script", command)
                views.append((shell_section, offset + start, command, evidence))
        seen: set[tuple[int, str | None]] = set()
        for section, number, text, evidence in views:
            for target in extract_write_targets(
                section, text, markdown=file.file_type == "markdown"
            ):
                if (number, target) in seen:
                    continue
                seen.add((number, target))
                result.findings.append(
                    make_finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description="The file appears to write to the filesystem.",
                        severity="medium",
                        capability="filesystem_write",
                        file_path=file.path,
                        line_number=number,
                        evidence=f"Target: {target}" if target else evidence,
                        remediation="Constrain writes to policy-approved paths.",
                    )
                )
                result.capabilities.append(
                    make_capability(
                        "filesystem_write",
                        file.path,
                        number,
                        resource=target,
                        command=evidence.strip(),
                    )
                )
        return result
