from __future__ import annotations

import pytest
from conftest import FIXTURES

from skillgate.rules.base import FileContent
from skillgate.rules.script_rules import FilesystemWriteRule, NetworkEgressRule
from skillgate.scan import scan_repository


@pytest.mark.parametrize("format_aware", [False, True])
def test_collection_comparison_namespace_and_placeholder_syntax_stays_clean(
    format_aware: bool,
) -> None:
    report = scan_repository(FIXTURES / "32-capability-noise-negative", format_aware=format_aware)

    assert report.findings == []
    assert report.capabilities == []


@pytest.mark.parametrize("format_aware", [False, True])
def test_real_requests_writes_and_embedded_shell_redirects_remain_visible(
    format_aware: bool,
) -> None:
    report = scan_repository(FIXTURES / "33-capability-syntax-positive", format_aware=format_aware)
    assert {item.rule_id for item in report.findings} == {"SG001", "SG003", "SG006"}
    hosts = {item.resource for item in report.capabilities if item.type == "network_egress"}
    writes = {item.resource for item in report.capabilities if item.type == "filesystem_write"}

    assert {"xml.example.invalid", "api.example.invalid", None} <= hosts
    assert {
        "generated/output.txt",
        "generated/path.txt",
        "generated/shell.txt",
        "generated/append.txt",
        "generated/node.txt",
        "generated/template.txt",
        "generated/history.txt",
        "generated/errors.txt",
        None,
    } <= writes
    assert "$OUTPUT" not in writes


@pytest.mark.parametrize("suffix", ["py", "js", "ts", "mjs", "cjs"])
def test_process_call_does_not_turn_source_comparison_into_redirect(suffix: str) -> None:
    file = FileContent(
        path=f"helper.{suffix}",
        file_type="script",
        text='if (count > limit) subprocess.run(["echo", "hello"])',
        format_aware=True,
    )

    assert FilesystemWriteRule().analyze(file).capabilities == []


def test_multiline_process_command_keeps_redirect_target() -> None:
    file = FileContent(
        path="helper.py",
        file_type="script",
        text='subprocess.run(\n    "printf hello > generated/hello.txt",\n    shell=True,\n)\n',
        format_aware=True,
    )
    result = FilesystemWriteRule().analyze(file)

    assert {item.resource for item in result.capabilities} == {"generated/hello.txt"}
    assert result.findings[0].line_number == 1


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("helper.py", 'run("printf hello > generated/hello.txt", shell=True)'),
        ("helper.js", 'exec("printf hello > generated/hello.txt")'),
    ],
)
def test_imported_process_calls_keep_redirects(path: str, text: str) -> None:
    file = FileContent(path=path, file_type="script", text=text)

    assert FilesystemWriteRule().analyze(file).capabilities[0].resource == "generated/hello.txt"


@pytest.mark.parametrize("target", ["$OUTPUT", "${OUTPUT}", "-g", "/tmp/*.txt", "`lookup`"])
def test_uncertain_redirect_targets_remain_unknown(target: str) -> None:
    file = FileContent(path="helper.sh", file_type="script", text=f"printf hello > {target}\n")
    result = FilesystemWriteRule().analyze(file)

    assert len(result.capabilities) == 1
    assert result.capabilities[0].resource is None


def test_quoted_redirect_filename_is_preserved() -> None:
    file = FileContent(
        path="helper.sh", file_type="script", text='printf hello > "generated/hello world.txt"\n'
    )

    assert (
        FilesystemWriteRule().analyze(file).capabilities[0].resource == "generated/hello world.txt"
    )


@pytest.mark.parametrize("assignment", ["NS", "XML_NAMESPACES", "nsmap: dict[str, str]"])
def test_unproven_namespace_receiver_keeps_namespace_and_request_evidence(
    assignment: str,
) -> None:
    file = FileContent(
        path="helper.py",
        file_type="script",
        text=(
            f'{assignment} = {{"文档": "https://xml.example.invalid/document"}}\n'
            f'root.findall("doc:item", namespaces={assignment.split(":")[0]})\n'
            'requests.get("https://xml.example.invalid/document")\n'
        ),
        format_aware=True,
    )
    result = NetworkEgressRule().analyze(file)

    assert {item.source_line for item in result.capabilities} == {1, 3}
    assert {item.resource for item in result.capabilities} == {"xml.example.invalid"}


def test_namespace_assignment_does_not_hide_network_calls() -> None:
    file = FileContent(
        path="helper.py",
        file_type="script",
        text='NS = {"doc": requests.get("https://xml.example.invalid/document")}\n',
    )

    assert NetworkEgressRule().analyze(file).capabilities[0].resource == "xml.example.invalid"


def test_namespace_name_does_not_hide_command_string() -> None:
    file = FileContent(
        path="helper.py",
        file_type="script",
        text='NS = {"doc": "curl https://api.example.invalid/data"}\n',
    )

    assert NetworkEgressRule().analyze(file).capabilities[0].resource == "api.example.invalid"


@pytest.mark.parametrize(
    "call", ["got", "got.get", "got.post", "got.stream", "got.extend", "got . get"]
)
def test_got_client_calls_remain_visible_with_unknown_endpoint(call: str) -> None:
    file = FileContent(path="helper.js", file_type="script", text=f"{call}(endpoint);\n")

    result = NetworkEgressRule().analyze(file)
    assert len(result.capabilities) == 1
    assert result.capabilities[0].resource is None


def test_got_method_extracts_literal_host_without_protocol() -> None:
    file = FileContent(
        path="helper.js", file_type="script", text='got.get("api.example.invalid/data")'
    )

    assert NetworkEgressRule().analyze(file).capabilities[0].resource == "api.example.invalid"


@pytest.mark.parametrize(
    "target", ["generated/$literal.txt", "generated/100%.txt", "generated/*.txt"]
)
def test_file_api_literal_paths_are_preserved(target: str) -> None:
    file = FileContent(
        path="helper.py", file_type="script", text=f"Path('{target}').write_text('result')\n"
    )

    assert FilesystemWriteRule().analyze(file).capabilities[0].resource == target


@pytest.mark.parametrize(
    "text", ["values.append(1)", "values. append(1)", "values.\n    append(1)"]
)
def test_collection_append_spacing_does_not_create_write_signal(text: str) -> None:
    file = FileContent(path="helper.py", file_type="script", text=text, format_aware=True)

    assert FilesystemWriteRule().analyze(file).capabilities == []


def test_malformed_python_retains_network_evidence() -> None:
    file = FileContent(
        path="helper.py",
        file_type="script",
        text='NS = {"doc": "https://xml.example.invalid/document"',
    )

    assert NetworkEgressRule().analyze(file).capabilities[0].resource == "xml.example.invalid"


@pytest.mark.parametrize("format_aware", [False, True])
def test_request_targets_and_adjacent_redirections_survive_noise_filters(
    format_aware: bool,
) -> None:
    report = scan_repository(FIXTURES / "34-request-target-and-redirect", format_aware=format_aware)
    assert {item.rule_id for item in report.findings} == {"SG003", "SG006"}
    hosts = {item.resource for item in report.capabilities if item.type == "network_egress"}
    assert hosts == {"upload.example.invalid", None}
    assert {item.resource for item in report.capabilities if item.type == "filesystem_write"} == {
        "output.txt"
    }


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run(["echo", "value > limit"])',
        'subprocess.run("echo value > limit")',
        'subprocess.run(["echo", "value > limit"], shell=False)',
        'subprocess.run(["echo", "value > limit"], shell=True)',
        'child_process.spawn("echo", ["value > limit"])',
    ],
)
def test_literal_process_arguments_are_not_shell_redirects(call: str) -> None:
    suffix = "js" if call.startswith("child_process") else "py"
    file = FileContent(path=f"helper.{suffix}", file_type="script", text=call, format_aware=True)
    assert FilesystemWriteRule().analyze(file).capabilities == []


@pytest.mark.parametrize(
    ("suffix", "call"),
    [
        ("py", 'subprocess.run(["bash", "-c", "echo hello > out.txt"])'),
        ("py", 'os.system("echo hello > out.txt")'),
        ("py", 'subprocess.run("echo hello > out.txt", shell=use_shell)'),
        ("js", 'child_process.spawn("bash", ["-c", "echo hello > out.txt"])'),
        ("js", "child_process.execSync(`echo hello > out.txt`)"),
        ("js", 'child_process.spawn("echo", ["hello > out.txt"], {shell: true})'),
    ],
)
def test_actual_shell_invocations_keep_redirects(suffix: str, call: str) -> None:
    result = FilesystemWriteRule().analyze(
        FileContent(path=f"helper.{suffix}", file_type="script", text=call)
    )
    assert {item.resource for item in result.capabilities} == {"out.txt"}


@pytest.mark.parametrize(
    "expression",
    [
        'f"echo hello > {output}"',
        '"echo hello > " + output',
        '"echo hello > %s" % output',
        '"echo hello > {}".format(output)',
    ],
)
def test_dynamic_shell_redirect_strings_keep_unknown_write(expression: str) -> None:
    text = f"subprocess.run({expression}, shell=True)"
    result = FilesystemWriteRule().analyze(
        FileContent(path="helper.py", file_type="script", text=text)
    )
    assert {item.resource for item in result.capabilities} == {None}


def test_xml_identifier_analysis_is_bounded_and_retains_uncertain_evidence() -> None:
    assignments = ['a0 = "https://xml.example.invalid/document"']
    assignments.extend(f"a{index} = a{index - 1}" for index in range(1, 100))
    text = "\n".join(assignments) + "\nxml.dom.minidom.parseString(a99)\n"
    result = NetworkEgressRule().analyze(
        FileContent(path="helper.py", file_type="script", text=text)
    )
    assert {item.resource for item in result.capabilities} == {"xml.example.invalid"}


@pytest.mark.parametrize(
    "text",
    [
        'curl -H "Referer: https://allowed.example.invalid" https://upload.example.invalid/data',
        'curl --header="Origin: https://allowed.example.invalid" --url=https://upload.example.invalid/data',
        'curl -d "https://allowed.example.invalid" https://upload.example.invalid/data',
        "curl --referer https://allowed.example.invalid https://upload.example.invalid/data",
        'wget --header="Referer: https://allowed.example.invalid" https://upload.example.invalid/data',
        'Invoke-WebRequest -Headers "Origin: https://allowed.example.invalid" -Uri https://upload.example.invalid/data',
        'requests.get("https://upload.example.invalid/data", headers={"Referer": "https://allowed.example.invalid"})',
        "requests.get('https://upload.example.invalid')",
    ],
)
def test_network_host_belongs_to_request_target(text: str) -> None:
    result = NetworkEgressRule().analyze(
        FileContent(path="helper.py", file_type="script", text=text)
    )
    assert {item.resource for item in result.capabilities} == {"upload.example.invalid"}


@pytest.mark.parametrize(
    "text",
    [
        'curl -H "Origin: https://allowed.example.invalid" "$ENDPOINT"',
        'requests.get(endpoint, headers={"Referer": "https://allowed.example.invalid"})',
        "curl https://[HOST]/setup",
        "curl https://{HOST}/setup",
        'requests.get("https://api.example.invalid:invalid")',
        'requests.get("https://allowed.example.invalid" + suffix)',
        'requests.get("https://{}.example.invalid".format(host))',
    ],
)
def test_invalid_and_dynamic_request_targets_remain_unknown(text: str) -> None:
    result = NetworkEgressRule().analyze(
        FileContent(path="helper.py", file_type="script", text=text)
    )
    assert {item.resource for item in result.capabilities} == {None}


@pytest.mark.parametrize(
    "text",
    [
        "curl https://allowed.example.invalid https://upload.example.invalid",
        'requests.get("https://allowed.example.invalid"); requests.get("https://upload.example.invalid")',
    ],
)
def test_every_literal_request_target_on_a_line_is_reported(text: str) -> None:
    result = NetworkEgressRule().analyze(
        FileContent(path="helper.py", file_type="script", text=text)
    )
    assert {item.resource for item in result.capabilities} == {
        "allowed.example.invalid",
        "upload.example.invalid",
    }


@pytest.mark.parametrize(
    "use",
    [
        'urlopen(NS["doc"])',
        'endpoint = NS["doc"]\nurlopen(endpoint)',
        'root.findall("doc:item", namespaces=NS)\nurlopen(NS["doc"])',
        "pairs = NS.items()\nfor item in pairs:\n    custom_request(item[1])",
    ],
)
def test_namespace_named_mapping_with_non_xml_consumers_keeps_url(use: str) -> None:
    text = 'NS = {"doc": "https://upload.example.invalid/data"}\n' + use
    result = NetworkEgressRule().analyze(
        FileContent(path="helper.py", file_type="script", text=text)
    )
    assert "upload.example.invalid" in {item.resource for item in result.capabilities}


@pytest.mark.parametrize(
    "use",
    [
        "custom_request(RELATIONSHIPS[1][0])",
        "for item in RELATIONSHIPS:\n    custom_request(item[0])",
        'for kind, target in RELATIONSHIPS:\n    relationship.setAttribute("Target", kind)',
    ],
)
def test_relationship_uri_with_non_identifier_consumer_keeps_url(use: str) -> None:
    text = (
        'RELATIONSHIPS = [("https://upload.example.invalid/data", "a.xml"), '
        '("https://upload.example.invalid/next", "b.xml")]\n' + use
    )
    result = NetworkEgressRule().analyze(
        FileContent(path="helper.py", file_type="script", text=text)
    )
    assert "upload.example.invalid" in {item.resource for item in result.capabilities}


def test_xml_namespace_attributes_do_not_mask_other_xml_urls() -> None:
    text = '''XML = """<root xmlns="https://xml.example.invalid/document" src="https://upload.example.invalid/data"/>"""\n'''
    result = NetworkEgressRule().analyze(
        FileContent(path="helper.py", file_type="script", text=text)
    )
    assert {item.resource for item in result.capabilities} == {"upload.example.invalid"}


@pytest.mark.parametrize(
    "text",
    [
        'command = "curl https://example.invalid/path"',
        "command = 'curl https://example.invalid/path'",
        "command = `curl https://example.invalid/path`",
    ],
)
def test_shell_string_delimiters_keep_network_host(text: str) -> None:
    result = NetworkEgressRule().analyze(FileContent("helper.js", "script", text))

    assert {item.resource for item in result.capabilities} == {"example.invalid"}


def test_escaped_shell_delimiter_keeps_network_host() -> None:
    text = r'command = "curl \"https://example.invalid/path\""'

    result = NetworkEgressRule().analyze(FileContent("helper.js", "script", text))

    assert {item.resource for item in result.capabilities} == {"example.invalid"}


def test_unterminated_escaped_shell_string_keeps_unknown_network_evidence() -> None:
    text = '"curl ' + r"\a" * 1000

    result = NetworkEgressRule().analyze(FileContent("helper.js", "script", text))

    assert len(result.capabilities) == 1
    assert result.capabilities[0].resource is None


@pytest.mark.parametrize("format_aware", [False, True])
def test_markdown_language_fences_quotes_and_real_commands(format_aware: bool) -> None:
    text = (
        "> Script paths below are examples.\n"
        "```python\ndef size() -> int:\n    return 1\n```\n"
        '```python\nsubprocess.run(["echo", "value > limit"])\n```\n'
        '```python\nsubprocess.run(\n    "echo hello > out.txt",\n    shell=True,\n)\n```\n'
        "> cat <input.txt>quoted-output.txt\n"
        "```bash\ncat <input.txt>shell-output.txt\n```\n"
    )
    file = FileContent(path="SKILL.md", file_type="markdown", text=text, format_aware=format_aware)
    writes = {item.resource for item in FilesystemWriteRule().analyze(file).capabilities}
    assert writes == (
        {"out.txt", "quoted-output.txt", "shell-output.txt"}
        if format_aware
        else {"quoted-output.txt", "shell-output.txt"}
    )


def test_indented_and_inline_markdown_redirects_keep_real_targets() -> None:
    text = "> Example commands:\n\n    > empty.txt\n\nRun `cat <input.txt>inline.txt`.\n"
    result = FilesystemWriteRule().analyze(
        FileContent(path="SKILL.md", file_type="markdown", text=text)
    )
    assert {(item.source_line, item.resource) for item in result.capabilities} == {
        (3, "empty.txt"),
        (5, "inline.txt"),
    }
