from __future__ import annotations

import pytest
from conftest import FIXTURES

from skillgate.rules.base import FileContent
from skillgate.rules.script_rules import NetworkEgressRule
from skillgate.scan import scan_repository


@pytest.mark.parametrize("format_aware", [False, True])
def test_collection_comparison_namespace_and_placeholder_syntax_stays_clean(
    format_aware: bool,
) -> None:
    report = scan_repository(FIXTURES / "32-capability-noise-negative", format_aware=format_aware)

    assert report.findings == []
    assert report.capabilities == []


@pytest.mark.parametrize("assignment", ["NS", "XML_NAMESPACES", "nsmap: dict[str, str]"])
def test_namespace_masking_preserves_identical_request_url_and_source_lines(
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

    assert {item.source_line for item in result.capabilities} == {3}
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


def test_malformed_python_retains_network_evidence() -> None:
    file = FileContent(
        path="helper.py",
        file_type="script",
        text='NS = {"doc": "https://xml.example.invalid/document"',
    )

    assert NetworkEgressRule().analyze(file).capabilities[0].resource == "xml.example.invalid"


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
