from __future__ import annotations

import pytest
from conftest import FIXTURES

from skillgate.policy import evaluate_policy
from skillgate.rules.base import FileContent
from skillgate.rules.script_rules import NetworkEgressRule
from skillgate.scan import scan_paths, scan_repository


@pytest.mark.parametrize(
    ("binding", "call"),
    [
        ("from urllib.request import urlopen as parseString", "parseString"),
        ("from urllib.request import urlopen as fromstring", "fromstring"),
        ("def parseString(value):\n    custom_request(value)", "parseString"),
        ("from xml.dom.minidom import parseString\nparseString = custom_request", "parseString"),
        (
            "import xml.dom.minidom\nxml.dom.minidom.parseString = custom_request",
            "xml.dom.minidom.parseString",
        ),
        ("import unrelated as ET", "ET.fromstring"),
    ],
)
def test_ambiguous_xml_parser_names_do_not_hide_urls(binding: str, call: str) -> None:
    text = f'{binding}\nENDPOINTS = {{"api": "https://upload.example.invalid/data"}}\n{call}(ENDPOINTS["api"])\n'
    result = NetworkEgressRule().analyze(FileContent("helper.py", "script", text))
    assert "upload.example.invalid" in {item.resource for item in result.capabilities}


@pytest.mark.parametrize(
    ("binding", "call"),
    [
        ("import xml.dom.minidom", "xml.dom.minidom.parseString(URI)"),
        ("from xml.dom.minidom import parseString as parse", "parse(URI)"),
        ("import xml.etree.ElementTree as ET", "ET.fromstring(URI)"),
        ("from xml.etree import ElementTree", "ElementTree.XML(URI)"),
        ("from lxml import etree", "etree.register_namespace('doc', URI)"),
        ("import defusedxml.minidom", "defusedxml.minidom.parseString(URI)"),
        ("from defusedxml.minidom import parseString as parse", "parse(URI)"),
        ("from defusedxml import ElementTree as ET", "ET.fromstring(URI)"),
    ],
)
def test_import_bound_xml_parsers_remain_identifier_consumers(binding: str, call: str) -> None:
    text = f'{binding}\nURI = "https://xml.example.invalid/document"\n{call}\n'
    result = NetworkEgressRule().analyze(FileContent("helper.py", "script", text))
    assert result.capabilities == []


@pytest.mark.parametrize("method", ["findall", "xpath"])
def test_generic_xml_looking_receiver_keeps_namespace_url(method: str) -> None:
    text = (
        'NS = {"doc": "https://upload.example.invalid/data"}\n'
        f'client.{method}("doc:item", namespaces=NS)\n'
    )
    result = NetworkEgressRule().analyze(FileContent("helper.py", "script", text))

    assert "upload.example.invalid" in {item.resource for item in result.capabilities}


@pytest.mark.parametrize("attribute", ["Type", "xmlns:doc"])
def test_generic_set_attribute_receiver_keeps_uri(attribute: str) -> None:
    text = f'URI = "https://upload.example.invalid/data"\nclient.setAttribute("{attribute}", URI)\n'
    result = NetworkEgressRule().analyze(FileContent("helper.py", "script", text))

    assert "upload.example.invalid" in {item.resource for item in result.capabilities}


def test_generic_get_attribute_receiver_keeps_uri() -> None:
    text = (
        'URI = "https://upload.example.invalid/data"\n'
        'if client.getAttribute("Type") in URI:\n'
        "    pass\n"
    )
    result = NetworkEgressRule().analyze(FileContent("helper.py", "script", text))

    assert "upload.example.invalid" in {item.resource for item in result.capabilities}


def test_generic_xml_looking_receiver_cannot_bypass_network_policy(tmp_path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "helper.py").write_text(
        'NS = {"doc": "https://upload.example.invalid/data"}\n'
        'client.findall("doc:item", namespaces=NS)\n',
        encoding="utf-8",
    )

    report = scan_paths(root, [root / "helper.py"])

    assert evaluate_policy(report, {"version": 1, "policy": {"network": {"allow": []}}}).blocked


@pytest.mark.parametrize(
    "factory",
    [
        'document.createElement("Relationship")',
        'document.createElementNS("urn:test", "Relationship")',
    ],
)
def test_proven_xml_factory_result_suppresses_identifier(factory: str) -> None:
    text = (
        "import xml.dom.minidom\n"
        'URI = "https://xml.example.invalid/relationships/comments"\n'
        'document = xml.dom.minidom.parseString("<root/>")\n'
        f"relationship = {factory}\n"
        'relationship.setAttribute("Type", URI)\n'
    )
    result = NetworkEgressRule().analyze(FileContent("helper.py", "script", text))

    assert result.capabilities == []


def test_generic_xml_factory_receiver_keeps_uri() -> None:
    text = (
        'URI = "https://upload.example.invalid/data"\n'
        'relationship = client.createElement("Relationship")\n'
        'relationship.setAttribute("Type", URI)\n'
    )
    result = NetworkEgressRule().analyze(FileContent("helper.py", "script", text))

    assert "upload.example.invalid" in {item.resource for item in result.capabilities}


def test_reassigned_xml_factory_result_keeps_uri() -> None:
    text = (
        "import xml.dom.minidom\n"
        'URI = "https://upload.example.invalid/data"\n'
        'document = xml.dom.minidom.parseString("<root/>")\n'
        'relationship = document.createElement("Relationship")\n'
        "relationship = client\n"
        'relationship.setAttribute("Type", URI)\n'
    )
    result = NetworkEgressRule().analyze(FileContent("helper.py", "script", text))

    assert "upload.example.invalid" in {item.resource for item in result.capabilities}


@pytest.mark.parametrize("format_aware", [False, True])
def test_aliased_network_call_is_blocked_by_network_policy(format_aware: bool) -> None:
    report = scan_repository(FIXTURES / "36-xml-parser-alias", format_aware=format_aware)
    assert {item.resource for item in report.capabilities} == {"upload.example.invalid"}
    assert evaluate_policy(report, {"version": 1, "policy": {"network": {"allow": []}}}).blocked
