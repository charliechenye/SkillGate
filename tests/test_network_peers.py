from __future__ import annotations

import pytest
from conftest import FIXTURES

from skillgate.policy import evaluate_policy
from skillgate.rules.base import FileContent
from skillgate.rules.script_rules import NetworkEgressRule
from skillgate.scan import scan_repository


@pytest.mark.parametrize(
    ("option", "peers"),
    [
        ("--proxy https://proxy.example.invalid", {"proxy.example.invalid"}),
        ("--proxy=https://proxy.example.invalid", {"proxy.example.invalid"}),
        ("-x proxy.example.invalid:8080", {"proxy.example.invalid"}),
        ("--proxy localhost:8080", {"localhost"}),
        ("--proxy [::1]:8080", {"::1"}),
        ("-xhttp://proxy.example.invalid:8080", {"proxy.example.invalid"}),
        ("--preproxy socks5://proxy.example.invalid:1080", {"proxy.example.invalid"}),
        ("--socks5-hostname proxy.example.invalid:1080", {"proxy.example.invalid"}),
        (
            "--connect-to allowed.example.invalid:443:proxy.example.invalid:443",
            {"proxy.example.invalid"},
        ),
        (
            "--connect-to=allowed.example.invalid:443:proxy.example.invalid:443",
            {"proxy.example.invalid"},
        ),
        ("--connect-to allowed.example.invalid:443:[::1]:443", {"::1"}),
        (
            "--resolve allowed.example.invalid:443:192.0.2.20,192.0.2.21",
            {"192.0.2.20", "192.0.2.21"},
        ),
        ("--resolve +allowed.example.invalid:443:[::1]", {"::1"}),
        ('--proxy "$PROXY"', {None}),
        ("--connect-to allowed.example.invalid:443:[HOST]:443", {None}),
        ("--connect-to invalid", {None}),
        ("--resolve invalid", {None}),
    ],
)
def test_curl_reports_request_host_and_declared_peers(option: str, peers: set[str | None]) -> None:
    text = f"curl {option} https://allowed.example.invalid/data"
    result = NetworkEgressRule().analyze(FileContent("helper.sh", "script", text))
    assert {item.resource for item in result.capabilities} == {"allowed.example.invalid", *peers}


@pytest.mark.parametrize("option", ['--proxy ""', "--connect-to allowed.example.invalid:443::443"])
def test_disabled_proxy_or_unchanged_connection_host_adds_no_peer(option: str) -> None:
    result = NetworkEgressRule().analyze(
        FileContent("helper.sh", "script", f"curl {option} https://allowed.example.invalid/data")
    )
    assert {item.resource for item in result.capabilities} == {"allowed.example.invalid"}


@pytest.mark.parametrize("format_aware", [False, True])
def test_network_allowlist_must_cover_connection_peers(format_aware: bool) -> None:
    report = scan_repository(FIXTURES / "40-network-connection-peers", format_aware=format_aware)
    policy = {"version": 1, "policy": {"network": {"allow": ["allowed.example.invalid"]}}}
    assert evaluate_policy(report, policy).blocked
    policy["policy"]["network"]["allow"].extend(["proxy.example.invalid", "192.0.2.20"])
    assert not evaluate_policy(report, policy).blocked
