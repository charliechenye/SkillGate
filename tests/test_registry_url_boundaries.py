from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import runner

from skillgate.cli import app
from skillgate.mcp_registry import (
    RegistryMetadataError,
    fetch_registry_index,
    host_is_local_or_private,
)


@pytest.mark.parametrize(
    "url",
    [
        "https://[HOST]/mcp",
        "https://[::1/mcp",
        "https://api.example.invalid:invalid/mcp",
        "https://{HOST}/mcp",
    ],
)
@pytest.mark.parametrize("surface", ["remote", "app"])
@pytest.mark.parametrize("command", ["scan", "registry", "preinstall"])
def test_malformed_registry_urls_produce_reviewable_json(
    tmp_path: Path, url: str, surface: str, command: str
) -> None:
    if surface == "remote":
        metadata = {
            "name": "io.example.audit",
            "remotes": [{"type": "streamable-http", "url": url}],
        }
    else:
        metadata = {"mcpApps": {"description": "registerTool", "url": url}}
    source = tmp_path / "mcp-registry.json"
    source.write_text(json.dumps(metadata))
    args = {
        "scan": ["scan", str(tmp_path)],
        "registry": ["mcp", "registry", "scan", str(source)],
        "preinstall": ["review", "preinstall", str(source)],
    }[command]
    result = runner.invoke(app, [*args, "--format", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    if command == "preinstall":
        assert data["reviewer"]["decision"] == "review_required"
    else:
        if surface == "remote":
            assert any(
                item["details"].get("endpoint_status") == "unknown" for item in data["capabilities"]
            )
        else:
            capability = next(
                item for item in data["capabilities"] if item["resource"] == "mcp_app_metadata"
            )
            assert capability["details"]["origins"] == []
            assert capability["details"]["unknown_origin_count"] == 1


@pytest.mark.parametrize(
    ("url", "private"),
    [
        ("http://localhost:8765/mcp", True),
        ("http://[::1]:8765/mcp", True),
        ("https://public.example.invalid/mcp", False),
        ("https://[HOST]/mcp", False),
    ],
)
def test_registry_host_classification_is_safe(url: str, private: bool) -> None:
    assert host_is_local_or_private(url) is private


@pytest.mark.parametrize(
    "url",
    [
        "https://[HOST]/servers",
        "https://{HOST}/servers",
        "https://api.example.invalid:invalid/servers",
        "ftp://registry.example.invalid/servers",
    ],
)
def test_invalid_registry_index_url_reports_input_error(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    def unexpected_request(*_args, **_kwargs):
        pytest.fail("Invalid registry URLs must fail before a network request")

    monkeypatch.setattr("urllib.request.urlopen", unexpected_request)
    with pytest.raises(RegistryMetadataError, match="invalid registry URL"):
        fetch_registry_index(url)


def test_valid_registry_index_url_is_fetched(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"servers": []}'

    requested: list[tuple[object, int]] = []

    def fake_urlopen(request: object, timeout: int) -> Response:
        requested.append((request, timeout))
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert fetch_registry_index("https://registry.example.invalid/servers") == {"servers": []}
    assert len(requested) == 1
