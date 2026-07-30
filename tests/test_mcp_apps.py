from __future__ import annotations

import base64
import json
import socket
import subprocess
import urllib.request
import webbrowser
from pathlib import Path

import pytest

from skillgate.mcp_apps import (
    INLINE_RESOURCE_MAX_BYTES,
    detect_bridge_markers,
    inventory_mcp_apps,
)
from skillgate.mcp_registry import compare_registry_metadata
from skillgate.scan import scan_repository


def test_modern_metadata_uses_spec_default_visibility_and_collects_surfaces() -> None:
    inventory = inventory_mcp_apps(
        {
            "resources": [
                {
                    "uri": "ui://widget/home.html",
                    "mimeType": "text/html;profile=mcp-app",
                    "_meta": {
                        "ui": {
                            "resourceUri": "ui://widget/home.html",
                            "mimeType": "text/html;profile=mcp-app",
                            "csp": {
                                "connect_domains": ["https://api.example.com"],
                                "resource_domains": ["https://cdn.example.com"],
                                "frame_domains": ["https://frame.example.com"],
                                "base_uri": ["https://app.example.com"],
                            },
                            "permissions": [
                                "camera",
                                {"name": "clipboardWrite"},
                            ],
                            "capabilities": ["responsive", "darkMode"],
                            "appCallableTools": [
                                {"name": "summarize", "appCallable": True},
                                {"name": "register_later", "dynamic": True},
                            ],
                        }
                    },
                }
            ]
        },
        scope="registry:example",
    )

    assert len(inventory.resources) == 1
    resource = inventory.resources[0]
    assert resource.resource_uri == "ui://widget/home.html"
    assert resource.declared_visibility is None
    assert resource.effective_visibility == ("app", "model")
    assert resource.visibility_source == "spec_default"
    assert [(item.kind, item.origin) for item in resource.origins] == [
        ("base_uri", "https://app.example.com"),
        ("connect", "https://api.example.com"),
        ("frame", "https://frame.example.com"),
        ("resource", "https://cdn.example.com"),
    ]
    assert [item.name for item in resource.permissions] == ["camera", "clipboardWrite"]
    assert resource.app_capabilities == ("darkMode", "responsive")
    assert [(item.name, item.surface, item.privileged) for item in resource.tool_surfaces] == [
        ("register_later", "dynamic_tool_surface", True),
        ("summarize", "app_callable_tool", True),
    ]


def test_legacy_metadata_keeps_omitted_visibility_unknown() -> None:
    inventory = inventory_mcp_apps(
        {
            "contents": [
                {
                    "mimeType": "text/html;profile=mcp-app",
                    "_meta": {"ui/resourceUri": "ui://legacy/widget.html"},
                }
            ]
        }
    )

    assert len(inventory.resources) == 1
    resource = inventory.resources[0]
    assert resource.declared_visibility is None
    assert resource.effective_visibility == ()
    assert resource.visibility_source == "unknown"


def test_declared_visibility_overrides_modern_default() -> None:
    inventory = inventory_mcp_apps(
        {
            "_meta": {
                "ui": {
                    "resourceUri": "ui://widget/panel.html",
                    "mimeType": "text/html;profile=mcp-app",
                    "visibility": ["app"],
                }
            }
        }
    )

    assert inventory.resources[0].declared_visibility == ("app",)
    assert inventory.resources[0].effective_visibility == ("app",)
    assert inventory.resources[0].visibility_source == "declared"


def test_secret_bearing_and_malformed_values_become_unknown_declarations() -> None:
    inventory = inventory_mcp_apps(
        {
            "_meta": {
                "ui": {
                    "resourceUri": "TOKEN=literal-secret",
                    "mimeType": "text/html;profile=mcp-app",
                }
            },
            "other": {
                "_meta": {
                    "ui": {
                        "resourceUri": "plain-widget-name",
                        "mimeType": "text/html;profile=mcp-app",
                    }
                }
            },
        }
    )

    assert not inventory.resources
    assert [item.reason for item in inventory.unknown_declarations] == [
        "invalid_or_redacted_resource_uri",
        "invalid_or_redacted_resource_uri",
    ]
    assert "literal-secret" not in repr(inventory)


def test_conflicting_resource_uri_keys_are_retained_as_unknown() -> None:
    inventory = inventory_mcp_apps(
        {
            "_meta": {
                "ui": {
                    "resourceUri": "ui://widget/a.html",
                    "resource_uri": "ui://widget/b.html",
                    "mimeType": "text/html;profile=mcp-app",
                }
            }
        }
    )

    assert inventory.resources[0].resource_uri == "ui://widget/a.html"
    assert [item.reason for item in inventory.unknown_declarations] == [
        "conflicting_resource_uri_keys"
    ]


def test_inline_text_and_base64_are_bounded_and_hashed() -> None:
    html = "<script>callServerTool('search')</script>"
    inventory = inventory_mcp_apps(
        {
            "_meta": {
                "ui": {
                    "resourceUri": "ui://widget/home.html",
                    "mimeType": "text/html;profile=mcp-app",
                    "text": html,
                    "blob": base64.b64encode(b"registerAppTool('x')").decode(),
                }
            }
        }
    )

    assert [(item.kind, item.text, item.skipped_reason) for item in inventory.inline_resources] == [
        ("blob", "registerAppTool('x')", None),
        ("text", html, None),
    ]
    assert all(item.sha256 for item in inventory.inline_resources)


def test_invalid_base64_is_unknown_not_exception() -> None:
    inventory = inventory_mcp_apps(
        {
            "_meta": {
                "ui": {
                    "resourceUri": "ui://widget/home.html",
                    "mimeType": "text/html;profile=mcp-app",
                    "blob": "not valid base64 !!",
                }
            }
        }
    )

    assert [item.reason for item in inventory.unknown_declarations] == ["invalid_inline_base64"]


def test_inline_resource_limits_skip_content_without_dropping_digest() -> None:
    oversized = "x" * (INLINE_RESOURCE_MAX_BYTES + 1)
    inventory = inventory_mcp_apps(
        {
            "_meta": {
                "ui": {
                    "resourceUri": "ui://widget/too-large.html",
                    "mimeType": "text/html;profile=mcp-app",
                    "text": oversized,
                }
            }
        }
    )

    inline = inventory.inline_resources[0]
    assert inline.text is None
    assert inline.size_bytes == INLINE_RESOURCE_MAX_BYTES + 1
    assert inline.sha256
    assert inline.skipped_reason == "inline_resource_too_large"


def test_inline_aggregate_limit_is_deterministic() -> None:
    exact = "x" * INLINE_RESOURCE_MAX_BYTES
    records = [
        {
            "_meta": {
                "ui": {
                    "resourceUri": f"ui://widget/{index}.html",
                    "mimeType": "text/html;profile=mcp-app",
                    "text": exact,
                }
            }
        }
        for index in range(6)
    ]
    inventory = inventory_mcp_apps({"resources": records})

    skipped = [item for item in inventory.inline_resources if item.skipped_reason]
    assert len(inventory.inline_resources) == 6
    assert [item.resource_uri for item in skipped] == ["ui://widget/5.html"]
    assert skipped[0].skipped_reason == "inline_resource_total_limit_exceeded"


def test_bridge_detection_uses_exact_markers_and_contextual_post_message() -> None:
    assert detect_bridge_markers("window.callServerTool('x'); tools/call") == (
        "callServerTool",
        "tools/call",
    )
    assert detect_bridge_markers("window.postMessage({type: 'mcp'});") == ("postMessage",)
    assert detect_bridge_markers("window.postMessage({type: 'analytics'});") == ()


def test_mcp_config_exposes_declarative_app_capabilities_without_sg003(
    tmp_path: Path,
) -> None:
    config = {
        "mcpServers": {
            "example": {
                "command": "node",
                "_meta": {
                    "ui": {
                        "resourceUri": "ui://widget/home.html",
                        "mimeType": "text/html;profile=mcp-app",
                        "csp": {"connect_domains": ["https://api.example.com"]},
                        "permissions": ["camera"],
                        "appCallableTools": [{"name": "search", "appCallable": True}],
                    }
                },
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")

    report = scan_repository(tmp_path)

    types = {capability.type for capability in report.capabilities}
    assert {
        "mcp_app_resource",
        "mcp_app_origin",
        "mcp_app_permission",
        "mcp_app_tool_surface",
    } <= types
    assert [finding.rule_id for finding in report.findings] == ["SG009", "SG011", "SG011"]
    assert {finding.capability for finding in report.findings if finding.rule_id == "SG011"} == {
        "mcp_app_permission",
        "mcp_app_tool_surface",
    }
    assert not [finding for finding in report.findings if finding.rule_id == "SG003"]
    server = next(
        capability for capability in report.capabilities if capability.type == "mcp_server"
    )
    assert server.details["mcp_apps"]["resources"][0]["resource_uri"] == "ui://widget/home.html"


def test_legacy_registry_app_metadata_is_capability_only_without_privileged_surface(
    tmp_path: Path,
) -> None:
    registry = {
        "server": {
            "name": "io.example.legacy-app",
            "version": "1.0.0",
            "resources": [
                {
                    "mimeType": "text/html;profile=mcp-app",
                    "_meta": {"ui/resourceUri": "ui://legacy/index.html"},
                }
            ],
        }
    }
    (tmp_path / "server.json").write_text(json.dumps(registry), encoding="utf-8")

    report = scan_repository(tmp_path)

    assert any(capability.type == "mcp_app_resource" for capability in report.capabilities)
    assert not [finding for finding in report.findings if finding.rule_id == "SG011"]
    registry_server = next(
        capability for capability in report.capabilities if capability.type == "mcp_registry_server"
    )
    assert registry_server.details["mcp_apps"]["resources"][0]["visibility_source"] == "unknown"


def test_malformed_app_metadata_produces_unknown_capability_not_finding(tmp_path: Path) -> None:
    (tmp_path / "server.json").write_text(
        json.dumps(
            {
                "server": {
                    "name": "io.example.bad-app",
                    "version": "1.0.0",
                    "_meta": {
                        "ui": {
                            "resourceUri": "TOKEN=literal-secret",
                            "mimeType": "text/html;profile=mcp-app",
                        }
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    unknown = [
        capability
        for capability in report.capabilities
        if capability.type == "mcp_app_unknown_declaration"
    ]
    assert unknown
    assert not [finding for finding in report.findings if finding.rule_id == "SG011"]
    assert "literal-secret" not in repr(report)


def test_registry_comparison_includes_normalized_app_surface_drift(tmp_path: Path) -> None:
    local = {
        "server": {
            "name": "io.example.app-drift",
            "version": "1.0.0",
            "_meta": {
                "ui": {
                    "resourceUri": "ui://widget/home.html",
                    "mimeType": "text/html;profile=mcp-app",
                }
            },
        }
    }
    remote = json.loads(json.dumps(local))
    remote["server"]["_meta"]["ui"]["permissions"] = ["camera"]
    local_dir = tmp_path / "local"
    local_dir.mkdir()
    (local_dir / "server.json").write_text(json.dumps(local), encoding="utf-8")
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps({"servers": [remote]}), encoding="utf-8")

    report = compare_registry_metadata(local_dir, "io.example.app-drift", str(registry_path))

    assert "mcp_apps" in {item["field"] for item in report.summary["registry_drift"]}
    assert any("mcp_apps" in (finding.evidence or "") for finding in report.findings)


def test_local_app_assets_are_discovered_and_bridges_are_capabilities(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "example": {
                        "command": "node",
                        "_meta": {
                            "ui": {
                                "resourceUri": "ui://app/index.html",
                                "mimeType": "text/html;profile=mcp-app",
                            }
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.html").write_text(
        '<link rel="stylesheet" href="style.css"><script src="app.js"></script>',
        encoding="utf-8",
    )
    (app / "style.css").write_text("@import 'theme.css';", encoding="utf-8")
    (app / "theme.css").write_text("body { color: black; }", encoding="utf-8")
    (app / "app.js").write_text("window.callServerTool('search');", encoding="utf-8")

    report = scan_repository(tmp_path)

    assert [file.path for file in report.scanned_files] == [
        ".mcp.json",
        "app/app.js",
        "app/index.html",
        "app/style.css",
        "app/theme.css",
    ]
    asset_paths = {
        capability.resource
        for capability in report.capabilities
        if capability.type == "mcp_app_asset" and not capability.details.get("skipped_reason")
    }
    assert asset_paths == {
        "app/app.js",
        "app/index.html",
        "app/style.css",
        "app/theme.css",
    }
    bridges = [
        capability
        for capability in report.capabilities
        if capability.type == "mcp_app_host_bridge"
    ]
    assert [(item.details["path"], item.details["marker"]) for item in bridges] == [
        ("app/app.js", "callServerTool")
    ]


def test_generic_web_project_does_not_enter_mcp_apps_adapter(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text(
        "<script src='app.js'></script><script>callServerTool('x')</script>",
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_text("registerAppTool('x')", encoding="utf-8")

    report = scan_repository(tmp_path)

    assert report.scanned_files == []
    assert not [
        capability for capability in report.capabilities if capability.type.startswith("mcp_app")
    ]


def test_local_asset_skips_traversal_missing_excluded_and_oversized(
    tmp_path: Path,
) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "example": {
                        "command": "node",
                        "_meta": {
                            "ui": {
                                "resourceUri": "ui://app/index.html",
                                "mimeType": "text/html;profile=mcp-app",
                            }
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    app = tmp_path / "app"
    app.mkdir()
    (tmp_path / "node_modules").mkdir()
    (app / "index.html").write_text(
        "\n".join(
            [
                '<script src="missing.js"></script>',
                '<script src="../../outside.js"></script>',
                '<script src="../node_modules/excluded.js"></script>',
                '<script src="large.js"></script>',
            ]
        ),
        encoding="utf-8",
    )
    (app / "large.js").write_text("x" * (1_048_576 + 1), encoding="utf-8")

    report = scan_repository(tmp_path)
    skipped = {
        capability.resource: capability.details["skipped_reason"]
        for capability in report.capabilities
        if capability.type == "mcp_app_asset" and capability.details.get("skipped_reason")
    }

    assert skipped == {
        "../../outside.js": "outside_scan_root",
        "../node_modules/excluded.js": "excluded_path",
        "app/large.js": "asset_too_large",
        "app/missing.js": "missing_reference",
    }


def test_local_app_scan_does_not_use_network_browser_or_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "example": {
                        "command": "node",
                        "_meta": {
                            "ui": {
                                "resourceUri": "ui://app/index.html",
                                "mimeType": "text/html;profile=mcp-app",
                                "csp": {"connect_domains": ["https://api.example.com"]},
                            }
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.html").write_text("ui/initialize", encoding="utf-8")

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("local MCP Apps scan must not call external entry points")

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(webbrowser, "open", fail)

    report = scan_repository(tmp_path)

    assert any(capability.type == "mcp_app_asset" for capability in report.capabilities)
    assert any(capability.type == "mcp_app_host_bridge" for capability in report.capabilities)
