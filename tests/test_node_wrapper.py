from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import yaml
from conftest import ROOT, clean_test_dir

from tools.build_release_manifest import ASSET_NAMES

WRAPPER = ROOT / "npm" / "bin" / "skillgate.js"
MANIFEST_BYTE_LIMIT = 1024 * 1024


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fake_executable(path: Path, exit_code: int = 0) -> None:
    if os.name == "nt":
        path.write_text(
            f"@echo off\r\necho ARGS:%*\r\nexit /b {exit_code}\r\n",
            encoding="utf-8",
        )
    else:
        path.write_text(
            f'#!/usr/bin/env sh\necho "ARGS:$*"\nexit {exit_code}\n',
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)


def write_manifest(tmp_path: Path, asset: Path, sha256: str | None = None) -> Path:
    manifest = {
        "schema_version": 1,
        "version": "v9.9.9",
        "assets": {
            "test-x64": {
                "name": asset.name,
                "sha256": sha256 or file_sha256(asset),
                "size_bytes": asset.stat().st_size,
                "url": asset.as_uri(),
            }
        },
    }
    manifest_path = tmp_path / "skillgate-release.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def manifest_bytes(
    asset: Path,
    *,
    sha256: str | None = None,
    size_bytes: int | None = None,
    url: str | None = None,
) -> bytes:
    manifest = {
        "schema_version": 1,
        "version": "v9.9.9",
        "assets": {
            "test-x64": {
                "name": asset.name,
                "sha256": sha256 or file_sha256(asset),
                "size_bytes": asset.stat().st_size if size_bytes is None else size_bytes,
                "url": asset.as_uri() if url is None else url,
            }
        },
    }
    return json.dumps(manifest).encode("utf-8")


@contextmanager
def http_server(
    routes: dict[str, tuple[int, bytes, dict[str, str] | None]],
) -> Iterator[ThreadingHTTPServer]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            status, body, headers = routes.get(self.path, (404, b"", {}))
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def wrapper_env(tmp_path: Path, manifest: Path) -> dict[str, str]:
    return {
        **os.environ,
        "SKILLGATE_CACHE_DIR": str(tmp_path / "cache"),
        "SKILLGATE_MANIFEST_PATH": str(manifest),
        "SKILLGATE_PLATFORM_KEY": "test-x64",
    }


def run_wrapper(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["node", str(WRAPPER), *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def wrapper_url_env(tmp_path: Path, manifest_url: str) -> dict[str, str]:
    env = {
        **os.environ,
        "SKILLGATE_CACHE_DIR": str(tmp_path / "cache"),
        "SKILLGATE_MANIFEST_URL": manifest_url,
        "SKILLGATE_PLATFORM_KEY": "test-x64",
    }
    env.pop("SKILLGATE_MANIFEST_PATH", None)
    return env


def test_node_wrapper_downloads_verifies_caches_and_forwards_args() -> None:
    tmp_path = clean_test_dir("node-wrapper-download")
    asset = tmp_path / ("skillgate-test.cmd" if os.name == "nt" else "skillgate-test")
    fake_executable(asset)
    manifest = write_manifest(tmp_path, asset)
    env = wrapper_env(tmp_path, manifest)

    result = run_wrapper(["scan", "."], env)

    assert result.returncode == 0
    assert "ARGS:scan ." in result.stdout
    cached = tmp_path / "cache" / "v9.9.9" / asset.name
    assert cached.is_file()
    current = json.loads((tmp_path / "cache" / "current.json").read_text(encoding="utf-8"))
    assert current["path"] == str(cached)
    assert current["sha256"] == file_sha256(asset)


def test_node_wrapper_strips_npx_separator_before_forwarding_args() -> None:
    tmp_path = clean_test_dir("node-wrapper-separator")
    asset = tmp_path / ("skillgate-test.cmd" if os.name == "nt" else "skillgate-test")
    fake_executable(asset)
    manifest = write_manifest(tmp_path, asset)

    result = run_wrapper(["--", "scan", "."], wrapper_env(tmp_path, manifest))

    assert result.returncode == 0
    assert "ARGS:scan ." in result.stdout
    assert "ARGS:-- scan ." not in result.stdout


def test_node_wrapper_fails_closed_on_checksum_mismatch() -> None:
    tmp_path = clean_test_dir("node-wrapper-checksum")
    asset = tmp_path / ("skillgate-test.cmd" if os.name == "nt" else "skillgate-test")
    fake_executable(asset)
    manifest = write_manifest(tmp_path, asset, sha256="0" * 64)

    result = run_wrapper(["scan", "."], wrapper_env(tmp_path, manifest))

    assert result.returncode == 1
    assert "checksum mismatch" in result.stderr


def test_node_wrapper_rejects_oversized_manifest_content_length() -> None:
    tmp_path = clean_test_dir("node-wrapper-manifest-limit")
    routes = {
        "/skillgate-release.json": (
            200,
            b"{}",
            {"Content-Length": str(MANIFEST_BYTE_LIMIT + 1)},
        )
    }
    with http_server(routes) as server:
        env = {
            **wrapper_url_env(
                tmp_path,
                f"http://127.0.0.1:{server.server_port}/skillgate-release.json",
            ),
            "SKILLGATE_ALLOW_INSECURE_HTTP_FOR_TESTS": "1",
        }

        result = run_wrapper(["scan", "."], env)

    assert result.returncode == 1
    assert "exceeds limit" in result.stderr
    assert "Content-Length" in result.stderr


def test_node_wrapper_rejects_binary_stream_larger_than_manifest_size() -> None:
    tmp_path = clean_test_dir("node-wrapper-binary-limit")
    asset = tmp_path / ("skillgate-test.cmd" if os.name == "nt" else "skillgate-test")
    fake_executable(asset)
    routes: dict[str, tuple[int, bytes, dict[str, str] | None]] = {}
    with http_server(routes) as server:
        body = asset.read_bytes() + b"\nextra bytes"
        asset_url = f"http://127.0.0.1:{server.server_port}/asset"
        routes["/asset"] = (200, body, None)
        manifest = tmp_path / "skillgate-release.json"
        manifest.write_bytes(manifest_bytes(asset, url=asset_url))
        env = {
            **wrapper_env(tmp_path, manifest),
            "SKILLGATE_ALLOW_INSECURE_HTTP_FOR_TESTS": "1",
        }

        result = run_wrapper(["scan", "."], env)

    assert result.returncode == 1
    assert "exceeds limit" in result.stderr


def test_node_wrapper_rejects_cached_binary_checksum_mismatch() -> None:
    tmp_path = clean_test_dir("node-wrapper-cache-tamper")
    asset = tmp_path / ("skillgate-test.cmd" if os.name == "nt" else "skillgate-test")
    fake_executable(asset)
    manifest = write_manifest(tmp_path, asset)
    env = wrapper_env(tmp_path, manifest)
    first = run_wrapper(["rules", "list"], env)
    assert first.returncode == 0
    cached = tmp_path / "cache" / "v9.9.9" / asset.name
    cached.write_text("tampered cached binary", encoding="utf-8")

    result = run_wrapper(["scan", "."], env)

    assert result.returncode == 1
    assert "cached SkillGate checksum mismatch" in result.stderr


def test_node_wrapper_requires_test_flag_for_http_downloads() -> None:
    tmp_path = clean_test_dir("node-wrapper-http-flag")
    asset = tmp_path / ("skillgate-test.cmd" if os.name == "nt" else "skillgate-test")
    fake_executable(asset)
    routes: dict[str, tuple[int, bytes, dict[str, str] | None]] = {}
    with http_server(routes) as server:
        base_url = f"http://127.0.0.1:{server.server_port}"
        manifest_url = f"{base_url}/skillgate-release.json"
        routes["/skillgate-release.json"] = (
            200,
            manifest_bytes(asset, url=f"{base_url}/asset"),
            None,
        )
        routes["/asset"] = (
            200,
            asset.read_bytes(),
            {"Content-Length": str(asset.stat().st_size)},
        )
        insecure_result = run_wrapper(["scan", "."], wrapper_url_env(tmp_path, manifest_url))
        allowed_result = run_wrapper(
            ["scan", "."],
            {
                **wrapper_url_env(tmp_path, manifest_url),
                "SKILLGATE_ALLOW_INSECURE_HTTP_FOR_TESTS": "1",
            },
        )

    assert insecure_result.returncode == 1
    assert "insecure HTTP download requires SKILLGATE_ALLOW_INSECURE_HTTP_FOR_TESTS=1" in (
        insecure_result.stderr
    )
    assert allowed_result.returncode == 0
    assert "ARGS:scan ." in allowed_result.stdout


def test_node_wrapper_no_update_check_uses_cached_binary() -> None:
    tmp_path = clean_test_dir("node-wrapper-no-update")
    asset = tmp_path / ("skillgate-test.cmd" if os.name == "nt" else "skillgate-test")
    fake_executable(asset)
    manifest = write_manifest(tmp_path, asset)
    env = wrapper_env(tmp_path, manifest)
    first = run_wrapper(["rules", "list"], env)
    assert first.returncode == 0

    no_update_env = {
        **env,
        "SKILLGATE_NO_UPDATE_CHECK": "1",
        "SKILLGATE_MANIFEST_PATH": str(tmp_path / "missing.json"),
    }
    second = run_wrapper(["scan", "."], no_update_env)

    assert second.returncode == 0
    assert "ARGS:scan ." in second.stdout


def test_node_wrapper_reports_unsupported_platform() -> None:
    tmp_path = clean_test_dir("node-wrapper-unsupported")
    asset = tmp_path / ("skillgate-test.cmd" if os.name == "nt" else "skillgate-test")
    fake_executable(asset)
    manifest = write_manifest(tmp_path, asset)
    env = {**wrapper_env(tmp_path, manifest), "SKILLGATE_PLATFORM_KEY": "plan9-x64"}

    result = run_wrapper(["scan", "."], env)

    assert result.returncode == 1
    assert "unsupported platform" in result.stderr


def test_release_manifest_builder_and_workflow_use_stable_assets() -> None:
    tmp_path = clean_test_dir("node-wrapper-manifest")
    asset_dir = tmp_path / "assets"
    asset_dir.mkdir()
    for name in ASSET_NAMES.values():
        (asset_dir / name).write_bytes(f"asset:{name}".encode())
    output = tmp_path / "skillgate-release.json"

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "build_release_manifest.py"),
            "--asset-dir",
            str(asset_dir),
            "--version",
            "v9.9.9",
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["version"] == "v9.9.9"
    assert set(manifest["assets"]) == set(ASSET_NAMES)
    for platform, asset in manifest["assets"].items():
        assert asset["name"] == ASSET_NAMES[platform]
        assert "v9.9.9" not in asset["name"]
        assert len(asset["sha256"]) == 64
        assert asset["size_bytes"] > 0

    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release-binaries.yml").read_text(encoding="utf-8")
    )
    assert workflow["env"]["FORCE_JAVASCRIPT_ACTIONS_TO_NODE24"] is True
    assert workflow["jobs"]["resolve-tag"]["outputs"]["release_tag"] == (
        "${{ steps.tag.outputs.value }}"
    )
    assert workflow["jobs"]["build"]["needs"] == "resolve-tag"
    assert workflow["jobs"]["build"]["steps"][0]["with"]["ref"] == (
        "${{ needs.resolve-tag.outputs.release_tag }}"
    )
    assert workflow["jobs"]["publish"]["needs"] == ["resolve-tag", "build"]
    assert workflow["jobs"]["publish"]["steps"][0]["with"]["ref"] == (
        "${{ needs.resolve-tag.outputs.release_tag }}"
    )
    build_steps = {step.get("name"): step for step in workflow["jobs"]["build"]["steps"]}
    smoke_step = build_steps["Smoke test standalone binary"]
    assert "--version" in smoke_step["run"]
    assert "rules', 'list" in smoke_step["run"]
    assert "review', 'preinstall" in smoke_step["run"]
    upload_step = build_steps["Upload build artifact"]
    assert upload_step["uses"] == "actions/upload-artifact@v7"
    assert upload_step["with"]["archive"] is True
    publish_steps = workflow["jobs"]["publish"]["steps"]
    download_step = next(
        step for step in publish_steps if step.get("uses") == "actions/download-artifact@v8"
    )
    assert download_step["with"]["merge-multiple"] is True
    assert download_step["with"]["skip-decompress"] is False
    assert download_step["with"]["digest-mismatch"] == "error"
    matrix = workflow["jobs"]["build"]["strategy"]["matrix"]["include"]
    assert {item["asset"] for item in matrix} == set(ASSET_NAMES.values())
    runners = {item["platform"]: item["runner"] for item in matrix}
    assert runners["darwin-x64"] == "macos-15-intel"
    assert runners["darwin-arm64"] == "macos-14"
    workflow_text = (ROOT / ".github" / "workflows" / "release-binaries.yml").read_text(
        encoding="utf-8"
    )
    assert "macos-13" not in workflow_text
    assert "skillgate-release.json" in workflow_text
    assert '--version "${{ needs.resolve-tag.outputs.release_tag }}"' in workflow_text
    assert 'gh release upload "${{ needs.resolve-tag.outputs.release_tag }}"' in workflow_text
    assert "actions/upload-artifact@v7" in workflow_text
    assert "actions/download-artifact@v8" in workflow_text
    assert "actions/upload-artifact@v4" not in workflow_text
    assert "actions/upload-artifact@v6" not in workflow_text
    assert "actions/download-artifact@v4" not in workflow_text
    assert "actions/download-artifact@v7" not in workflow_text
    assert "ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION" not in workflow_text
    website_step = next(
        step for step in publish_steps if step.get("name") == "Notify Personal Website of Release"
    )
    assert website_step["continue-on-error"] is True


def test_package_json_exposes_github_npx_launcher_without_npm_claim() -> None:
    package_json = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    docs = (ROOT / "docs" / "node-wrapper.md").read_text(encoding="utf-8")

    assert package_json["private"] is True
    assert package_json["bin"] == {"skillgate": "npm/bin/skillgate.js"}
    assert "npx --yes github:charliechenye/SkillGate#v0 -- scan ." in readme
    assert "npx --yes github:charliechenye/SkillGate#v0 -- scan ." in docs
    assert "Bare `npx skillgate scan .`" in docs
    assert "Bare `npx skillgate scan .` remains future work" in readme
    assert "```bash\nnpx skillgate scan ." not in readme
