from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import yaml
from conftest import ROOT, clean_test_dir

from tools.build_release_manifest import ASSET_NAMES

WRAPPER = ROOT / "npm" / "bin" / "skillgate.js"


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
    matrix = workflow["jobs"]["build"]["strategy"]["matrix"]["include"]
    assert {item["asset"] for item in matrix} == set(ASSET_NAMES.values())
    assert "skillgate-release.json" in (
        ROOT / ".github" / "workflows" / "release-binaries.yml"
    ).read_text(encoding="utf-8")


def test_package_json_exposes_github_npx_launcher_without_npm_claim() -> None:
    package_json = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    docs = (ROOT / "docs" / "node-wrapper.md").read_text(encoding="utf-8")

    assert package_json["bin"] == {"skillgate": "npm/bin/skillgate.js"}
    assert "npx --yes github:charliechenye/SkillGate#v0 -- scan ." in readme
    assert "npx --yes github:charliechenye/SkillGate#v0 -- scan ." in docs
    assert "Bare `npx skillgate scan .`" in docs
    assert "Bare `npx skillgate scan .` remains future work" in readme
    assert "```bash\nnpx skillgate scan ." not in readme
