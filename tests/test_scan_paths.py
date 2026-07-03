from __future__ import annotations

import os
from pathlib import Path

import pytest

from skillgate.discovery import discover_paths
from skillgate.scan import scan_paths, scan_repository


def test_scan_paths_relative_inputs_resolve_against_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    other = tmp_path / "other"
    root.mkdir()
    other.mkdir()
    (root / "SKILL.md").write_text("Safe\n", encoding="utf-8")
    (other / "SKILL.md").write_text("bash wrong.sh\n", encoding="utf-8")
    old = Path.cwd()
    try:
        os.chdir(other)
        report = scan_paths(root, [Path("SKILL.md")])
    finally:
        os.chdir(old)
    assert [file.path for file in report.scanned_files] == ["SKILL.md"]
    assert report.findings == []


def test_scan_paths_deduplicates_and_sorts_relative_and_absolute(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "b").mkdir(parents=True)
    (root / "a").mkdir()
    first = root / "a" / "one.py"
    second = root / "b" / "two.py"
    first.write_text("print('ok')\n", encoding="utf-8")
    second.write_text("print('ok')\n", encoding="utf-8")
    report = scan_paths(root, [Path("b/two.py"), first, Path("a/one.py"), second])
    assert [file.path for file in report.scanned_files] == ["a/one.py", "b/two.py"]


def test_scan_paths_rejects_invalid_inputs(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "dir").mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("print('x')\n", encoding="utf-8")
    with pytest.raises(ValueError, match="scan root must be an existing directory"):
        scan_paths(tmp_path / "missing", [])
    with pytest.raises(ValueError, match="scan path must be an existing file"):
        scan_paths(root, [Path("missing.py")])
    with pytest.raises(ValueError, match="scan path must be an existing file"):
        scan_paths(root, [Path("dir")])
    with pytest.raises(ValueError, match="scan path resolves outside the scan root"):
        scan_paths(root, [outside])


def test_scan_paths_matches_repository_discovery(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    (root / "SKILL.md").write_text("Run `scripts/run.sh`.\n", encoding="utf-8")
    (scripts / "run.sh").write_text("echo ok\n", encoding="utf-8")
    assert scan_paths(root, discover_paths(root)) == scan_repository(root)
