from __future__ import annotations

import os
from pathlib import Path

import pytest

from skillgate.discovery import discover_paths, discover_preinstall_paths, referenced_scripts
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


def test_discovery_resolves_wrapped_script_references(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    (root / "SKILL.md").write_text("Run scripts/\n  install.sh.\n", encoding="utf-8")
    (scripts / "install.sh").write_text("bash payload.sh\n", encoding="utf-8")

    paths = [path.relative_to(root).as_posix() for path in discover_paths(root)]

    assert paths == ["SKILL.md", "scripts/install.sh"]


def test_discovery_resolves_bare_script_names_only_in_known_directories(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    scripts = root / "scripts"
    other = root / "other"
    scripts.mkdir(parents=True)
    other.mkdir()
    (root / "SKILL.md").write_text("Run install.sh after review.\n", encoding="utf-8")
    (scripts / "install.sh").write_text("echo safe\n", encoding="utf-8")
    (other / "install.sh").write_text("bash payload.sh\n", encoding="utf-8")

    paths = [path.relative_to(root).as_posix() for path in discover_paths(root)]

    assert paths == ["SKILL.md", "scripts/install.sh"]


def test_preinstall_discovery_extends_only_skill_bundles(tmp_path: Path) -> None:
    files = {
        "README.md",
        "tools/outside.py",
        "skills/first/SKILL.md",
        "skills/first/references/notes.md",
        "skills/first/tools/unlinked.PY",
        "skills/first/.venv/trap.py",
        "skills/first/assets/opaque.bin",
        "skills/first/helper.rb",
        "nested/second/SKILL.md",
        "nested/second/scripts/task.ps1",
    }
    for name in files:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Static test input.\n", encoding="utf-8")

    assert [
        path.relative_to(tmp_path).as_posix() for path in discover_preinstall_paths(tmp_path)
    ] == [
        "nested/second/SKILL.md",
        "nested/second/scripts/task.ps1",
        "skills/first/SKILL.md",
        "skills/first/references/notes.md",
        "skills/first/tools/unlinked.PY",
    ]
    assert [path.relative_to(tmp_path).as_posix() for path in discover_paths(tmp_path)] == [
        "nested/second/SKILL.md",
        "skills/first/SKILL.md",
    ]


def test_local_script_references_require_complete_filename_extensions(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ["run.sh", "evals.js", "app.js", "output.ps1"]:
        (scripts / name).write_text("Static input.\n", encoding="utf-8")
    source = tmp_path / "SKILL.md"
    content = (
        "Create scripts/evals.json, scripts/app.js.map, and scripts/output.ps1xml.\n"
        "Run scripts/run.sh.\n"
    )
    assert referenced_scripts(tmp_path, source, content) == [scripts / "run.sh"]


def test_preinstall_discovery_does_not_follow_directory_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "skill"
    root.mkdir()
    (root / "SKILL.md").write_text("Static input.\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "helper.py").write_text("raise SystemExit(99)\n", encoding="utf-8")
    (root / "linked").symlink_to(outside, target_is_directory=True)

    assert discover_preinstall_paths(root) == [root / "SKILL.md"]


def test_preinstall_discovery_rejects_escaping_file_symlinks_before_reading(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "skill"
    root.mkdir()
    (root / "SKILL.md").write_text("Static input.\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("raise SystemExit(99)\n", encoding="utf-8")
    (root / "helper.py").symlink_to(outside)
    read_text = Path.read_text

    def guarded_read(path: Path, *args, **kwargs):
        assert path.resolve() != outside, "Out-of-root content must not be read"
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    with pytest.raises(ValueError):
        discover_preinstall_paths(root)
