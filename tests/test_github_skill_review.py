from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from conftest import FAKE_COMMIT_SHA, ROOT, runner

from skillgate.cli import app
from skillgate.sources import RemoteScanLimits, SourceError, fetch_github_sparse

FIXTURE = ROOT / "fixtures" / "github-review" / "review-demo"
SKILL_PATH = "skills/review-demo"
SOURCE = f"https://github.com/example/skills/tree/{FAKE_COMMIT_SHA}/{SKILL_PATH}"


def mock_skill_repository(monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, str], list[str]]:
    files = {
        f"{SKILL_PATH}/{path.relative_to(FIXTURE).as_posix()}": path.read_text(encoding="utf-8")
        for path in sorted(FIXTURE.rglob("*"))
        if path.is_file() and path.name != "expected-findings.yaml"
    }
    files[f"{SKILL_PATH}/opaque.bin"] = "unsupported binary placeholder"
    files[f"{SKILL_PATH}/.venv/trap.sh"] = "must not be fetched"
    files["skills/other/SKILL.md"] = "must not be fetched"
    fetched: list[str] = []

    def request_json(url: str, **_kwargs) -> dict[str, object]:
        assert url.endswith(f"/git/trees/{FAKE_COMMIT_SHA}?recursive=1")
        return {"tree": [{"path": path, "type": "blob"} for path in sorted(files)]}

    def request_text(url: str, **_kwargs) -> str:
        prefix = f"https://raw.githubusercontent.com/example/skills/{FAKE_COMMIT_SHA}/"
        assert url.startswith(prefix)
        path = url.removeprefix(prefix)
        fetched.append(path)
        return files[path]

    monkeypatch.setattr("skillgate.sources.request_json", request_json)
    monkeypatch.setattr("skillgate.sources.request_text", request_text)
    return files, fetched


@pytest.mark.parametrize("command", [["review", "preinstall"], ["github", "scan"]])
def test_github_skill_review_scans_bundled_files_without_execution(monkeypatch, command) -> None:
    _files, fetched = mock_skill_repository(monkeypatch)
    result = runner.invoke(app, [*command, SOURCE, "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    if command == ["review", "preinstall"]:
        report = payload["source_manifest"]
        findings = [item for group in payload["findings"]["groups"].values() for item in group]
        assert payload["reviewer"]["no_execution"] is True
        assert payload["skills"]["findings"] == []
    else:
        report = payload["scan_report"]
        findings = report["findings"]

    expected = yaml.safe_load((FIXTURE / "expected-findings.yaml").read_text())
    assert {item["rule_id"] for item in findings} == set(expected["findings"])
    assert [item["path"] for item in report["scanned_files"]] == [
        "SKILL.md",
        "references/guide.md",
        "references/unlinked.md",
        "scripts/audit.py",
        "scripts/bootstrap.sh",
    ]
    assert sorted(fetched) == [
        f"{SKILL_PATH}/SKILL.md",
        f"{SKILL_PATH}/references/guide.md",
        f"{SKILL_PATH}/references/unlinked.md",
        f"{SKILL_PATH}/scripts/audit.py",
        f"{SKILL_PATH}/scripts/bootstrap.sh",
    ]


def test_local_and_github_skill_review_select_the_same_bundled_files(
    monkeypatch, tmp_path: Path
) -> None:
    files, _fetched = mock_skill_repository(monkeypatch)
    local_root = tmp_path / "review-demo"
    for remote_path, content in files.items():
        if not remote_path.startswith(f"{SKILL_PATH}/"):
            continue
        path = local_root / remote_path.removeprefix(f"{SKILL_PATH}/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    packets = []
    for source in [str(local_root), SOURCE]:
        result = runner.invoke(app, ["review", "preinstall", source, "--format", "json"])
        assert result.exit_code == 0, result.output
        packets.append(json.loads(result.output))
    local, github = packets
    assert local["source_manifest"]["scanned_files"] == github["source_manifest"]["scanned_files"]
    assert len(local["source_manifest"]["scanned_files"]) == 5
    assert local["capabilities"] == github["capabilities"]
    assert local["findings"] == github["findings"]
    assert local["skills"]["findings"] == github["skills"]["findings"] == []
    assert local["metadata"]["coverage"]["status"] == "incomplete"
    assert local["source_manifest"]["skipped_files"] == [
        {"path": "opaque.bin", "reason": "not_selected"}
    ]

    (local_root / "opaque.bin").unlink()
    del files[f"{SKILL_PATH}/opaque.bin"]
    for source in [str(local_root), SOURCE]:
        result = runner.invoke(
            app, ["review", "preinstall", source, "--require-complete", "--format", "json"]
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["metadata"]["coverage"]["status"] == "complete"


@pytest.mark.parametrize("nested", [False, True])
def test_github_skill_review_keeps_real_directory_name_errors(monkeypatch, nested) -> None:
    files, _fetched = mock_skill_repository(monkeypatch)
    if nested:
        del files[f"{SKILL_PATH}/SKILL.md"]
        files[f"{SKILL_PATH}/nested/SKILL.md"] = (
            "---\nname: wrong-nested\ndescription: A nested skill.\n---\n"
        )
        expected = "directory=nested, name=wrong-nested"
    else:
        files[f"{SKILL_PATH}/SKILL.md"] = files[f"{SKILL_PATH}/SKILL.md"].replace(
            "name: review-demo", "name: wrong-root"
        )
        expected = "directory=review-demo, name=wrong-root"
    result = runner.invoke(app, ["review", "preinstall", SOURCE, "--format", "json"])

    assert result.exit_code == 0, result.output
    findings = json.loads(result.output)["skills"]["findings"]
    assert {item["evidence"] for item in findings if item["rule_id"] == "SKILL004"} == {expected}


def test_github_skill_review_preserves_missing_local_path_errors(monkeypatch) -> None:
    files, _fetched = mock_skill_repository(monkeypatch)
    files[f"{SKILL_PATH}/SKILL.md"] += "Run `scripts/missing.sh`.\n"
    with pytest.raises(SourceError, match="missing referenced scripts"):
        fetch_github_sparse(SOURCE)


def test_github_skill_review_follows_existing_bare_filenames(monkeypatch) -> None:
    files, fetched = mock_skill_repository(monkeypatch)
    files[f"{SKILL_PATH}/SKILL.md"] += "Inspect `standalone.sh`.\n"
    files[f"{SKILL_PATH}/standalone.sh"] = "exit 99\n"
    sparse = fetch_github_sparse(SOURCE)
    try:
        assert f"{SKILL_PATH}/standalone.sh" in fetched
        assert "standalone.sh" in sparse.fetched_paths
    finally:
        sparse.cleanup()


def test_github_skill_review_accounts_for_unsupported_and_excluded_files(monkeypatch) -> None:
    mock_skill_repository(monkeypatch)
    sparse = fetch_github_sparse(SOURCE)
    try:
        assert sparse.manifest["skipped_files"] == [
            {"remote_path": f"{SKILL_PATH}/.venv/trap.sh", "reason": "excluded_path"},
            {"remote_path": f"{SKILL_PATH}/opaque.bin", "reason": "unsupported_file"},
        ]
    finally:
        sparse.cleanup()


def test_github_skill_supporting_files_obey_download_limits(monkeypatch) -> None:
    mock_skill_repository(monkeypatch)
    with pytest.raises(SourceError, match="maximum file count exceeded") as error:
        fetch_github_sparse(SOURCE, limits=RemoteScanLimits(max_files=1))
    assert error.value.manifest["skipped_files"][-1] == {
        "remote_path": f"{SKILL_PATH}/references/guide.md",
        "reason": "max_files_exceeded",
    }


def test_github_preinstall_requires_complete_coverage_only_when_requested(monkeypatch) -> None:
    files, _fetched = mock_skill_repository(monkeypatch)
    result = runner.invoke(
        app, ["review", "preinstall", SOURCE, "--require-complete", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["metadata"]["coverage"]["status"] == "incomplete"
    assert payload["metadata"]["coverage"]["reasons"] == ["unsupported_file"]
    assert payload["source_manifest"]["skipped_file_count"] == 2

    del files[f"{SKILL_PATH}/opaque.bin"]
    result = runner.invoke(
        app, ["review", "preinstall", SOURCE, "--require-complete", "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["metadata"]["coverage"]["status"] == "complete"
    assert payload["findings"]["total"] > 0
    assert payload["source_manifest"]["skipped_file_count"] == 1


@pytest.mark.parametrize("unsupported", [False, True])
def test_github_review_without_supported_files_does_not_claim_no_findings(
    monkeypatch, unsupported: bool
) -> None:
    files, _fetched = mock_skill_repository(monkeypatch)
    files.clear()
    if unsupported:
        files[f"{SKILL_PATH}/plugin.json"] = '{"name":"minimal-plugin"}'
    result = runner.invoke(
        app, ["review", "preinstall", SOURCE, "--require-complete", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["metadata"]["coverage"]["status"] == ("unsupported" if unsupported else "empty")
    assert payload["findings"]["total"] == 0
    assert payload["reviewer"]["decision"] == "review_required"
    assert payload["source"]["revision"] == FAKE_COMMIT_SHA
