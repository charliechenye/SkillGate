from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from typer.testing import CliRunner

from skillgate.cli import app

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "benchmark"


@dataclass(frozen=True)
class SnapshotCase:
    name: str
    args: tuple[str, ...]


SNAPSHOT_CASES = (
    SnapshotCase(
        "scan_remote_download.txt",
        ("scan", str(FIXTURES / "05-remote-download-execute")),
    ),
    SnapshotCase(
        "scan_remote_download.json",
        ("scan", str(FIXTURES / "05-remote-download-execute"), "--format", "json"),
    ),
    SnapshotCase(
        "scan_remote_download.sarif",
        ("scan", str(FIXTURES / "05-remote-download-execute"), "--format", "sarif"),
    ),
    SnapshotCase("rules_list.txt", ("rules", "list")),
    SnapshotCase("rules_list.json", ("rules", "list", "--format", "json")),
    SnapshotCase("explain_sg004.txt", ("explain", "SG004")),
    SnapshotCase("explain_sg004.json", ("explain", "SG004", "--format", "json")),
)


def snapshot_output(case: SnapshotCase) -> str:
    result = CliRunner().invoke(app, list(case.args))
    if result.exit_code != 0:
        raise RuntimeError(f"Snapshot command failed for {case.name}: {result.output}")
    return result.output
