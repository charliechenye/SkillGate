from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_DIR = ROOT / "tests" / "snapshots"
DEFAULT_ARTIFACTS = ROOT / "test-outputs" / "snapshots"

sys.path.insert(0, str(ROOT))

from tests.snapshot_cases import SNAPSHOT_CASES, snapshot_output  # noqa: E402


def diff_text(name: str, expected: str, actual: str) -> str:
    return "".join(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=f"tests/snapshots/{name}",
            tofile=f"actual/{name}",
        )
    )


def write_artifacts(artifacts: Path, name: str, actual: str, diff: str) -> None:
    output = artifacts / name
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(actual, encoding="utf-8")
    diff_output = artifacts / f"{name}.diff"
    diff_output.parent.mkdir(parents=True, exist_ok=True)
    diff_output.write_text(diff, encoding="utf-8")


def check_snapshots(artifacts: Path) -> int:
    mismatches = []
    for case in SNAPSHOT_CASES:
        snapshot = SNAPSHOT_DIR / case.name
        expected = snapshot.read_text(encoding="utf-8")
        actual = snapshot_output(case)
        if actual != expected:
            diff = diff_text(case.name, expected, actual)
            write_artifacts(artifacts, case.name, actual, diff)
            mismatches.append(case.name)
    if mismatches:
        print("Snapshot mismatches:")
        for name in mismatches:
            print(f"- {name}")
        print(f"\nReview actual output and diffs under {artifacts}")
        return 1
    print("Snapshots match.")
    return 0


def accept_snapshots() -> int:
    for case in SNAPSHOT_CASES:
        snapshot = SNAPSHOT_DIR / case.name
        snapshot.write_text(snapshot_output(case), encoding="utf-8")
        print(f"Updated {snapshot.relative_to(ROOT).as_posix()}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check or update SkillGate golden snapshots.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Check snapshots without updating them.")
    mode.add_argument("--accept", action="store_true", help="Update tracked snapshot files.")
    parser.add_argument(
        "--artifacts",
        type=Path,
        default=DEFAULT_ARTIFACTS,
        help="Directory for actual outputs and diffs when --check finds mismatches.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.accept:
        return accept_snapshots()
    return check_snapshots(args.artifacts)


if __name__ == "__main__":
    raise SystemExit(main())
