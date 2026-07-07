from __future__ import annotations

import argparse
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "fixtures" / "mcpb-demo" / "reviewable-node"
FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def source_files(source: Path) -> list[Path]:
    return sorted(path for path in source.rglob("*") if path.is_file())


def build_demo_mcpb(source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        for path in source_files(source):
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(relative)
            info.date_time = FIXED_TIME
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, path.read_bytes())


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the deterministic SkillGate MCPB demo.")
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help="MCPB source directory to package.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "test-outputs" / "reviewable-node.mcpb",
        help="Output .mcpb file.",
    )
    args = parser.parse_args()
    build_demo_mcpb(args.source, args.output)
    print(args.output)


if __name__ == "__main__":
    main()
