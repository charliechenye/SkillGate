from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ASSET_NAMES = {
    "win32-x64": "skillgate-win32-x64.exe",
    "darwin-arm64": "skillgate-darwin-arm64",
    "darwin-x64": "skillgate-darwin-x64",
    "linux-arm64": "skillgate-linux-arm64",
    "linux-x64": "skillgate-linux-x64",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(asset_dir: Path, version: str) -> dict[str, object]:
    assets = {}
    for platform, name in sorted(ASSET_NAMES.items()):
        path = asset_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"missing release asset: {path}")
        assets[platform] = {
            "name": name,
            "sha256": sha256(path),
            "size_bytes": path.stat().st_size,
        }
    return {
        "schema_version": 1,
        "version": version,
        "assets": assets,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the SkillGate release manifest.")
    parser.add_argument("--asset-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_manifest(args.asset_dir, args.version)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
