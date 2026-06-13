from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / "docs" / "assets" / "repo_image.png"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MIN_WIDTH = 1200
MIN_HEIGHT = 600
MIN_RATIO = 1.8
MAX_RATIO = 2.2


def main() -> int:
    if not IMAGE.exists():
        sys.stderr.write(f"Missing social preview image: {IMAGE}\n")
        return 1
    data = IMAGE.read_bytes()
    if len(data) < 24 or data[:8] != PNG_SIGNATURE:
        sys.stderr.write(f"Social preview is not a valid PNG: {IMAGE}\n")
        return 1
    width, height = struct.unpack(">II", data[16:24])
    ratio = width / height
    if width < MIN_WIDTH or height < MIN_HEIGHT or not (MIN_RATIO <= ratio <= MAX_RATIO):
        sys.stderr.write(
            "Social preview dimensions must be at least "
            f"{MIN_WIDTH}x{MIN_HEIGHT} and roughly 2:1; got {width}x{height}\n"
        )
        return 1
    sys.stdout.write(f"Social preview OK: {width}x{height}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
