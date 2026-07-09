from __future__ import annotations

import hashlib
import stat
import zipfile
from collections.abc import Iterable
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

DEMO_MCPB_SHA256 = "6948b641f88671717de7142ce075f21f9710621392b115a311eee05831fe5a1c"
DEMO_MCPB_SOURCE = "demo_assets/mcpb-reviewable-node"
DEMO_SKILL_SOURCE = "demo_assets/skill-reviewable"
FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def demo_mcpb_files() -> dict[str, bytes]:
    root = resources.files("skillgate").joinpath(DEMO_MCPB_SOURCE)
    return {
        path: resource.read_bytes()
        for path, resource in sorted(_resource_files(root), key=lambda item: item[0])
    }


def build_demo_mcpb(output: Path) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        for relative, content in demo_mcpb_files().items():
            info = zipfile.ZipInfo(relative)
            info.date_time = FIXED_TIME
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, content)

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    if digest != DEMO_MCPB_SHA256:
        raise RuntimeError("deterministic demo MCPB hash changed unexpectedly")
    return digest


def demo_skill_files() -> dict[str, bytes]:
    root = resources.files("skillgate").joinpath(DEMO_SKILL_SOURCE)
    return {
        path: resource.read_bytes()
        for path, resource in sorted(_resource_files(root), key=lambda item: item[0])
    }


def build_demo_skill(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for relative, content in demo_skill_files().items():
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)


def _resource_files(root: Traversable, prefix: str = "") -> Iterable[tuple[str, Traversable]]:
    for child in root.iterdir():
        relative = f"{prefix}/{child.name}" if prefix else child.name
        if child.is_dir():
            yield from _resource_files(child, relative)
        elif child.is_file():
            yield relative, child
