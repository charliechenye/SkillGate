from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skillgate import __version__
from skillgate.models import SCHEMA_VERSION, stable_json

ALGORITHM = "sha256"


class ProvenanceError(ValueError):
    pass


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance_entry(role: str, path: Path) -> dict[str, str]:
    return {
        "role": role,
        "path": path.as_posix(),
        "sha256": file_digest(path),
    }


def create_provenance_manifest(policy: Path, baseline: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "algorithm": ALGORITHM,
        "files": [
            provenance_entry("policy", policy),
            provenance_entry("baseline", baseline),
        ],
    }


def save_provenance_manifest(manifest: dict[str, Any], output: Path) -> None:
    output.write_text(stable_json(manifest), encoding="utf-8")


def load_provenance_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"Unable to load provenance manifest: {path}") from exc
    if not isinstance(data, dict):
        raise ProvenanceError("Provenance manifest must be a JSON object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ProvenanceError("Provenance manifest schema_version must be 1")
    if data.get("algorithm") != ALGORITHM:
        raise ProvenanceError("Provenance manifest algorithm must be sha256")
    files = data.get("files")
    if not isinstance(files, list) or not files:
        raise ProvenanceError("Provenance manifest must contain files")
    for item in files:
        if not isinstance(item, dict):
            raise ProvenanceError("Provenance manifest files must be objects")
        required = ["role", "path", "sha256"]
        if not all(isinstance(item.get(key), str) and item.get(key) for key in required):
            raise ProvenanceError("Provenance manifest file entries require role, path, and sha256")
    return data


def verify_provenance_manifest(manifest_path: Path) -> list[str]:
    manifest = load_provenance_manifest(manifest_path)
    mismatches = []
    for item in manifest["files"]:
        target = (manifest_path.parent / item["path"]).resolve()
        if not target.exists():
            raise ProvenanceError(f"Missing {item['role']} file: {item['path']}")
        actual = file_digest(target)
        if actual != item["sha256"]:
            mismatches.append(f"Checksum mismatch for {item['role']} file: {item['path']}")
    return mismatches
