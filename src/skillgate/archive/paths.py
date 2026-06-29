from __future__ import annotations

import re
from pathlib import Path

from .errors import ArchiveLimitError, ArchiveSafetyError, archive_error
from .models import ArchiveLimits

WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")


def normalize_archive_member_path(
    raw_path: str,
    *,
    is_dir: bool,
    limits: ArchiveLimits,
) -> str:
    if "\x00" in raw_path:
        raise archive_error(
            ArchiveSafetyError,
            "Archive member path contains a NUL byte",
            member_path=raw_path,
            code="unsafe_path",
        )
    if raw_path.startswith(("\\\\", "//")):
        raise archive_error(
            ArchiveSafetyError,
            "Archive member path must not be a UNC path",
            member_path=raw_path,
            code="unsafe_path",
        )
    if WINDOWS_DRIVE_RE.match(raw_path):
        raise archive_error(
            ArchiveSafetyError,
            "Archive member path must not include a Windows drive",
            member_path=raw_path,
            code="unsafe_path",
        )

    normalized = raw_path.replace("\\", "/")
    if normalized.startswith("/"):
        raise archive_error(
            ArchiveSafetyError,
            "Archive member path must be relative",
            member_path=raw_path,
            code="unsafe_path",
        )

    parts: list[str] = []
    for part in normalized.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise archive_error(
                ArchiveSafetyError,
                "Archive member path must not contain parent traversal",
                member_path=raw_path,
                code="unsafe_path",
            )
        parts.append(part)

    normalized = "/".join(parts)
    if not normalized:
        kind = "directory" if is_dir else "file"
        raise archive_error(
            ArchiveSafetyError,
            f"Archive member {kind} path is empty after normalization",
            member_path=raw_path,
            code="unsafe_path",
        )
    if len(normalized) > limits.max_path_length:
        raise archive_error(
            ArchiveLimitError,
            "Archive member path exceeds maximum normalized length",
            member_path=raw_path,
            code="path_too_long",
            limit="max_path_length",
            observed=len(normalized),
            allowed=limits.max_path_length,
        )
    return normalized


def validate_archive_member_paths(
    members: list[tuple[str, str]],
    *,
    archive_path: str | Path | None = None,
) -> None:
    seen: dict[str, str] = {}
    explicit_dirs: set[str] = set()
    files: set[str] = set()

    for normalized_path, member_type in members:
        previous = seen.get(normalized_path)
        if previous is not None:
            if previous != member_type:
                raise archive_error(
                    ArchiveSafetyError,
                    "Archive contains a file/directory path collision",
                    archive_path=archive_path,
                    member_path=normalized_path,
                    code="path_type_collision",
                )
            raise archive_error(
                ArchiveSafetyError,
                "Archive contains duplicate normalized member paths",
                archive_path=archive_path,
                member_path=normalized_path,
                code="duplicate_path",
            )
        seen[normalized_path] = member_type
        if member_type == "directory":
            explicit_dirs.add(normalized_path)
        else:
            files.add(normalized_path)

    for file_path in sorted(files):
        parent_parts = file_path.split("/")[:-1]
        for index in range(1, len(parent_parts) + 1):
            parent = "/".join(parent_parts[:index])
            if parent in files:
                raise archive_error(
                    ArchiveSafetyError,
                    "Archive member uses a regular file as a parent directory",
                    archive_path=archive_path,
                    member_path=file_path,
                    code="path_type_collision",
                )

    for directory in sorted(explicit_dirs):
        if directory in files:
            raise archive_error(
                ArchiveSafetyError,
                "Archive contains a directory/file path collision",
                archive_path=archive_path,
                member_path=directory,
                code="path_type_collision",
            )


def _ensure_within_root(
    root: Path, target: Path, archive_path: str | Path, member_path: str
) -> None:
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise archive_error(
            ArchiveSafetyError,
            "Archive member resolved outside extraction root",
            archive_path=archive_path,
            member_path=member_path,
            code="unsafe_path",
        ) from exc
