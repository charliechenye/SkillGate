from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ARCHIVE_SCHEMA_VERSION = "1"
WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")


@dataclass(frozen=True)
class ArchiveLimits:
    max_archive_bytes: int
    max_members: int
    max_total_uncompressed_bytes: int
    max_member_uncompressed_bytes: int
    max_compression_ratio: float
    max_path_length: int
    allow_nested_archives: bool = False

    def __post_init__(self) -> None:
        checks = {
            "max_archive_bytes": self.max_archive_bytes,
            "max_members": self.max_members,
            "max_total_uncompressed_bytes": self.max_total_uncompressed_bytes,
            "max_member_uncompressed_bytes": self.max_member_uncompressed_bytes,
            "max_compression_ratio": self.max_compression_ratio,
            "max_path_length": self.max_path_length,
        }
        for name, value in checks.items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if self.max_member_uncompressed_bytes > self.max_total_uncompressed_bytes:
            raise ValueError(
                "max_member_uncompressed_bytes must be less than or equal to "
                "max_total_uncompressed_bytes"
            )

    def to_data(self) -> dict[str, object]:
        return {
            "max_archive_bytes": self.max_archive_bytes,
            "max_members": self.max_members,
            "max_total_uncompressed_bytes": self.max_total_uncompressed_bytes,
            "max_member_uncompressed_bytes": self.max_member_uncompressed_bytes,
            "max_compression_ratio": self.max_compression_ratio,
            "max_path_length": self.max_path_length,
            "allow_nested_archives": self.allow_nested_archives,
        }


DEFAULT_ARCHIVE_LIMITS = ArchiveLimits(
    max_archive_bytes=100 * 1024 * 1024,
    max_members=1000,
    max_total_uncompressed_bytes=100 * 1024 * 1024,
    max_member_uncompressed_bytes=20 * 1024 * 1024,
    max_compression_ratio=100.0,
    max_path_length=240,
    allow_nested_archives=False,
)


@dataclass(frozen=True)
class ArchiveMember:
    original_path: str
    normalized_path: str
    member_type: str
    compressed_size: int
    uncompressed_size: int
    compression_ratio: float | None
    sha256: str | None
    is_nested_archive: bool
    is_scannable_text: bool
    skip_reason: str | None


@dataclass
class ArchiveInspectionResult:
    archive_path: Path
    archive_sha256: str
    archive_format: str
    limits: ArchiveLimits
    member_count: int
    total_compressed_bytes: int
    total_uncompressed_bytes: int
    members: list[ArchiveMember]
    extraction_root: Path = field(repr=False, compare=False)
    _cleaned_up: bool = field(default=False, init=False, repr=False, compare=False)

    def cleanup(self) -> None:
        if self._cleaned_up:
            return
        shutil.rmtree(self.extraction_root, ignore_errors=True)
        self._cleaned_up = True

    def __enter__(self) -> ArchiveInspectionResult:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.cleanup()


class ArchiveError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        archive_path: str | Path | None = None,
        member_path: str | None = None,
        code: str,
        limit: str | None = None,
        observed: object | None = None,
        allowed: object | None = None,
    ) -> None:
        self.archive_path = archive_path
        self.member_path = member_path
        self.code = code
        self.limit = limit
        self.observed = observed
        self.allowed = allowed
        super().__init__(message)

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {"code": self.code, "message": str(self)}
        if self.archive_path is not None:
            data["archive_path"] = _safe_archive_display(self.archive_path)
        if self.member_path is not None:
            data["member_path"] = _safe_member_display(self.member_path)
        if self.limit is not None:
            data["limit"] = self.limit
        if self.observed is not None:
            data["observed"] = self.observed
        if self.allowed is not None:
            data["allowed"] = self.allowed
        return data


class ArchiveFormatError(ArchiveError):
    pass


class ArchiveSafetyError(ArchiveError):
    pass


class ArchiveLimitError(ArchiveError):
    pass


def _safe_archive_display(path: str | Path) -> str:
    return str(path).encode("unicode_escape").decode("ascii")


def _safe_member_display(name: str) -> str:
    return name.encode("unicode_escape").decode("ascii")


def _format_archive_error_message(
    message: str,
    *,
    archive_path: str | Path | None = None,
    member_path: str | None = None,
) -> str:
    parts = [message]
    if archive_path is not None:
        parts.append(f"archive={_safe_archive_display(archive_path)}")
    if member_path is not None:
        parts.append(f"member={_safe_member_display(member_path)}")
    return " (".join([parts[0], ", ".join(parts[1:]) + ")"]) if len(parts) > 1 else message


def archive_error(
    error_type: type[ArchiveError],
    message: str,
    *,
    archive_path: str | Path | None = None,
    member_path: str | None = None,
    code: str,
    limit: str | None = None,
    observed: object | None = None,
    allowed: object | None = None,
) -> ArchiveError:
    return error_type(
        _format_archive_error_message(
            message,
            archive_path=archive_path,
            member_path=member_path,
        ),
        archive_path=archive_path,
        member_path=member_path,
        code=code,
        limit=limit,
        observed=observed,
        allowed=allowed,
    )


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
        prefix = f"{directory}/"
        if directory in files or any(file_path.startswith(prefix) for file_path in files):
            raise archive_error(
                ArchiveSafetyError,
                "Archive contains a directory/file prefix collision",
                archive_path=archive_path,
                member_path=directory,
                code="path_type_collision",
            )


def inspect_archive(
    path: Path | str,
    *,
    limits: ArchiveLimits | None = None,
) -> ArchiveInspectionResult:
    raise archive_error(
        ArchiveFormatError,
        "Archive inspection is not implemented yet",
        archive_path=path,
        code="malformed_archive",
    )


def archive_manifest(result: ArchiveInspectionResult) -> dict[str, object]:
    members: list[dict[str, Any]] = []
    for member in sorted(result.members, key=lambda item: item.normalized_path):
        members.append(
            {
                "path": member.normalized_path,
                "type": member.member_type,
                "compressed_size": member.compressed_size,
                "uncompressed_size": member.uncompressed_size,
                "compression_ratio": (
                    None if member.compression_ratio is None else round(member.compression_ratio, 4)
                ),
                "sha256": member.sha256,
                "nested_archive": member.is_nested_archive,
                "scannable_text": member.is_scannable_text,
                "skip_reason": member.skip_reason,
            }
        )
    return {
        "schema_version": ARCHIVE_SCHEMA_VERSION,
        "archive": {
            "sha256": result.archive_sha256,
            "format": result.archive_format,
            "member_count": result.member_count,
            "total_compressed_bytes": result.total_compressed_bytes,
            "total_uncompressed_bytes": result.total_uncompressed_bytes,
        },
        "limits": result.limits.to_data(),
        "members": members,
    }
