from __future__ import annotations

import hashlib
import re
import shutil
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ARCHIVE_SCHEMA_VERSION = "1"
WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")
ARCHIVE_READ_CHUNK_SIZE = 64 * 1024
SUPPORTED_ZIP_COMPRESSION_METHODS = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
}
NESTED_ARCHIVE_EXTENSIONS = {".zip", ".mcpb", ".jar", ".whl"}


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


def _archive_hash(path: Path, limits: ArchiveLimits, original_path: str | Path) -> str:
    if not path.exists():
        raise archive_error(
            ArchiveFormatError,
            "Archive path does not exist",
            archive_path=original_path,
            code="malformed_archive",
        )
    if path.is_dir():
        raise archive_error(
            ArchiveFormatError,
            "Archive path must be a file, not a directory",
            archive_path=original_path,
            code="malformed_archive",
        )

    digest = hashlib.sha256()
    observed = 0
    try:
        with path.open("rb") as archive_file:
            while True:
                chunk = archive_file.read(ARCHIVE_READ_CHUNK_SIZE)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > limits.max_archive_bytes:
                    raise archive_error(
                        ArchiveLimitError,
                        "Archive exceeds maximum compressed size",
                        archive_path=original_path,
                        code="archive_too_large",
                        limit="max_archive_bytes",
                        observed=observed,
                        allowed=limits.max_archive_bytes,
                    )
                digest.update(chunk)
    except ArchiveError:
        raise
    except OSError as exc:
        raise archive_error(
            ArchiveFormatError,
            "Archive could not be read",
            archive_path=original_path,
            code="malformed_archive",
        ) from exc
    return digest.hexdigest()


def _bad_zip_code(path: Path) -> str:
    try:
        with path.open("rb") as archive_file:
            prefix = archive_file.read(4)
    except OSError:
        return "malformed_archive"
    return "truncated_archive" if prefix.startswith(b"PK") else "malformed_archive"


def _compression_ratio(info: zipfile.ZipInfo, member_type: str) -> float | None:
    if member_type == "directory":
        return None
    if info.file_size == 0:
        return 0.0
    return info.file_size / max(info.compress_size, 1)


def _member_type(info: zipfile.ZipInfo, archive_path: str | Path) -> str:
    unix_mode = info.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    if file_type:
        if stat.S_ISLNK(unix_mode):
            raise archive_error(
                ArchiveSafetyError,
                "Archive member is a symlink",
                archive_path=archive_path,
                member_path=info.filename,
                code="symlink_member",
            )
        if stat.S_ISDIR(unix_mode):
            return "directory"
        if stat.S_ISREG(unix_mode):
            return "file"
        raise archive_error(
            ArchiveSafetyError,
            "Archive member is a special file",
            archive_path=archive_path,
            member_path=info.filename,
            code="special_member",
        )
    return "directory" if info.is_dir() else "file"


def _is_nested_archive_path(normalized_path: str) -> bool:
    return Path(normalized_path).suffix.lower() in NESTED_ARCHIVE_EXTENSIONS


def _metadata_members(
    archive_path: Path,
    original_path: str | Path,
    limits: ArchiveLimits,
) -> tuple[list[ArchiveMember], int, int]:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
    except zipfile.BadZipFile as exc:
        code = _bad_zip_code(archive_path)
        raise archive_error(
            ArchiveFormatError,
            "Archive is not a readable ZIP file",
            archive_path=original_path,
            code=code,
        ) from exc
    except OSError as exc:
        raise archive_error(
            ArchiveFormatError,
            "Archive could not be opened",
            archive_path=original_path,
            code="malformed_archive",
        ) from exc

    if len(infos) > limits.max_members:
        raise archive_error(
            ArchiveLimitError,
            "Archive exceeds maximum member count",
            archive_path=original_path,
            code="member_limit_exceeded",
            limit="max_members",
            observed=len(infos),
            allowed=limits.max_members,
        )

    members: list[ArchiveMember] = []
    total_compressed = 0
    total_uncompressed = 0
    path_inventory: list[tuple[str, str]] = []

    for info in infos:
        member_type = _member_type(info, original_path)
        normalized_path = normalize_archive_member_path(
            info.filename,
            is_dir=member_type == "directory",
            limits=limits,
        )
        if info.flag_bits & 0x1:
            raise archive_error(
                ArchiveFormatError,
                "Archive member is encrypted",
                archive_path=original_path,
                member_path=info.filename,
                code="encrypted_member",
            )
        if info.compress_type not in SUPPORTED_ZIP_COMPRESSION_METHODS:
            raise archive_error(
                ArchiveFormatError,
                "Archive member uses unsupported compression",
                archive_path=original_path,
                member_path=info.filename,
                code="unsupported_compression",
                observed=info.compress_type,
                allowed=sorted(SUPPORTED_ZIP_COMPRESSION_METHODS),
            )
        if member_type == "file" and info.file_size > limits.max_member_uncompressed_bytes:
            raise archive_error(
                ArchiveLimitError,
                "Archive member exceeds maximum uncompressed size",
                archive_path=original_path,
                member_path=info.filename,
                code="member_size_exceeded",
                limit="max_member_uncompressed_bytes",
                observed=info.file_size,
                allowed=limits.max_member_uncompressed_bytes,
            )

        ratio = _compression_ratio(info, member_type)
        if ratio is not None and ratio > limits.max_compression_ratio:
            raise archive_error(
                ArchiveLimitError,
                "Archive member exceeds maximum compression ratio",
                archive_path=original_path,
                member_path=info.filename,
                code="compression_ratio_exceeded",
                limit="max_compression_ratio",
                observed=ratio,
                allowed=limits.max_compression_ratio,
            )

        total_compressed += info.compress_size
        if member_type == "file":
            total_uncompressed += info.file_size
            if total_uncompressed > limits.max_total_uncompressed_bytes:
                raise archive_error(
                    ArchiveLimitError,
                    "Archive exceeds maximum total uncompressed size",
                    archive_path=original_path,
                    member_path=info.filename,
                    code="total_size_exceeded",
                    limit="max_total_uncompressed_bytes",
                    observed=total_uncompressed,
                    allowed=limits.max_total_uncompressed_bytes,
                )

        is_nested = member_type == "file" and _is_nested_archive_path(normalized_path)
        if is_nested and not limits.allow_nested_archives:
            raise archive_error(
                ArchiveSafetyError,
                "Archive member is a nested archive",
                archive_path=original_path,
                member_path=info.filename,
                code="nested_archive",
            )

        path_inventory.append((normalized_path, member_type))
        members.append(
            ArchiveMember(
                original_path=info.filename,
                normalized_path=normalized_path,
                member_type=member_type,
                compressed_size=info.compress_size,
                uncompressed_size=info.file_size if member_type == "file" else 0,
                compression_ratio=ratio,
                sha256=None,
                is_nested_archive=is_nested,
                is_scannable_text=False,
                skip_reason=(
                    "nested archive retained but not recursively inspected"
                    if is_nested
                    else "content not inspected yet"
                    if member_type == "file"
                    else None
                ),
            )
        )

    validate_archive_member_paths(path_inventory, archive_path=original_path)
    return (
        sorted(members, key=lambda item: item.normalized_path),
        total_compressed,
        total_uncompressed,
    )


def inspect_archive(
    path: Path | str,
    *,
    limits: ArchiveLimits | None = None,
) -> ArchiveInspectionResult:
    limits = limits or DEFAULT_ARCHIVE_LIMITS
    archive_path = Path(path)
    archive_sha256 = _archive_hash(archive_path, limits, path)
    members, total_compressed, total_uncompressed = _metadata_members(
        archive_path,
        path,
        limits,
    )
    result = ArchiveInspectionResult(
        archive_path=archive_path,
        archive_sha256=archive_sha256,
        archive_format="zip",
        limits=limits,
        member_count=len(members),
        total_compressed_bytes=total_compressed,
        total_uncompressed_bytes=total_uncompressed,
        members=members,
        extraction_root=Path("__skillgate_no_extraction_root__"),
    )
    result._cleaned_up = True
    return result


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
