from __future__ import annotations

import hashlib
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .classification import (
    CONTENT_PREFIX_BYTES,
    _has_zip_magic,
    _is_nested_archive_path,
    classify_archive_member,
)
from .cleanup import _remove_extraction_root_preserving_error
from .errors import (
    ArchiveError,
    ArchiveFormatError,
    ArchiveLimitError,
    ArchiveSafetyError,
    archive_error,
)
from .models import (
    DEFAULT_ARCHIVE_LIMITS,
    ArchiveInspectionResult,
    ArchiveLimits,
    ArchiveMember,
)
from .paths import (
    _ensure_within_root,
    normalize_archive_member_path,
    validate_archive_member_paths,
)

ARCHIVE_READ_CHUNK_SIZE = 64 * 1024
SUPPORTED_ZIP_COMPRESSION_METHODS = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
}


@dataclass(frozen=True)
class _PendingMember:
    info: zipfile.ZipInfo
    member: ArchiveMember


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


def _metadata_members(
    archive_path: Path,
    original_path: str | Path,
    limits: ArchiveLimits,
) -> tuple[list[_PendingMember], int, int]:
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

    pending_members: list[_PendingMember] = []
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
        pending_members.append(
            _PendingMember(
                info=info,
                member=ArchiveMember(
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
                ),
            )
        )
    validate_archive_member_paths(path_inventory, archive_path=original_path)
    return (
        sorted(pending_members, key=lambda item: item.member.normalized_path),
        total_compressed,
        total_uncompressed,
    )


def _create_temp_root(archive_path: str | Path) -> Path:
    try:
        return Path(tempfile.mkdtemp(prefix="skillgate-archive-"))
    except OSError as exc:
        raise archive_error(
            ArchiveFormatError,
            "Archive temporary extraction directory could not be created",
            archive_path=archive_path,
            code="extraction_failure",
        ) from exc


def _wrap_extraction_error(
    exc: BaseException,
    *,
    archive_path: str | Path,
    member_path: str,
) -> ArchiveError:
    text = str(exc)
    if isinstance(exc, zipfile.BadZipFile) and "CRC" in text.upper():
        return archive_error(
            ArchiveFormatError,
            "Archive member failed CRC validation",
            archive_path=archive_path,
            member_path=member_path,
            code="crc_failure",
        )
    if isinstance(exc, zipfile.BadZipFile):
        return archive_error(
            ArchiveFormatError,
            "Archive member could not be decompressed",
            archive_path=archive_path,
            member_path=member_path,
            code="truncated_archive",
        )
    return archive_error(
        ArchiveFormatError,
        "Archive member could not be extracted",
        archive_path=archive_path,
        member_path=member_path,
        code="extraction_failure",
    )


def _chmod_restrictive(path: Path, mode: int, archive_path: str | Path, member_path: str) -> None:
    try:
        path.chmod(mode)
    except OSError as exc:
        raise archive_error(
            ArchiveFormatError,
            "Archive extracted path permissions could not be restricted",
            archive_path=archive_path,
            member_path=member_path,
            code="extraction_failure",
        ) from exc


def _stream_member(
    archive: zipfile.ZipFile,
    pending: _PendingMember,
    destination: Path,
    original_path: str | Path,
    limits: ArchiveLimits,
) -> tuple[str, bytes]:
    digest = hashlib.sha256()
    byte_count = 0
    prefix = bytearray()
    try:
        with archive.open(pending.info, "r") as source, destination.open("xb") as target:
            while True:
                chunk = source.read(ARCHIVE_READ_CHUNK_SIZE)
                if not chunk:
                    break
                next_count = byte_count + len(chunk)
                if next_count > limits.max_member_uncompressed_bytes:
                    raise archive_error(
                        ArchiveLimitError,
                        "Archive member stream exceeds maximum uncompressed size",
                        archive_path=original_path,
                        member_path=pending.member.original_path,
                        code="member_size_exceeded",
                        limit="max_member_uncompressed_bytes",
                        observed=next_count,
                        allowed=limits.max_member_uncompressed_bytes,
                    )
                if next_count > pending.info.file_size:
                    raise archive_error(
                        ArchiveFormatError,
                        "Archive member stream exceeded declared uncompressed size",
                        archive_path=original_path,
                        member_path=pending.member.original_path,
                        code="content_size_mismatch",
                        observed=next_count,
                        allowed=pending.info.file_size,
                    )
                if len(prefix) < CONTENT_PREFIX_BYTES:
                    prefix.extend(chunk[: CONTENT_PREFIX_BYTES - len(prefix)])
                digest.update(chunk)
                target.write(chunk)
                byte_count = next_count
    except ArchiveError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise _wrap_extraction_error(
            exc,
            archive_path=original_path,
            member_path=pending.member.original_path,
        ) from exc

    if byte_count != pending.info.file_size:
        raise archive_error(
            ArchiveFormatError,
            "Archive member stream did not match declared uncompressed size",
            archive_path=original_path,
            member_path=pending.member.original_path,
            code="content_size_mismatch",
            observed=byte_count,
            allowed=pending.info.file_size,
        )
    return digest.hexdigest(), bytes(prefix)


def _extract_members(
    archive_path: Path,
    original_path: str | Path,
    pending_members: list[_PendingMember],
    limits: ArchiveLimits,
    extraction_root: Path,
) -> list[ArchiveMember]:
    root = extraction_root.resolve()
    extracted: list[ArchiveMember] = []
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for pending in pending_members:
                member = pending.member
                destination = (root / member.normalized_path).resolve()
                _ensure_within_root(root, destination, original_path, member.original_path)
                if member.member_type == "directory":
                    try:
                        destination.mkdir(parents=True, exist_ok=True)
                    except OSError as exc:
                        raise archive_error(
                            ArchiveFormatError,
                            "Archive directory could not be materialized",
                            archive_path=original_path,
                            member_path=member.original_path,
                            code="extraction_failure",
                        ) from exc
                    _chmod_restrictive(destination, 0o700, original_path, member.original_path)
                    extracted.append(member)
                    continue

                try:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                except OSError as exc:
                    raise archive_error(
                        ArchiveFormatError,
                        "Archive member parent directory could not be materialized",
                        archive_path=original_path,
                        member_path=member.original_path,
                        code="extraction_failure",
                    ) from exc
                _ensure_within_root(root, destination, original_path, member.original_path)
                sha256, prefix = _stream_member(
                    archive,
                    pending,
                    destination,
                    original_path,
                    limits,
                )
                _chmod_restrictive(destination, 0o600, original_path, member.original_path)

                magic_nested = _has_zip_magic(prefix)
                is_nested = member.is_nested_archive or magic_nested
                if magic_nested and not limits.allow_nested_archives:
                    raise archive_error(
                        ArchiveSafetyError,
                        "Archive member is a nested archive",
                        archive_path=original_path,
                        member_path=member.original_path,
                        code="nested_archive",
                    )
                if is_nested:
                    is_text = False
                    skip_reason = "nested archive retained but not recursively inspected"
                else:
                    is_text, skip_reason = classify_archive_member(member.normalized_path, prefix)
                extracted.append(
                    ArchiveMember(
                        original_path=member.original_path,
                        normalized_path=member.normalized_path,
                        member_type=member.member_type,
                        compressed_size=member.compressed_size,
                        uncompressed_size=member.uncompressed_size,
                        compression_ratio=member.compression_ratio,
                        sha256=sha256,
                        is_nested_archive=is_nested,
                        is_scannable_text=is_text,
                        skip_reason=skip_reason,
                    )
                )
    except ArchiveError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise archive_error(
            ArchiveFormatError,
            "Archive extraction failed",
            archive_path=original_path,
            code="extraction_failure",
        ) from exc
    return sorted(extracted, key=lambda item: item.normalized_path)


def inspect_archive(
    path: Path | str,
    *,
    limits: ArchiveLimits | None = None,
) -> ArchiveInspectionResult:
    limits = limits or DEFAULT_ARCHIVE_LIMITS
    archive_path = Path(path)
    archive_sha256 = _archive_hash(archive_path, limits, path)
    pending_members, total_compressed, total_uncompressed = _metadata_members(
        archive_path,
        path,
        limits,
    )
    extraction_root = _create_temp_root(path)
    try:
        members = _extract_members(
            archive_path,
            path,
            pending_members,
            limits,
            extraction_root,
        )
    except Exception as exc:
        _remove_extraction_root_preserving_error(extraction_root, exc)
        raise
    return ArchiveInspectionResult(
        archive_path=archive_path,
        archive_sha256=archive_sha256,
        archive_format="zip",
        limits=limits,
        member_count=len(members),
        total_compressed_bytes=total_compressed,
        total_uncompressed_bytes=total_uncompressed,
        members=members,
        extraction_root=extraction_root,
    )
