from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

from .cleanup import (
    _add_cleanup_note,
    _remove_extraction_root_strict,
)
from .errors import ArchiveError


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
        _remove_extraction_root_strict(self.extraction_root, archive_path=self.archive_path)
        self._cleaned_up = True

    def __enter__(self) -> ArchiveInspectionResult:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self.cleanup()
        except ArchiveError:
            if exc is None:
                raise
            _add_cleanup_note(exc)
