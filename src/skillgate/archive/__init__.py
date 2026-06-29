"""Fail-closed ZIP archive inspection.

Import supported archive interfaces from this package rather than its internal
modules.
"""

from .errors import (
    ArchiveError,
    ArchiveFormatError,
    ArchiveLimitError,
    ArchiveSafetyError,
)
from .manifest import archive_manifest
from .models import (
    DEFAULT_ARCHIVE_LIMITS,
    ArchiveInspectionResult,
    ArchiveLimits,
    ArchiveMember,
)
from .paths import (
    normalize_archive_member_path,
    validate_archive_member_paths,
)
from .zip_inspection import inspect_archive

__all__ = [
    "ArchiveError",
    "ArchiveFormatError",
    "ArchiveInspectionResult",
    "ArchiveLimitError",
    "ArchiveLimits",
    "ArchiveMember",
    "ArchiveSafetyError",
    "DEFAULT_ARCHIVE_LIMITS",
    "archive_manifest",
    "inspect_archive",
    "normalize_archive_member_path",
    "validate_archive_member_paths",
]
