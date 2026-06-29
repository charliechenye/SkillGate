from __future__ import annotations

import shutil
from pathlib import Path

from .errors import ArchiveFormatError, archive_error


def _add_cleanup_note(error: BaseException) -> None:
    error.add_note("Archive temporary cleanup was incomplete.")


def _remove_extraction_root_strict(
    extraction_root: Path,
    *,
    archive_path: str | Path,
) -> None:
    try:
        shutil.rmtree(extraction_root)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise archive_error(
            ArchiveFormatError,
            "Archive temporary extraction directory could not be removed",
            archive_path=archive_path,
            code="cleanup_failure",
        ) from exc


def _remove_extraction_root_preserving_error(
    extraction_root: Path,
    original_error: BaseException,
) -> None:
    try:
        shutil.rmtree(extraction_root)
    except FileNotFoundError:
        return
    except OSError:
        _add_cleanup_note(original_error)
