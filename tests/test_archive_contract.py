from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path

import pytest

import skillgate.archive
from skillgate.archive import (
    DEFAULT_ARCHIVE_LIMITS,
    ArchiveFormatError,
    ArchiveLimitError,
    ArchiveSafetyError,
    archive_manifest,
    inspect_archive,
    normalize_archive_member_path,
)

EXPECTED_ARCHIVE_EXPORTS = [
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


@pytest.mark.parametrize("name", EXPECTED_ARCHIVE_EXPORTS)
def test_archive_supported_symbols_are_available(name: str) -> None:
    assert hasattr(skillgate.archive, name)


def test_archive_all_matches_supported_exports() -> None:
    assert skillgate.archive.__all__ == EXPECTED_ARCHIVE_EXPORTS


def test_default_archive_limits_contract() -> None:
    assert DEFAULT_ARCHIVE_LIMITS.to_data() == {
        "max_archive_bytes": 104857600,
        "max_members": 1000,
        "max_total_uncompressed_bytes": 104857600,
        "max_member_uncompressed_bytes": 20971520,
        "max_compression_ratio": 100.0,
        "max_path_length": 240,
        "allow_nested_archives": False,
    }


def test_archive_format_error_data_contract(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.zip"
    expected_path = str(missing_path).encode("unicode_escape").decode("ascii")

    with pytest.raises(ArchiveFormatError) as excinfo:
        inspect_archive(missing_path)

    assert excinfo.value.to_data() == {
        "code": "malformed_archive",
        "message": f"Archive path does not exist (archive={expected_path})",
        "archive_path": expected_path,
    }


def test_archive_safety_error_data_contract() -> None:
    with pytest.raises(ArchiveSafetyError) as excinfo:
        normalize_archive_member_path(
            "../escape.txt",
            is_dir=False,
            limits=DEFAULT_ARCHIVE_LIMITS,
        )

    assert excinfo.value.to_data() == {
        "code": "unsafe_path",
        "message": "Archive member path must not contain parent traversal (member=../escape.txt)",
        "member_path": "../escape.txt",
    }


def test_archive_limit_error_data_contract() -> None:
    member_path = "a" * 241

    with pytest.raises(ArchiveLimitError) as excinfo:
        normalize_archive_member_path(
            member_path,
            is_dir=False,
            limits=DEFAULT_ARCHIVE_LIMITS,
        )

    assert excinfo.value.to_data() == {
        "code": "path_too_long",
        "message": (
            f"Archive member path exceeds maximum normalized length (member={member_path})"
        ),
        "member_path": member_path,
        "limit": "max_path_length",
        "observed": 241,
        "allowed": 240,
    }


def _stored_zip_info(name: str, *, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.date_time = (2020, 1, 1, 0, 0, 0)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = mode
    return info


def test_archive_manifest_contract_is_deterministic(tmp_path: Path) -> None:
    archive_path = tmp_path / "contract.zip"
    file_content = b"hello"
    markdown_content = b"# title\n"

    directory_info = _stored_zip_info(
        "a/",
        mode=((stat.S_IFDIR | 0o700) << 16) | 0x10,
    )
    file_info = _stored_zip_info(
        "a/file.txt",
        mode=(stat.S_IFREG | 0o600) << 16,
    )
    markdown_info = _stored_zip_info(
        "z.md",
        mode=(stat.S_IFREG | 0o600) << 16,
    )

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(markdown_info, markdown_content)
        archive.writestr(directory_info, b"")
        archive.writestr(file_info, file_content)

    expected_archive_sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()

    result = inspect_archive(archive_path)
    try:
        manifest = archive_manifest(result)
        assert manifest == {
            "schema_version": "1",
            "archive": {
                "sha256": expected_archive_sha256,
                "format": "zip",
                "member_count": 3,
                "total_compressed_bytes": 13,
                "total_uncompressed_bytes": 13,
            },
            "limits": DEFAULT_ARCHIVE_LIMITS.to_data(),
            "members": [
                {
                    "path": "a",
                    "type": "directory",
                    "compressed_size": 0,
                    "uncompressed_size": 0,
                    "compression_ratio": None,
                    "sha256": None,
                    "nested_archive": False,
                    "scannable_text": False,
                    "skip_reason": None,
                },
                {
                    "path": "a/file.txt",
                    "type": "file",
                    "compressed_size": 5,
                    "uncompressed_size": 5,
                    "compression_ratio": 1.0,
                    "sha256": hashlib.sha256(file_content).hexdigest(),
                    "nested_archive": False,
                    "scannable_text": True,
                    "skip_reason": None,
                },
                {
                    "path": "z.md",
                    "type": "file",
                    "compressed_size": 8,
                    "uncompressed_size": 8,
                    "compression_ratio": 1.0,
                    "sha256": hashlib.sha256(markdown_content).hexdigest(),
                    "nested_archive": False,
                    "scannable_text": True,
                    "skip_reason": None,
                },
            ],
        }

        serialized = json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

        assert serialized == json.dumps(
            archive_manifest(result),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        assert str(archive_path) not in serialized
        assert str(result.extraction_root) not in serialized
    finally:
        result.cleanup()
