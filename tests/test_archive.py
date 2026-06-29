from __future__ import annotations

import hashlib
import stat
import zipfile
from pathlib import Path

import pytest

from skillgate.archive import (
    DEFAULT_ARCHIVE_LIMITS,
    ArchiveFormatError,
    ArchiveLimitError,
    ArchiveLimits,
    ArchiveSafetyError,
    inspect_archive,
    normalize_archive_member_path,
    validate_archive_member_paths,
)


def tiny_limits(**overrides: object) -> ArchiveLimits:
    values = {
        "max_archive_bytes": 1000,
        "max_members": 10,
        "max_total_uncompressed_bytes": 1000,
        "max_member_uncompressed_bytes": 500,
        "max_compression_ratio": 10.0,
        "max_path_length": 240,
        "allow_nested_archives": False,
    }
    values.update(overrides)
    return ArchiveLimits(**values)


def write_zip(path: Path, entries: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return path


def write_zipinfo(path: Path, info: zipfile.ZipInfo, content: bytes = b"data") -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, content)
    return path


def patch_encrypted_flag(path: Path) -> None:
    data = bytearray(path.read_bytes())
    for signature, flag_offset in [(b"PK\x03\x04", 6), (b"PK\x01\x02", 8)]:
        offset = 0
        while True:
            offset = data.find(signature, offset)
            if offset < 0:
                break
            flag_index = offset + flag_offset
            flag = int.from_bytes(data[flag_index : flag_index + 2], "little") | 0x1
            data[flag_index : flag_index + 2] = flag.to_bytes(2, "little")
            offset += 4
    path.write_bytes(data)


@pytest.mark.parametrize(
    ("raw_path", "expected"),
    [
        ("a//b", "a/b"),
        ("a/./b", "a/b"),
        ("safe/nested/file.txt", "safe/nested/file.txt"),
        ("dir/", "dir"),
    ],
)
def test_normalize_archive_member_path_accepts_safe_paths(raw_path: str, expected: str) -> None:
    assert (
        normalize_archive_member_path(raw_path, is_dir=False, limits=DEFAULT_ARCHIVE_LIMITS)
        == expected
    )


@pytest.mark.parametrize(
    "raw_path",
    [
        "../file",
        "a/../../file",
        "a\\..\\file",
        "/file",
        "C:\\file",
        "C:/file",
        "\\\\server\\share\\file",
        "\x00",
        "safe/\x00/file",
        "",
        ".",
    ],
)
def test_normalize_archive_member_path_rejects_unsafe_paths(raw_path: str) -> None:
    with pytest.raises(ArchiveSafetyError) as excinfo:
        normalize_archive_member_path(raw_path, is_dir=False, limits=DEFAULT_ARCHIVE_LIMITS)

    assert excinfo.value.code == "unsafe_path"


def test_normalize_archive_member_path_rejects_long_paths() -> None:
    with pytest.raises(ArchiveLimitError) as excinfo:
        normalize_archive_member_path(
            "a" * 21, is_dir=False, limits=tiny_limits(max_path_length=20)
        )

    assert excinfo.value.code == "path_too_long"
    assert excinfo.value.limit == "max_path_length"
    assert excinfo.value.observed == 21
    assert excinfo.value.allowed == 20


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_archive_bytes": 0},
        {"max_members": 0},
        {"max_total_uncompressed_bytes": 0},
        {"max_member_uncompressed_bytes": 0},
        {"max_compression_ratio": 0.0},
        {"max_path_length": 0},
        {"max_total_uncompressed_bytes": 10, "max_member_uncompressed_bytes": 11},
    ],
)
def test_archive_limits_reject_invalid_configurations(kwargs: dict[str, object]) -> None:
    values = {
        "max_archive_bytes": 100,
        "max_members": 10,
        "max_total_uncompressed_bytes": 100,
        "max_member_uncompressed_bytes": 10,
        "max_compression_ratio": 10.0,
        "max_path_length": 20,
    }
    values.update(kwargs)

    with pytest.raises(ValueError):
        ArchiveLimits(**values)


def test_validate_archive_member_paths_rejects_duplicate_normalized_paths() -> None:
    with pytest.raises(ArchiveSafetyError) as excinfo:
        validate_archive_member_paths([("a/b.txt", "file"), ("a/b.txt", "file")])

    assert excinfo.value.code == "duplicate_path"


def test_validate_archive_member_paths_rejects_file_and_directory_same_path() -> None:
    with pytest.raises(ArchiveSafetyError) as excinfo:
        validate_archive_member_paths([("a", "directory"), ("a", "file")])

    assert excinfo.value.code == "path_type_collision"


def test_validate_archive_member_paths_rejects_file_as_parent() -> None:
    with pytest.raises(ArchiveSafetyError) as excinfo:
        validate_archive_member_paths([("a", "file"), ("a/b.txt", "file")])

    assert excinfo.value.code == "path_type_collision"


def test_validate_archive_member_paths_allows_explicit_parent_directory() -> None:
    validate_archive_member_paths([("a", "directory"), ("a/b.txt", "file")])


def test_error_messages_escape_control_characters() -> None:
    with pytest.raises(ArchiveLimitError) as excinfo:
        normalize_archive_member_path(
            "safe\nname",
            is_dir=False,
            limits=tiny_limits(max_path_length=4),
        )

    message = str(excinfo.value)
    assert "\n" not in message
    assert "\\n" in message


def test_inspect_archive_rejects_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "missing.zip"

    with pytest.raises(ArchiveFormatError) as excinfo:
        inspect_archive(missing)

    assert excinfo.value.code == "malformed_archive"


def test_inspect_archive_rejects_directory_input(tmp_path: Path) -> None:
    with pytest.raises(ArchiveFormatError) as excinfo:
        inspect_archive(tmp_path)

    assert excinfo.value.code == "malformed_archive"


def test_empty_zip_archive_is_valid(tmp_path: Path) -> None:
    archive_path = tmp_path / "empty.zip"
    with zipfile.ZipFile(archive_path, "w"):
        pass

    result = inspect_archive(archive_path)

    assert result.member_count == 0
    assert result.members == []
    assert result.archive_sha256 == hashlib.sha256(archive_path.read_bytes()).hexdigest()
    result.cleanup()
    result.cleanup()


def test_metadata_members_are_sorted_and_directories_allowed(tmp_path: Path) -> None:
    archive_path = tmp_path / "safe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("z.txt", b"last")
        archive.writestr("a/", b"")
        archive.writestr("a/b.txt", b"first")

    result = inspect_archive(archive_path)

    assert [member.normalized_path for member in result.members] == ["a", "a/b.txt", "z.txt"]
    assert [member.member_type for member in result.members] == ["directory", "file", "file"]
    assert all(member.sha256 is None for member in result.members)


def test_archive_size_limit_is_enforced(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "large.zip", [("a.txt", b"data")])

    with pytest.raises(ArchiveLimitError) as excinfo:
        inspect_archive(archive_path, limits=tiny_limits(max_archive_bytes=1))

    assert excinfo.value.code == "archive_too_large"


def test_member_count_limit_is_enforced(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "many.zip", [("a.txt", b"a"), ("b.txt", b"b")])

    with pytest.raises(ArchiveLimitError) as excinfo:
        inspect_archive(archive_path, limits=tiny_limits(max_members=1))

    assert excinfo.value.code == "member_limit_exceeded"


def test_member_size_limit_is_enforced(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "member.zip", [("a.txt", b"12345")])

    with pytest.raises(ArchiveLimitError) as excinfo:
        inspect_archive(archive_path, limits=tiny_limits(max_member_uncompressed_bytes=4))

    assert excinfo.value.code == "member_size_exceeded"


def test_total_uncompressed_size_limit_is_enforced(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "total.zip", [("a.txt", b"123"), ("b.txt", b"456")])

    with pytest.raises(ArchiveLimitError) as excinfo:
        inspect_archive(
            archive_path,
            limits=tiny_limits(max_total_uncompressed_bytes=5, max_member_uncompressed_bytes=5),
        )

    assert excinfo.value.code == "total_size_exceeded"


def test_compression_ratio_limit_is_enforced(tmp_path: Path) -> None:
    archive_path = tmp_path / "ratio.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", b"a" * 100)

    with pytest.raises(ArchiveLimitError) as excinfo:
        inspect_archive(archive_path, limits=tiny_limits(max_compression_ratio=1.1))

    assert excinfo.value.code == "compression_ratio_exceeded"


def test_encrypted_member_flag_is_rejected(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "encrypted.zip", [("a.txt", b"data")])
    patch_encrypted_flag(archive_path)

    with pytest.raises(ArchiveFormatError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "encrypted_member"


def test_unsupported_compression_is_rejected(tmp_path: Path) -> None:
    if not hasattr(zipfile, "ZIP_BZIP2"):
        pytest.skip("ZIP_BZIP2 is unavailable in this Python build")
    info = zipfile.ZipInfo("a.txt")
    info.compress_type = zipfile.ZIP_BZIP2
    archive_path = write_zipinfo(tmp_path / "bzip2.zip", info)

    with pytest.raises(ArchiveFormatError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "unsupported_compression"


def test_malformed_archive_is_rejected(tmp_path: Path) -> None:
    archive_path = tmp_path / "malformed.zip"
    archive_path.write_bytes(b"not a zip")

    with pytest.raises(ArchiveFormatError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "malformed_archive"


def test_truncated_zip_archive_is_rejected(tmp_path: Path) -> None:
    archive_path = tmp_path / "truncated.zip"
    archive_path.write_bytes(b"PK\x03\x04short")

    with pytest.raises(ArchiveFormatError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "truncated_archive"


def test_zip_symlink_is_rejected(tmp_path: Path) -> None:
    info = zipfile.ZipInfo("link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    archive_path = write_zipinfo(tmp_path / "symlink.zip", info, b"target")

    with pytest.raises(ArchiveSafetyError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "symlink_member"


def test_zip_special_file_is_rejected(tmp_path: Path) -> None:
    info = zipfile.ZipInfo("fifo")
    info.external_attr = (stat.S_IFIFO | 0o600) << 16
    archive_path = write_zipinfo(tmp_path / "fifo.zip", info, b"")

    with pytest.raises(ArchiveSafetyError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "special_member"


@pytest.mark.parametrize("name", ["nested.zip", "bundle.mcpb", "lib.jar", "pkg.whl", "UPPER.ZIP"])
def test_nested_archive_extensions_are_rejected_by_default(tmp_path: Path, name: str) -> None:
    archive_path = write_zip(tmp_path / "nested.zip", [(name, b"not inspected")])

    with pytest.raises(ArchiveSafetyError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "nested_archive"


def test_nested_archive_extension_can_be_allowed(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "nested.zip", [("nested.zip", b"not inspected")])

    result = inspect_archive(archive_path, limits=tiny_limits(allow_nested_archives=True))

    assert result.members[0].is_nested_archive is True
    assert result.members[0].skip_reason == "nested archive retained but not recursively inspected"


def test_duplicate_normalized_paths_are_rejected_from_zip(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "duplicate.zip", [("a//b.txt", b"1"), ("a/b.txt", b"2")])

    with pytest.raises(ArchiveSafetyError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "duplicate_path"


def test_file_used_as_parent_is_rejected_from_zip(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "collision.zip", [("a", b"1"), ("a/b.txt", b"2")])

    with pytest.raises(ArchiveSafetyError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "path_type_collision"


def test_zip_comments_and_benign_extra_fields_are_ignored(tmp_path: Path) -> None:
    archive_path = tmp_path / "comments.zip"
    info = zipfile.ZipInfo("a.txt")
    info.comment = b"ignored member comment"
    info.extra = b"\xfe\xca\x04\x00data"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.comment = b"ignored archive comment"
        archive.writestr(info, b"safe")

    result = inspect_archive(archive_path)

    assert [member.normalized_path for member in result.members] == ["a.txt"]
