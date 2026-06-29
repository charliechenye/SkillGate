from __future__ import annotations

import pytest

from skillgate.archive import (
    DEFAULT_ARCHIVE_LIMITS,
    ArchiveLimitError,
    ArchiveLimits,
    ArchiveSafetyError,
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
        "max_path_length": 20,
        "allow_nested_archives": False,
    }
    values.update(overrides)
    return ArchiveLimits(**values)


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
        normalize_archive_member_path("a" * 21, is_dir=False, limits=tiny_limits())

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


def test_validate_archive_member_paths_rejects_file_as_parent() -> None:
    with pytest.raises(ArchiveSafetyError) as excinfo:
        validate_archive_member_paths([("a", "file"), ("a/b.txt", "file")])

    assert excinfo.value.code == "path_type_collision"


def test_validate_archive_member_paths_rejects_directory_prefix_collision() -> None:
    with pytest.raises(ArchiveSafetyError) as excinfo:
        validate_archive_member_paths([("a", "directory"), ("a/b.txt", "file")])

    assert excinfo.value.code == "path_type_collision"


def test_error_messages_escape_control_characters() -> None:
    with pytest.raises(ArchiveLimitError) as excinfo:
        normalize_archive_member_path(
            "safe\nname", is_dir=False, limits=tiny_limits(max_path_length=4)
        )

    message = str(excinfo.value)
    assert "\n" not in message
    assert "\\n" in message
