from __future__ import annotations

import hashlib
import os
import shutil
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
    archive_manifest,
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
    assert result.members[0].sha256 is None
    assert result.members[1].sha256 == hashlib.sha256(b"first").hexdigest()
    assert result.members[2].sha256 == hashlib.sha256(b"last").hexdigest()
    assert (result.extraction_root / "a" / "b.txt").read_bytes() == b"first"
    result.cleanup()


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
    result.cleanup()


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
    result.cleanup()


def test_omitted_directory_entries_are_materialized(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "omitted-dir.zip", [("nested/path/file.txt", b"hello")])

    result = inspect_archive(archive_path)

    assert (result.extraction_root / "nested" / "path" / "file.txt").read_bytes() == b"hello"
    assert result.members[0].sha256 == hashlib.sha256(b"hello").hexdigest()
    result.cleanup()


def test_successful_context_manager_removes_temporary_directory(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "context.zip", [("a.txt", b"hello")])

    with inspect_archive(archive_path) as result:
        root = result.extraction_root
        assert root.exists()
        assert (root / "a.txt").exists()

    assert not root.exists()
    assert result.member_count == 1
    result.cleanup()


def test_exception_inside_context_manager_removes_temporary_directory(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "context-error.zip", [("a.txt", b"hello")])

    with pytest.raises(RuntimeError):
        with inspect_archive(archive_path) as result:
            root = result.extraction_root
            raise RuntimeError("caller failed")

    assert not root.exists()


def test_explicit_cleanup_removes_only_result_root(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "cleanup.zip", [("a.txt", b"hello")])
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()

    result = inspect_archive(archive_path)
    root = result.extraction_root
    result.cleanup()
    result.cleanup()

    assert not root.exists()
    assert unrelated.exists()
    assert result.member_count == 1


def test_cleanup_treats_missing_extraction_root_as_success(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "missing-root.zip", [("a.txt", b"hello")])
    result = inspect_archive(archive_path)
    root = result.extraction_root

    shutil.rmtree(root)
    result.cleanup()
    result.cleanup()

    assert result._cleaned_up is True
    assert result.extraction_root == root
    assert not root.exists()
    assert result.member_count == 1


def test_explicit_cleanup_failure_is_stable_and_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = write_zip(tmp_path / "cleanup-failure.zip", [("a.txt", b"hello")])
    result = inspect_archive(archive_path)
    root = result.extraction_root

    def fail_rmtree(path: object) -> None:
        raise OSError("transient cleanup failure")

    monkeypatch.setattr("skillgate.archive.shutil.rmtree", fail_rmtree)

    with pytest.raises(ArchiveFormatError) as excinfo:
        result.cleanup()

    assert excinfo.value.code == "cleanup_failure"
    assert result._cleaned_up is False
    assert str(root) not in str(excinfo.value)
    assert str(root) not in repr(excinfo.value.to_data())


def test_cleanup_retry_after_transient_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = write_zip(tmp_path / "cleanup-retry.zip", [("a.txt", b"hello")])
    result = inspect_archive(archive_path)
    real_rmtree = shutil.rmtree
    calls = 0

    def flaky_rmtree(path: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("transient cleanup failure")
        real_rmtree(path)

    monkeypatch.setattr("skillgate.archive.shutil.rmtree", flaky_rmtree)

    with pytest.raises(ArchiveFormatError):
        result.cleanup()

    assert result._cleaned_up is False

    result.cleanup()

    assert result._cleaned_up is True
    assert not result.extraction_root.exists()
    assert calls == 2


def test_cleanup_failure_on_normal_context_exit_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = write_zip(tmp_path / "context-cleanup-failure.zip", [("a.txt", b"hello")])
    result = inspect_archive(archive_path)
    root = result.extraction_root

    def fail_rmtree(path: object) -> None:
        raise OSError("cleanup failed")

    monkeypatch.setattr("skillgate.archive.shutil.rmtree", fail_rmtree)

    with pytest.raises(ArchiveFormatError) as excinfo:
        with result:
            pass

    assert excinfo.value.code == "cleanup_failure"
    assert result._cleaned_up is False
    assert str(root) not in str(excinfo.value)
    assert str(root) not in repr(excinfo.value.to_data())


def test_cleanup_failure_preserves_context_body_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = write_zip(tmp_path / "context-body-cleanup-failure.zip", [("a.txt", b"hello")])
    result = inspect_archive(archive_path)
    root = result.extraction_root

    def fail_rmtree(path: object) -> None:
        raise OSError("cleanup failed")

    monkeypatch.setattr("skillgate.archive.shutil.rmtree", fail_rmtree)

    with pytest.raises(RuntimeError, match="caller failed") as excinfo:
        with result:
            raise RuntimeError("caller failed")

    notes = getattr(excinfo.value, "__notes__", [])
    assert any("temporary cleanup was incomplete" in note.lower() for note in notes)
    assert str(root) not in " ".join(notes)
    assert result._cleaned_up is False


def test_failed_inspection_cleanup_failure_preserves_original_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = write_zip(
        tmp_path / "nested-cleanup-failure.zip",
        [("payload.bin", b"PK\x03\x04nested")],
    )
    temp_root = tmp_path / "nested-cleanup-temp"
    real_rmtree = shutil.rmtree

    def fail_temp_rmtree(path: object) -> None:
        if Path(path) == temp_root:
            raise OSError("cleanup failed")
        real_rmtree(path)

    monkeypatch.setattr("skillgate.archive.tempfile.mkdtemp", lambda prefix: str(temp_root))
    monkeypatch.setattr("skillgate.archive.shutil.rmtree", fail_temp_rmtree)

    with pytest.raises(ArchiveSafetyError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "nested_archive"
    notes = getattr(excinfo.value, "__notes__", [])
    assert any("temporary cleanup was incomplete" in note.lower() for note in notes)
    assert str(temp_root) not in " ".join(notes)
    assert "cleanup_failure" not in repr(excinfo.value.to_data())


def test_metadata_failure_happens_before_temp_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = write_zip(tmp_path / "unsafe.zip", [("../escape.txt", b"no")])
    called = False

    def fail_mkdtemp(*args: object, **kwargs: object) -> str:
        nonlocal called
        called = True
        raise AssertionError("temp directory should not be created")

    monkeypatch.setattr("skillgate.archive.tempfile.mkdtemp", fail_mkdtemp)

    with pytest.raises(ArchiveSafetyError):
        inspect_archive(archive_path)

    assert called is False


def test_temporary_directory_creation_failure_is_wrapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = write_zip(tmp_path / "temp-failure.zip", [("a.txt", b"hello")])

    def fail_mkdtemp(*args: object, **kwargs: object) -> str:
        raise OSError("no temp")

    monkeypatch.setattr("skillgate.archive.tempfile.mkdtemp", fail_mkdtemp)

    with pytest.raises(ArchiveFormatError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "extraction_failure"


def test_magic_nested_archive_rejection_cleans_temporary_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = write_zip(tmp_path / "magic.zip", [("payload.bin", b"PK\x03\x04nested")])
    temp_root = tmp_path / "skillgate-temp"

    monkeypatch.setattr("skillgate.archive.tempfile.mkdtemp", lambda prefix: str(temp_root))

    with pytest.raises(ArchiveSafetyError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "nested_archive"
    assert not temp_root.exists()


def test_magic_nested_archive_can_be_allowed(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "magic-allowed.zip", [("payload.bin", b"PK\x03\x04nested")])

    result = inspect_archive(archive_path, limits=tiny_limits(allow_nested_archives=True))

    assert result.members[0].is_nested_archive is True
    assert result.members[0].is_scannable_text is False
    assert result.members[0].skip_reason == "nested archive retained but not recursively inspected"
    result.cleanup()


def test_text_and_binary_classification(tmp_path: Path) -> None:
    archive_path = write_zip(
        tmp_path / "classification.zip",
        [("notes.txt", b"hello"), ("image.bin", b"\x00\x01binary")],
    )

    result = inspect_archive(archive_path)
    by_path = {member.normalized_path: member for member in result.members}

    assert by_path["notes.txt"].is_scannable_text is True
    assert by_path["notes.txt"].skip_reason is None
    assert by_path["image.bin"].is_scannable_text is False
    assert by_path["image.bin"].skip_reason == "binary content"
    assert by_path["image.bin"].sha256 == hashlib.sha256(b"\x00\x01binary").hexdigest()
    result.cleanup()


def test_crc_failure_is_wrapped_and_cleaned_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = write_zip(tmp_path / "crc.zip", [("a.txt", b"data")])
    data = bytearray(archive_path.read_bytes())
    offset = data.index(b"data")
    data[offset : offset + 4] = b"DATA"
    archive_path.write_bytes(data)
    temp_root = tmp_path / "crc-temp"
    monkeypatch.setattr("skillgate.archive.tempfile.mkdtemp", lambda prefix: str(temp_root))

    with pytest.raises(ArchiveFormatError) as excinfo:
        inspect_archive(archive_path)

    assert excinfo.value.code == "crc_failure"
    assert not temp_root.exists()


def test_executable_zip_mode_bits_are_not_restored_on_posix(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("POSIX executable-bit check is not meaningful on this platform")
    info = zipfile.ZipInfo("run.sh")
    info.external_attr = (stat.S_IFREG | 0o755) << 16
    archive_path = write_zipinfo(tmp_path / "mode.zip", info, b"echo hello")

    result = inspect_archive(archive_path)

    mode = (result.extraction_root / "run.sh").stat().st_mode
    assert mode & stat.S_IXUSR == 0
    result.cleanup()


def test_manifest_excludes_archive_original_and_temp_paths(tmp_path: Path) -> None:
    archive_path = write_zip(tmp_path / "manifest.zip", [("dir/file.txt", b"hello")])
    result = inspect_archive(archive_path)
    root = result.extraction_root

    manifest = archive_manifest(result)
    rendered = repr(manifest)

    assert "original_path" not in rendered
    assert str(root) not in rendered
    assert str(archive_path) not in rendered
    assert manifest["members"][0]["path"] == "dir/file.txt"
    result.cleanup()
    assert archive_manifest(result) == manifest


def test_repeated_inspections_produce_identical_manifests(tmp_path: Path) -> None:
    archive_path = write_zip(
        tmp_path / "repeat.zip",
        [("b.txt", b"second"), ("a.txt", b"first")],
    )

    first = inspect_archive(archive_path)
    second = inspect_archive(archive_path)
    try:
        assert archive_manifest(first) == archive_manifest(second)
    finally:
        first.cleanup()
        second.cleanup()


def test_manifest_members_are_sorted_deterministically(tmp_path: Path) -> None:
    archive_path = write_zip(
        tmp_path / "sorted.zip",
        [("z.txt", b"last"), ("a.txt", b"first"), ("m.txt", b"middle")],
    )

    result = inspect_archive(archive_path)

    assert [member["path"] for member in archive_manifest(result)["members"]] == [
        "a.txt",
        "m.txt",
        "z.txt",
    ]
    result.cleanup()


def test_manifest_uses_stable_ratio_rounding(tmp_path: Path) -> None:
    archive_path = tmp_path / "ratio-manifest.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", b"a" * 257)

    result = inspect_archive(archive_path)
    member = result.members[0]
    manifest_member = archive_manifest(result)["members"][0]

    assert manifest_member["compression_ratio"] == round(member.compression_ratio or 0.0, 4)
    result.cleanup()


def test_manifest_represents_binary_and_nested_members_deterministically(tmp_path: Path) -> None:
    archive_path = write_zip(
        tmp_path / "mixed.zip",
        [("payload.bin", b"\x00binary"), ("nested.bin", b"PK\x03\x04nested")],
    )

    first = inspect_archive(archive_path, limits=tiny_limits(allow_nested_archives=True))
    second = inspect_archive(archive_path, limits=tiny_limits(allow_nested_archives=True))
    try:
        manifest = archive_manifest(first)
        by_path = {member["path"]: member for member in manifest["members"]}
        assert by_path["payload.bin"]["scannable_text"] is False
        assert by_path["payload.bin"]["skip_reason"] == "binary content"
        assert by_path["nested.bin"]["nested_archive"] is True
        assert by_path["nested.bin"]["skip_reason"] == (
            "nested archive retained but not recursively inspected"
        )
        assert manifest == archive_manifest(second)
    finally:
        first.cleanup()
        second.cleanup()
