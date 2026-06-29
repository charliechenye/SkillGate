from __future__ import annotations

from typing import Any

from .models import ArchiveInspectionResult

ARCHIVE_SCHEMA_VERSION = "1"


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
