from __future__ import annotations

from pathlib import Path

from skillgate.archive import ArchiveError

MAX_MCPB_MANIFEST_BYTES = 1_048_576
MCPB_FATAL_CODES = {
    "mcpb_manifest_missing",
    "mcpb_manifest_too_large",
    "mcpb_manifest_invalid_utf8",
    "mcpb_manifest_invalid_json",
    "mcpb_manifest_duplicate_key",
    "mcpb_manifest_invalid_shape",
    "mcpb_entry_point_unsafe",
    "mcpb_reference_unsafe",
}


class McpbError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        code: str,
        manifest_path: str | None = None,
        field_path: str | None = None,
        member_path: str | None = None,
        limit: str | None = None,
        observed: object | None = None,
        allowed: object | None = None,
    ) -> None:
        self.code = code
        self.manifest_path = manifest_path
        self.field_path = field_path
        self.member_path = member_path
        self.limit = limit
        self.observed = observed
        self.allowed = allowed
        super().__init__(message)

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "code": self.code,
            "message": _safe_display(str(self)),
        }
        if self.manifest_path is not None:
            data["manifest_path"] = _safe_display(self.manifest_path)
        if self.field_path is not None:
            data["field_path"] = _safe_display(self.field_path)
        if self.member_path is not None:
            data["member_path"] = _safe_display(self.member_path)
        if self.limit is not None:
            data["limit"] = self.limit
        if self.observed is not None:
            data["observed"] = self.observed
        if self.allowed is not None:
            data["allowed"] = self.allowed
        return data


def _safe_display(value: str | Path) -> str:
    return str(value).encode("unicode_escape").decode("ascii")


def sanitized_archive_message(exc: ArchiveError) -> str:
    context: list[str] = []
    if exc.archive_path is not None:
        context.append(f"archive={_safe_display(exc.archive_path)}")
    if exc.member_path is not None:
        context.append(f"member={_safe_display(exc.member_path)}")
    message = str(exc)
    suffix = f" ({', '.join(context)})" if context else ""
    if suffix and message.endswith(suffix):
        return message[: -len(suffix)]
    return message


def mcpb_archive_error_data(exc: ArchiveError) -> dict[str, object]:
    data: dict[str, object] = {
        "code": exc.code,
        "message": sanitized_archive_message(exc),
    }
    if exc.member_path is not None:
        data["member_path"] = _safe_display(exc.member_path)
    if exc.limit is not None:
        data["limit"] = exc.limit
    if exc.observed is not None:
        data["observed"] = exc.observed
    if exc.allowed is not None:
        data["allowed"] = exc.allowed
    return data
