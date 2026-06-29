from __future__ import annotations

from pathlib import Path


class ArchiveError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        archive_path: str | Path | None = None,
        member_path: str | None = None,
        code: str,
        limit: str | None = None,
        observed: object | None = None,
        allowed: object | None = None,
    ) -> None:
        self.archive_path = archive_path
        self.member_path = member_path
        self.code = code
        self.limit = limit
        self.observed = observed
        self.allowed = allowed
        super().__init__(message)

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {"code": self.code, "message": str(self)}
        if self.archive_path is not None:
            data["archive_path"] = _safe_archive_display(self.archive_path)
        if self.member_path is not None:
            data["member_path"] = _safe_member_display(self.member_path)
        if self.limit is not None:
            data["limit"] = self.limit
        if self.observed is not None:
            data["observed"] = self.observed
        if self.allowed is not None:
            data["allowed"] = self.allowed
        return data


class ArchiveFormatError(ArchiveError):
    pass


class ArchiveSafetyError(ArchiveError):
    pass


class ArchiveLimitError(ArchiveError):
    pass


def _safe_archive_display(path: str | Path) -> str:
    return str(path).encode("unicode_escape").decode("ascii")


def _safe_member_display(name: str) -> str:
    return name.encode("unicode_escape").decode("ascii")


def _format_archive_error_message(
    message: str,
    *,
    archive_path: str | Path | None = None,
    member_path: str | None = None,
) -> str:
    parts = [message]
    if archive_path is not None:
        parts.append(f"archive={_safe_archive_display(archive_path)}")
    if member_path is not None:
        parts.append(f"member={_safe_member_display(member_path)}")
    return " (".join([parts[0], ", ".join(parts[1:]) + ")"]) if len(parts) > 1 else message


def archive_error(
    error_type: type[ArchiveError],
    message: str,
    *,
    archive_path: str | Path | None = None,
    member_path: str | None = None,
    code: str,
    limit: str | None = None,
    observed: object | None = None,
    allowed: object | None = None,
) -> ArchiveError:
    return error_type(
        _format_archive_error_message(
            message,
            archive_path=archive_path,
            member_path=member_path,
        ),
        archive_path=archive_path,
        member_path=member_path,
        code=code,
        limit=limit,
        observed=observed,
        allowed=allowed,
    )
