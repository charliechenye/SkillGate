"""Bounded, source-preserving logical text views for format-aware scanning."""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_LOGICAL_LINES = 8
MAX_LOGICAL_BYTES = 4 * 1024
SCRIPT_SUFFIXES = {".sh", ".bash", ".py", ".js", ".ts", ".mjs", ".cjs", ".ps1"}


@dataclass(frozen=True)
class LogicalSpan:
    """A bounded derived view mapped back to physical source lines."""

    text: str
    start_line: int
    end_line: int
    evidence: str
    reason: str


def _physical_lines(text: str) -> list[str]:
    lines = text.splitlines(keepends=True)
    if not lines and text:
        return [text]
    return lines


def _line_text(line: str, *, first: bool = False) -> str:
    value = line.rstrip("\r\n")
    return value.removeprefix("\ufeff") if first else value


def _bounded_span(
    lines: list[str], start: int, end: int, normalized: str, reason: str
) -> LogicalSpan | None:
    if end <= start or end - start > MAX_LOGICAL_LINES:
        return None
    normalized = normalized.strip()
    if not normalized or len(normalized.encode("utf-8")) > MAX_LOGICAL_BYTES:
        return None
    return LogicalSpan(
        text=normalized,
        start_line=start + 1,
        end_line=end,
        evidence="".join(lines[start:end]),
        reason=reason,
    )


def _script_continuation(line: str) -> bool:
    stripped = line.rstrip()
    if not stripped:
        return False
    if stripped.endswith("\\"):
        return True
    return bool(re.search(r"(?:&&|\|\||\||,|[([{])$", stripped))


def _delimiter_balance(lines: list[str], start: int, end: int) -> int:
    value = "\n".join(_line_text(line, first=start == 0) for line in lines[start:end])
    pairs = {"(": ")", "[": "]", "{": "}"}
    balance = 0
    for character in value:
        if character in pairs:
            balance += 1
        elif character in pairs.values():
            balance = max(0, balance - 1)
    return balance


def _script_spans(lines: list[str]) -> list[LogicalSpan]:
    spans: list[LogicalSpan] = []
    for start in range(len(lines) - 1):
        if not _script_continuation(_line_text(lines[start], first=start == 0)) and not (
            _delimiter_balance(lines, start, start + 1) > 0
        ):
            continue
        end = start + 1
        while end < len(lines) and end - start <= MAX_LOGICAL_LINES:
            if not _line_text(lines[end]).strip():
                break
            previous = _line_text(lines[end - 1])
            needs_next = _script_continuation(previous) or _delimiter_balance(lines, start, end) > 0
            if end > start + 1 and not needs_next:
                break
            end += 1
        if end <= start + 1:
            continue
        normalized_lines = []
        for index in range(start, end):
            value = _line_text(lines[index], first=index == 0).strip()
            if value.endswith("\\"):
                value = value[:-1].rstrip()
            normalized_lines.append(value)
        span = _bounded_span(lines, start, end, " ".join(normalized_lines), "script-continuation")
        if span:
            spans.append(span)
    return spans


_MARKDOWN_BOUNDARY_RE = re.compile(r"^(?:#{1,6}\s|```|~~~|[-*+]\s+|\d+[.)]\s+|>|\|)")


def _markdown_plain(line: str) -> bool:
    stripped = line.strip()
    return (
        bool(stripped)
        and not _MARKDOWN_BOUNDARY_RE.match(stripped)
        and not line.startswith(("    ", "\t"))
    )


def _markdown_spans(lines: list[str]) -> list[LogicalSpan]:
    spans: list[LogicalSpan] = []
    index = 0
    in_fence = False
    while index < len(lines):
        current = _line_text(lines[index], first=index == 0)
        if current.strip().startswith(("```", "~~~")):
            in_fence = not in_fence
            index += 1
            continue
        if in_fence or not _markdown_plain(current):
            index += 1
            continue
        start = index
        while index < len(lines):
            current = _line_text(lines[index])
            if current.strip().startswith(("```", "~~~")) or not _markdown_plain(current):
                break
            index += 1
        if index - start < 2:
            continue
        chunk_start = start
        while chunk_start < index - 1:
            chunk_end = min(index, chunk_start + MAX_LOGICAL_LINES)
            normalized = " ".join(
                _line_text(lines[item], first=item == 0).strip()
                for item in range(chunk_start, chunk_end)
            )
            span = _bounded_span(lines, chunk_start, chunk_end, normalized, "markdown-paragraph")
            if span:
                spans.append(span)
            if chunk_end == index:
                break
            chunk_start = chunk_end - 1
    return spans


def iter_logical_spans(text: str, file_type: str) -> list[LogicalSpan]:
    """Return bounded derived spans; raw physical lines are never replaced."""

    lines = _physical_lines(text)
    if len(lines) < 2:
        return []
    if file_type == "markdown":
        candidates = _markdown_spans(lines)
    elif file_type == "script":
        candidates = _script_spans(lines)
    else:
        candidates = []
    unique = {(span.start_line, span.end_line, span.text, span.reason): span for span in candidates}
    return [unique[key] for key in sorted(unique)]
