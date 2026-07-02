from __future__ import annotations

from pathlib import Path

CONTENT_PREFIX_BYTES = 4096
NESTED_ARCHIVE_EXTENSIONS = {".zip", ".mcpb", ".jar", ".whl"}
ZIP_MAGIC_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
TEXT_NAMES = {
    "SKILL.md",
    "AGENTS.md",
    "CLAUDE.md",
    "mcp.json",
    ".mcp.json",
    "mcp-registry.json",
    "mcp-server.json",
    "package.json",
    "pyproject.toml",
    "uv.lock",
    "yarn.lock",
}
TEXT_EXTENSIONS = {
    ".bash",
    ".cjs",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}


def classify_archive_member(normalized_path: str, prefix: bytes) -> tuple[bool, str | None]:
    if b"\x00" in prefix:
        return False, "binary content"
    name = Path(normalized_path).name
    suffix = Path(normalized_path).suffix.lower()
    if name not in TEXT_NAMES and suffix not in TEXT_EXTENSIONS:
        return False, "unsupported file type"
    try:
        prefix.decode("utf-8")
    except UnicodeDecodeError:
        return False, "binary content"
    return True, None


def _is_nested_archive_path(normalized_path: str) -> bool:
    return Path(normalized_path).suffix.lower() in NESTED_ARCHIVE_EXTENSIONS


def _has_zip_magic(prefix: bytes) -> bool:
    return any(prefix.startswith(magic) for magic in ZIP_MAGIC_PREFIXES)
