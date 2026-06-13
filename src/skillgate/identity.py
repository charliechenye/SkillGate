from __future__ import annotations

import hashlib
import json
import re
from typing import Any

TOKEN_LIKE_RE = re.compile(
    r"(?i)(token|secret|password|passwd|api[_-]?key|authorization)(\s*[:=]\s*)([^\s,;]+)"
)
WHITESPACE_RE = re.compile(r"\s+")


def normalized_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def normalized_evidence(value: str | None) -> str | None:
    if value is None:
        return None
    redacted = TOKEN_LIKE_RE.sub(r"\1\2<redacted>", value)
    return WHITESPACE_RE.sub(" ", redacted).strip()


def finding_fingerprint(finding: Any) -> str:
    payload = {
        "capability": getattr(finding, "capability", None),
        "evidence": normalized_evidence(getattr(finding, "evidence", None)),
        "file_path": normalized_path(str(getattr(finding, "file_path", ""))),
        "rule_id": getattr(finding, "rule_id", None),
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"
