from __future__ import annotations

import fnmatch
import re
from datetime import date
from typing import Any

from skillgate.identity import finding_fingerprint
from skillgate.models import Finding, PolicyViolation

FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FINDING_WAIVER_SELECTOR_KEYS = {
    "id",
    "rule_id",
    "capability",
    "file_path",
    "title",
    "evidence",
    "fingerprint",
}
NARROW_FINDING_SELECTOR_KEYS = {"id", "file_path", "title", "evidence", "fingerprint"}


def is_broad_selector(selector: dict[str, object]) -> bool:
    string_values = [value for value in selector.values() if isinstance(value, str)]
    if not selector or any(value.strip() in {"", "*", "**"} for value in string_values):
        return True
    if "id" in selector or "fingerprint" in selector:
        return False
    if len(selector) < 2:
        return True
    return not bool(NARROW_FINDING_SELECTOR_KEYS & set(selector))


def policy_waiver_entries(policy: dict[str, Any]) -> list[dict[str, Any]]:
    waivers = policy.get("waivers")
    if not isinstance(waivers, dict):
        return []
    entries = waivers.get("entries")
    return (
        [entry for entry in entries if isinstance(entry, dict)] if isinstance(entries, list) else []
    )


def waiver_selector_label(entry: dict[str, Any]) -> str:
    waiver_id = entry.get("id")
    if isinstance(waiver_id, str) and waiver_id:
        return waiver_id
    selector = entry.get("finding")
    if isinstance(selector, dict):
        return ", ".join(f"{key}={value}" for key, value in sorted(selector.items()))
    return "<unknown waiver>"


def waiver_summary(entry: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "id": entry.get("id"),
        "owner": entry.get("owner"),
        "reason": entry.get("reason"),
        "created_on": entry.get("created_on"),
        "expires_on": entry.get("expires_on"),
        "ticket": entry.get("ticket"),
        "finding": entry.get("finding"),
        "selector": waiver_selector_label(entry),
    }
    return {key: value for key, value in summary.items() if value is not None}


def waiver_expires_on(entry: dict[str, Any]) -> date:
    value = entry.get("expires_on")
    return date.fromisoformat(value) if isinstance(value, str) else date.min


def finding_value(finding: Finding, key: str) -> str | None:
    if key == "fingerprint":
        return finding_fingerprint(finding)
    value = getattr(finding, key)
    return value if isinstance(value, str) else None


def finding_matches_waiver(finding: Finding, entry: dict[str, Any]) -> bool:
    selector = entry.get("finding")
    if not isinstance(selector, dict):
        return False
    for key, pattern in selector.items():
        if not isinstance(pattern, str):
            return False
        value = finding_value(finding, key)
        if value is None:
            return False
        if key == "fingerprint":
            if pattern != value:
                return False
            continue
        if not fnmatch.fnmatch(value, pattern):
            return False
    return True


def matching_waiver_for_violation(
    item: PolicyViolation,
    findings_by_id: dict[str, Finding],
    active_waivers: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if item.finding_id is None:
        return None
    finding = findings_by_id.get(item.finding_id)
    if finding is None:
        return None
    for waiver in active_waivers:
        if finding_matches_waiver(finding, waiver):
            return waiver_summary(waiver)
    return None
