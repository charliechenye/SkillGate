"""Stable, redacted review packets for pre-install decisions."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from skillgate import __version__
from skillgate.inventory import normalized_resource, trust_boundary_for
from skillgate.models import (
    SEVERITY_ORDER,
    Capability,
    Finding,
    ScanReport,
    model_to_data,
    stable_json,
)

PREINSTALL_PACKET_SCHEMA_VERSION = "1"
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:token|secret|password|credential|api[_-]?key|access[_-]?key)\b\s*[:=]\s*)([^\s,;]+)"
)


def _redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.username and not parsed.password:
        return value
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit(
        (parsed.scheme, "[REDACTED]@" + host, parsed.path, parsed.query, parsed.fragment)
    )


def _redact_text(value: str) -> str:
    value = _redact_url(value)
    return _SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]", value)


def _redact_path(value: str | None, root: str | None = None) -> str | None:
    if value is None:
        return None
    normalized = value.replace("\\", "/")
    if root:
        root_path = Path(root).expanduser()
        try:
            candidate = Path(normalized)
            if candidate.is_absolute():
                return candidate.relative_to(root_path).as_posix()
        except ValueError:
            pass
    if Path(normalized).is_absolute():
        return f"<local>/{Path(normalized).name}"
    return normalized


def _source_record(source: dict[str, Any], root: str | None) -> dict[str, Any]:
    reference = str(source.get("reference", ""))
    record = {
        "kind": source.get("kind", "unknown"),
        "reference": (
            _redact_path(reference, root)
            if source.get("kind") == "local"
            else _redact_url(reference)
        ),
    }
    if source.get("path") is not None:
        record["path"] = _redact_path(str(source["path"]), root)
    for key in ("revision", "subpath", "digest"):
        if source.get(key) is not None:
            record[key] = _redact_text(str(source[key]))
    if source.get("metadata"):
        record["metadata"] = _redact_mapping(source["metadata"], root)
    return record


def _redact_mapping(value: Any, root: str | None = None, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            str(name): _redact_mapping(item, root, str(name))
            for name, item in sorted(value.items())
        }
    if isinstance(value, list):
        return [_redact_mapping(item, root, key) for item in value]
    if isinstance(value, str):
        lowered_key = key.lower()
        if any(token in lowered_key for token in ("token", "secret", "password", "credential")):
            return "[REDACTED]"
        if any(token in key.lower() for token in ("path", "file", "root")):
            return _redact_path(value, root)
        return _redact_text(value)
    return value


def _finding_record(finding: Finding | dict[str, Any], root: str | None = None) -> dict[str, Any]:
    data = model_to_data(finding)
    return {
        "id": data.get("id"),
        "rule_id": data.get("rule_id") or data.get("code"),
        "title": _redact_text(str(data.get("title", ""))),
        "severity": data.get("severity", "informational"),
        "capability": data.get("capability"),
        "file_path": _redact_path(data.get("file_path"), root),
        "line_number": data.get("line_number"),
        "evidence": _redact_text(str(data["evidence"])) if data.get("evidence") else None,
        "remediation": _redact_text(str(data["remediation"])) if data.get("remediation") else None,
    }


def _capability_record(
    capability: Capability | dict[str, Any], root: str | None = None
) -> dict[str, Any]:
    data = model_to_data(capability)
    return {
        "type": data.get("type"),
        "resource": _redact_text(normalized_resource(data.get("resource")) or ""),
        "source_file": _redact_path(data.get("source_file"), root),
        "source_line": data.get("source_line"),
        "trust_boundary": trust_boundary_for(data.get("type", "")) or "other",
    }


def _severity_groups(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped = {severity: [] for severity in SEVERITY_ORDER}
    for finding in findings:
        grouped.setdefault(finding["severity"], []).append(finding)
    for values in grouped.values():
        values.sort(
            key=lambda item: (
                SEVERITY_ORDER.get(item["severity"], -1),
                item["rule_id"] or "",
                item["file_path"] or "",
            )
        )
    return grouped


def build_preinstall_packet(
    source: dict[str, Any],
    scan_report: ScanReport | dict[str, Any] | None = None,
    skills_payload: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic review packet from scan and validation results."""
    report_data = model_to_data(scan_report) if scan_report is not None else {}
    root = report_data.get("scan_root") if report_data else source.get("path")
    findings = [_finding_record(item, root) for item in report_data.get("findings", [])]
    skill_findings = []
    if skills_payload:
        skill_findings = [
            _finding_record(item, skills_payload.get("root"))
            for item in skills_payload.get("findings", [])
        ]
    all_findings = sorted(
        [*findings, *skill_findings],
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], -1),
            item["rule_id"] or "",
            item["file_path"] or "",
            item["line_number"] or 0,
        ),
    )
    grouped = _severity_groups(all_findings)
    counts = {severity: len(grouped[severity]) for severity in SEVERITY_ORDER}
    source_kind = source.get("kind", "unknown")
    next_actions = [
        "Review each high or critical finding before installation.",
        "Confirm that endpoints, secret references, and startup behavior are expected.",
        "Use `skillgate check` or `skillgate diff` when this review becomes "
        "an enforcement decision.",
    ]
    if not all_findings:
        next_actions.insert(
            0, "No static findings were produced; continue with normal maintainer review."
        )
    limitations = [
        "This is deterministic static analysis, not a malware verdict or runtime proof.",
        "SkillGate does not execute code, install packages, start servers, or invoke an agent.",
        "Findings identify review signals; they do not establish maintainer intent "
        "or exploitability.",
    ]
    packet = {
        "packet_type": "preinstall_review",
        "schema_version": PREINSTALL_PACKET_SCHEMA_VERSION,
        "tool_version": __version__,
        "source": _source_record(source, root),
        "metadata": _redact_mapping(metadata or {}, root),
        "capabilities": [
            _capability_record(item, root) for item in report_data.get("capabilities", [])
        ],
        "findings": {
            "total": len(all_findings),
            "by_severity": counts,
            "groups": grouped,
        },
        "skills": {
            "validated": skills_payload is not None,
            "summary": _redact_mapping(
                (skills_payload or {}).get("summary", {}),
                skills_payload.get("root") if skills_payload else root,
            ),
            "findings": skill_findings,
        },
        "reviewer": {
            "decision": "review_required" if all_findings else "no_findings",
            "next_actions": next_actions,
            "limitations": limitations,
            "no_execution": True,
            "network_access": source_kind == "github",
        },
    }
    return _redact_mapping(packet, root)


def preinstall_packet_json(packet: dict[str, Any]) -> str:
    return stable_json(packet)


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    if not rows:
        return ["None."]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(item or "").replace("|", "\\|") for item in row) + " |")
    return lines


def render_preinstall_markdown(packet: dict[str, Any]) -> str:
    source = packet["source"]
    findings = packet["findings"]
    lines = [
        "# SkillGate Pre-install Review",
        "",
        f"- Source: `{source['reference']}`",
        f"- Kind: `{source['kind']}`",
        f"- Decision: **{packet['reviewer']['decision']}**",
        f"- Tool version: `{packet['tool_version']}`",
        "",
        "## Capability Inventory",
        *(
            _table(
                ["Capability", "Resource", "Trust boundary", "Source"],
                [
                    [
                        item["type"],
                        item["resource"],
                        item["trust_boundary"],
                        f"{item['source_file']}:{item['source_line'] or 1}",
                    ]
                    for item in packet["capabilities"]
                ],
            )
        ),
        "",
        "## Findings By Severity",
        *(
            _table(
                ["Severity", "Rule", "Title", "Source"],
                [
                    [
                        item["severity"],
                        item["rule_id"],
                        item["title"],
                        f"{item['file_path']}:{item['line_number'] or 1}",
                    ]
                    for item in sum(findings["groups"].values(), [])
                ],
            )
        ),
        "",
        "## Agent Skills Validation",
        f"Validated: **{packet['skills']['validated']}**",
        "",
        *(
            _table(
                ["Severity", "Rule", "Title", "Source"],
                [
                    [
                        item["severity"],
                        item["rule_id"],
                        item["title"],
                        f"{item['file_path']}:{item['line_number'] or 1}",
                    ]
                    for item in packet["skills"]["findings"]
                ],
            )
        ),
        "",
        "## Reviewer Next Actions",
        *[f"- {item}" for item in packet["reviewer"]["next_actions"]],
        "",
        "## Limitations",
        *[f"- {item}" for item in packet["reviewer"]["limitations"]],
        "",
        "No code was executed by the packet renderer.",
    ]
    return "\n".join(lines) + "\n"
