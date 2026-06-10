from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from skillgate.cli import validate_fail_on, validate_format, validate_severity  # noqa: E402
from skillgate.models import severity_at_or_above, stable_json  # noqa: E402
from skillgate.reporting import scan_text  # noqa: E402
from skillgate.scan import filter_report_by_severity, scan_repository  # noqa: E402
from skillgate.sources import installed_skill_roots  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan installed Codex skills without installing SkillGate."
    )
    parser.add_argument("--root", action="append", type=Path, help="Skill root to scan.")
    parser.add_argument("--format", default="text", choices=["text", "json"], help="Output format.")
    parser.add_argument(
        "--severity",
        choices=["informational", "low", "medium", "high", "critical"],
        help="Only show findings at or above this severity.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["medium", "high", "critical"],
        help="Exit 1 when displayed findings are at or above this severity.",
    )
    return parser.parse_args()


def report_failed(report, fail_on: str | None) -> bool:
    if fail_on is None:
        return False
    return any(severity_at_or_above(finding.severity, fail_on) for finding in report.findings)


def main() -> int:
    args = parse_args()
    output_format = validate_format(args.format, {"text", "json"})
    severity = validate_severity(args.severity)
    fail_on = validate_fail_on(args.fail_on)
    roots = args.root or installed_skill_roots()
    existing_roots = [root for root in roots if root.exists()]
    skipped_roots = [root for root in roots if not root.exists()]

    reports = [
        filter_report_by_severity(scan_repository(root), severity)
        for root in sorted(existing_roots)
    ]
    failed = any(report_failed(report, fail_on) for report in reports)

    if output_format == "json":
        payload = {
            "roots": [
                {
                    "path": str(root),
                    "report": report,
                }
                for root, report in zip(sorted(existing_roots), reports, strict=True)
            ],
            "skipped_roots": [str(root) for root in skipped_roots],
            "summary": {
                "roots": len(reports),
                "skipped_roots": len(skipped_roots),
                "findings": sum(int(report.summary["findings"]) for report in reports),
                "failed": failed,
            },
        }
        sys.stdout.write(stable_json(payload))
    else:
        lines = ["SkillGate installed skills scan", ""]
        if skipped_roots:
            lines.append("Skipped missing roots:")
            lines.extend(f"- {root}" for root in skipped_roots)
            lines.append("")
        if not reports:
            lines.append("No installed skill roots found.")
        for root, report in zip(sorted(existing_roots), reports, strict=True):
            lines.append(f"Root: {root}")
            lines.append(scan_text(report).rstrip())
            lines.append("")
        total_findings = sum(int(report.summary["findings"]) for report in reports)
        lines.append(f"Totals: roots={len(reports)} findings={total_findings}")
        if failed:
            lines.append(f"FAILED: installed skills scan found findings at or above {fail_on}")
        sys.stdout.write("\n".join(lines).rstrip() + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
