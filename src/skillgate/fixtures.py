from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from skillgate.baseline import create_baseline, diff_against_baseline
from skillgate.scan import scan_repository


class FixtureSummaryError(ValueError):
    pass


@dataclass(frozen=True)
class FixtureSummary:
    name: str
    path: str
    expected_rule_ids: list[str]
    actual_rule_ids: list[str]
    diff_rule_ids: list[str]
    status: str

    def to_data(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "expected_rule_ids": self.expected_rule_ids,
            "actual_rule_ids": self.actual_rule_ids,
            "diff_rule_ids": self.diff_rule_ids,
            "status": self.status,
        }


def load_expected_rule_ids(path: Path) -> list[str]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise FixtureSummaryError(f"Unable to load expected findings: {path}") from exc
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list) or not all(isinstance(item, str) for item in findings):
        raise FixtureSummaryError(f"{path} must contain findings as a list of rule IDs")
    return sorted(set(findings))


def fixture_diff_rule_ids(fixture: Path, benchmark_root: Path) -> list[str]:
    if fixture.name != "12-mcp-capability-drift-after":
        return []
    before = benchmark_root / "11-mcp-capability-drift-before"
    if not before.exists():
        raise FixtureSummaryError("MCP drift fixture requires 11-mcp-capability-drift-before")
    baseline = create_baseline(before)
    diff, _report = diff_against_baseline(fixture, baseline)
    return sorted({finding.rule_id for finding in diff.findings})


def summarize_fixture(fixture: Path, benchmark_root: Path) -> FixtureSummary:
    expected_path = fixture / "expected-findings.yaml"
    if not expected_path.exists():
        raise FixtureSummaryError(f"Missing expected findings file: {expected_path}")
    expected = load_expected_rule_ids(expected_path)
    scan_ids = sorted({finding.rule_id for finding in scan_repository(fixture).findings})
    diff_ids = fixture_diff_rule_ids(fixture, benchmark_root)
    actual = sorted(set(scan_ids) | set(diff_ids))
    return FixtureSummary(
        name=fixture.name,
        path=fixture.as_posix(),
        expected_rule_ids=expected,
        actual_rule_ids=scan_ids,
        diff_rule_ids=diff_ids,
        status="pass" if actual == expected else "fail",
    )


def summarize_fixtures(root: Path) -> list[FixtureSummary]:
    if not root.exists() or not root.is_dir():
        raise FixtureSummaryError(f"Fixture path must be a directory: {root}")
    fixtures = [path for path in sorted(root.iterdir()) if path.is_dir()]
    return [summarize_fixture(fixture, root) for fixture in fixtures]


def fixture_summary_payload(root: Path, summaries: list[FixtureSummary]) -> dict[str, object]:
    return {
        "path": root.as_posix(),
        "fixtures": [summary.to_data() for summary in summaries],
        "summary": {
            "fixtures": len(summaries),
            "passed": sum(1 for summary in summaries if summary.status == "pass"),
            "failed": sum(1 for summary in summaries if summary.status == "fail"),
        },
    }


def fixture_summary_text(root: Path, summaries: list[FixtureSummary]) -> str:
    lines = [f"SkillGate fixture summary: {root}", ""]
    for summary in summaries:
        actual = sorted(set(summary.actual_rule_ids) | set(summary.diff_rule_ids))
        lines.append(
            f"{summary.status.upper():<5}  {summary.name}  "
            f"expected={summary.expected_rule_ids} actual={actual}"
        )
    lines.extend(
        [
            "",
            f"Fixtures: {len(summaries)}",
            f"Passed: {sum(1 for summary in summaries if summary.status == 'pass')}",
            f"Failed: {sum(1 for summary in summaries if summary.status == 'fail')}",
        ]
    )
    return "\n".join(lines) + "\n"
