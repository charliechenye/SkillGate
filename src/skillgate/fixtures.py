from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from skillgate import __version__
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
    attribution: dict[str, object] | None = None

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "name": self.name,
            "path": self.path,
            "expected_rule_ids": self.expected_rule_ids,
            "actual_rule_ids": self.actual_rule_ids,
            "diff_rule_ids": self.diff_rule_ids,
            "status": self.status,
        }
        if self.attribution is not None:
            data["attribution"] = self.attribution
        return data


def validate_attribution(
    path: Path,
    fixture_name: str,
    data: dict[str, object],
) -> dict[str, object] | None:
    attribution = data.get("attribution")
    if attribution is None:
        if "-public-pattern-" in fixture_name:
            raise FixtureSummaryError(
                f"{path} must contain attribution for public-pattern fixtures"
            )
        return None
    if not isinstance(attribution, dict):
        raise FixtureSummaryError(f"{path} attribution must be a mapping")
    sources = attribution.get("sources")
    if not isinstance(sources, list) or not sources:
        raise FixtureSummaryError(f"{path} attribution.sources must be a non-empty list")
    for source in sources:
        if not isinstance(source, dict):
            raise FixtureSummaryError(f"{path} attribution.sources entries must be mappings")
        for key in ["name", "url"]:
            if not isinstance(source.get(key), str) or not source.get(key):
                raise FixtureSummaryError(f"{path} attribution.sources entries require {key}")
    for key in ["reduction", "retrieved_on"]:
        if not isinstance(attribution.get(key), str) or not attribution.get(key):
            raise FixtureSummaryError(f"{path} attribution.{key} must be a non-empty string")
    return attribution


def load_expected_findings(
    path: Path,
    fixture_name: str,
) -> tuple[list[str], dict[str, object] | None]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise FixtureSummaryError(f"Unable to load expected findings: {path}") from exc
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list) or not all(isinstance(item, str) for item in findings):
        raise FixtureSummaryError(f"{path} must contain findings as a list of rule IDs")
    attribution = validate_attribution(path, fixture_name, data)
    return sorted(set(findings)), attribution


def load_expected_rule_ids(path: Path) -> list[str]:
    findings, _attribution = load_expected_findings(path, path.parent.name)
    return findings


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
    expected, attribution = load_expected_findings(expected_path, fixture.name)
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
        attribution=attribution,
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


def fixture_summary_markdown(root: Path, summaries: list[FixtureSummary]) -> str:
    expected_rules = sorted(
        {rule_id for summary in summaries for rule_id in summary.expected_rule_ids}
    )
    actual_rules = sorted(
        {
            rule_id
            for summary in summaries
            for rule_id in [*summary.actual_rule_ids, *summary.diff_rule_ids]
        }
    )
    lines = [
        "# SkillGate Benchmark Report",
        "",
        f"- Scanner version: `{__version__}`",
        f"- Fixture root: `{root.as_posix()}`",
        f"- Fixtures: {len(summaries)}",
        f"- Passed: {sum(1 for summary in summaries if summary.status == 'pass')}",
        f"- Failed: {sum(1 for summary in summaries if summary.status == 'fail')}",
        "",
        "## Rule Coverage",
        "",
        "| Rule | Expected fixtures | Actual fixtures | Coverage status |",
        "| --- | ---: | ---: | --- |",
    ]
    for rule_id in sorted(set(expected_rules) | set(actual_rules)):
        expected_count = sum(rule_id in summary.expected_rule_ids for summary in summaries)
        actual_count = sum(
            rule_id in summary.actual_rule_ids or rule_id in summary.diff_rule_ids
            for summary in summaries
        )
        status = "covered" if expected_count == actual_count else "mismatch"
        lines.append(f"| {rule_id} | {expected_count} | {actual_count} | {status} |")
    lines.extend(
        [
            "",
            "## Fixture Results",
            "",
            "| Fixture | Status | Expected rules | Actual rules | Attribution |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for summary in summaries:
        actual = sorted(set(summary.actual_rule_ids) | set(summary.diff_rule_ids))
        attribution = "yes" if summary.attribution else "no"
        lines.append(
            f"| `{summary.name}` | **{summary.status}** | "
            f"`{', '.join(summary.expected_rule_ids) or 'none'}` | "
            f"`{', '.join(actual) or 'none'}` | {attribution} |"
        )
    lines.extend(
        [
            "",
            "## Reproduce",
            "",
            "```bash",
            "skillgate fixtures summary fixtures/benchmark --format markdown",
            "```",
            "",
            "## Attribution",
            "",
            "Public-pattern fixtures retain source URLs, retrieval dates, and reduction "
            "notes in their expected-findings metadata.",
            "",
            "## Limitations",
            "",
            "This report verifies deterministic fixture expectations and rule coverage. It "
            "is not a real-world detection accuracy benchmark, malware verdict, or "
            "completeness claim.",
            "Fixtures are intentionally reduced examples and may not represent the "
            "behavior, context, or security posture of their source projects.",
            "",
        ]
    )
    return "\n".join(lines)
