"""Run a local-only, static differential benchmark against Skill-Inject."""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skillgate.models import SEVERITY_ORDER, stable_json
from skillgate.rules import DEFAULT_RULES
from skillgate.scan import finding_key, scan_repository

SCHEMA_VERSION = "1"
INJECTION_FILES = {
    "obvious": "obvious_injections.json",
    "contextual": "contextual_injections.json",
}
CONTROL_CASES = (
    {
        "name": "plain-documentation",
        "text": "This guide explains a reviewed workflow and a Markdown file format.\n",
        "expected_rule_ids": [],
    },
    {
        "name": "ordinary-format-wording",
        "text": "Use the document format that matches the project specification.\n",
        "expected_rule_ids": [],
    },
    {
        "name": "safe-download-instructions",
        "text": (
            "Download the release archive from https://downloads.example.com/release.tar.gz "
            "and verify its checksum before use.\n"
        ),
        "expected_rule_ids": ["SG003"],
    },
    {
        "name": "unrelated-shell-example",
        "text": "After review, run bash scripts/build.sh to produce the checked-in artifact.\n",
        "expected_rule_ids": ["SG001"],
    },
)
RULE_IDS = tuple(rule.rule_id for rule in DEFAULT_RULES)


@dataclass(frozen=True)
class Definition:
    category: str
    definition_id: int
    title: str
    skill: str
    line_number: int
    injection_prefix: str
    injection: str
    prompt: str


class BenchmarkInputError(ValueError):
    """Raised when a local Skill-Inject checkout is incomplete or malformed."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkInputError(f"Unable to read benchmark data: {path}") from exc


def validate_source(source: Path) -> Path:
    source = source.expanduser().resolve()
    required = [
        source / "data" / "skills",
        *(source / "data" / filename for filename in INJECTION_FILES.values()),
    ]
    if not source.is_dir():
        raise BenchmarkInputError(f"Skill-Inject source must be a local directory: {source}")
    missing = [path for path in required if not path.exists()]
    if missing:
        joined = ", ".join(path.as_posix() for path in missing)
        raise BenchmarkInputError(f"Skill-Inject source is missing required paths: {joined}")
    return source


def load_definitions(source: Path) -> list[Definition]:
    definitions: list[Definition] = []
    for category, filename in INJECTION_FILES.items():
        records = load_json(source / "data" / filename)
        if not isinstance(records, list):
            raise BenchmarkInputError(f"{filename} must contain a JSON list")
        for record in records:
            try:
                tasks = record["tasks"]
                task = tasks[0]
                instructions = record["instructions"]
                definitions.append(
                    Definition(
                        category=category,
                        definition_id=int(record["id"]),
                        title=str(record["title"]),
                        skill=str(task["skill"]),
                        line_number=int(task["line_num"]),
                        injection_prefix=str(task.get("injection_prefix", "")),
                        injection=str(instructions["line_injection"]),
                        prompt=str(task["prompt"]),
                    )
                )
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise BenchmarkInputError(
                    f"Malformed {category} injection definition: {record!r}"
                ) from exc
    return sorted(definitions, key=lambda item: (item.category, item.definition_id))


def normalize_name(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def resolve_skill_directory(skills_root: Path, skill_name: str) -> Path:
    directories = sorted({path.parent for path in skills_root.rglob("SKILL.md")})
    normalized = normalize_name(skill_name)
    exact = [path for path in directories if normalize_name(path.name) == normalized]
    if len(exact) == 1:
        return exact[0]

    aliases = {
        "email": "email-api",
        "fhir": "fhir-developer-skill",
    }
    alias = aliases.get(skill_name)
    if alias:
        candidates = [path for path in directories if path.name == alias]
        if len(candidates) == 1:
            return candidates[0]

    candidates = [
        path
        for path in directories
        if normalized in normalize_name(path.name) or normalize_name(path.name) in normalized
    ]
    if len(candidates) == 1:
        return candidates[0]
    names = ", ".join(path.as_posix() for path in candidates) or "none"
    raise BenchmarkInputError(
        f"Unable to resolve Skill-Inject skill {skill_name!r}; candidates: {names}"
    )


def inject_skill(skill_source: Path, target: Path, definition: Definition) -> None:
    shutil.copytree(skill_source, target)
    skill_file = target / "SKILL.md"
    lines = skill_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    insertion = f"{definition.injection_prefix}{definition.injection}"
    if not insertion.endswith("\n"):
        insertion += "\n"
    index = min(max(definition.line_number - 1, 0), len(lines))
    lines.insert(index, insertion)
    skill_file.write_text("".join(lines), encoding="utf-8")


def new_findings(baseline: Any, injected: Any) -> list[Any]:
    baseline_keys = {finding_key(finding) for finding in baseline.findings}
    return [finding for finding in injected.findings if finding_key(finding) not in baseline_keys]


def case_result(source: Path, definition: Definition, temporary_root: Path) -> dict[str, Any]:
    source_skill = resolve_skill_directory(source / "data" / "skills", definition.skill)
    injected_root = temporary_root / "injected"
    temporary_root.mkdir(parents=True, exist_ok=True)
    baseline = scan_repository(source_skill)
    inject_skill(source_skill, injected_root, definition)
    injected = scan_repository(injected_root)
    findings = new_findings(baseline, injected)
    severities = sorted({finding.severity for finding in findings}, key=SEVERITY_ORDER.get)
    rule_counts = Counter(finding.rule_id for finding in findings)
    return {
        "id": f"{definition.category}-{definition.definition_id}",
        "category": definition.category,
        "definition_id": definition.definition_id,
        "title": definition.title,
        "skill": definition.skill,
        "task_prompt": definition.prompt,
        "new_finding_count": len(findings),
        "new_rule_ids": sorted({finding.rule_id for finding in findings}),
        "new_rule_counts": dict(sorted(rule_counts.items())),
        "new_severities": severities,
        "high_or_critical": any(
            SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER["high"] for finding in findings
        ),
        "baseline_findings": len(baseline.findings),
        "injected_findings": len(injected.findings),
    }


def run_injection_benchmark(source: Path) -> dict[str, Any]:
    source = validate_source(source)
    definitions = load_definitions(source)
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="skillgate-skill-inject-") as temporary:
        temporary_root = Path(temporary)
        for definition in definitions:
            case_root = temporary_root / definition.category / str(definition.definition_id)
            results.append(case_result(source, definition, case_root))

    by_category = {}
    for category in INJECTION_FILES:
        category_results = [result for result in results if result["category"] == category]
        by_category[category] = category_summary(category_results)

    rule_case_hits = Counter(rule_id for result in results for rule_id in result["new_rule_ids"])
    rule_finding_counts = Counter()
    for result in results:
        rule_finding_counts.update(result["new_rule_counts"])

    misses = [
        {
            key: result[key]
            for key in ["id", "category", "definition_id", "title", "skill", "task_prompt"]
        }
        for result in results
        if result["new_finding_count"] == 0
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark": "Skill-Inject",
        "scope": {
            "source": source.name,
            "source_mode": "user-provided local checkout",
            "definitions": len(results),
            "representative_tasks_per_definition": 1,
            "pairs_evaluated": len(results),
            "payloads_executed": False,
            "network_access": False,
            "docker_or_agent_runtime": False,
            "measurement": "new static SkillGate findings versus the clean skill copy",
            "injection_accuracy_metrics": "not computed without authored negative controls",
        },
        "summary": {
            "cases_evaluated": len(results),
            "cases_with_any_new_signal": sum(result["new_finding_count"] > 0 for result in results),
            "cases_with_high_or_critical_signal": sum(
                result["high_or_critical"] for result in results
            ),
            "total_new_findings": sum(result["new_finding_count"] for result in results),
            "missed_cases": len(misses),
            "rule_case_hits": dict(sorted(rule_case_hits.items())),
            "rule_new_finding_counts": dict(sorted(rule_finding_counts.items())),
        },
        "categories": by_category,
        "misses": misses,
        "cases": results,
    }


def category_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cases": len(results),
        "cases_with_any_new_signal": sum(result["new_finding_count"] > 0 for result in results),
        "cases_with_high_or_critical_signal": sum(result["high_or_critical"] for result in results),
        "total_new_findings": sum(result["new_finding_count"] for result in results),
    }


def control_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter()
    total = len(results) * len(RULE_IDS)
    for result in results:
        expected = set(result["expected_rule_ids"])
        actual = set(result["actual_rule_ids"])
        for rule_id in RULE_IDS:
            expected_positive = rule_id in expected
            actual_positive = rule_id in actual
            if expected_positive and actual_positive:
                counts["true_positive"] += 1
            elif expected_positive:
                counts["false_negative"] += 1
            elif actual_positive:
                counts["false_positive"] += 1
            else:
                counts["true_negative"] += 1
    true_positive = counts["true_positive"]
    false_positive = counts["false_positive"]
    false_negative = counts["false_negative"]
    precision = (
        true_positive / (true_positive + false_positive) if true_positive + false_positive else 0
    )
    recall = (
        true_positive / (true_positive + false_negative) if true_positive + false_negative else 0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    return {
        "cases": len(results),
        "interpretation": "authored control cases only",
        "rule_universe": list(RULE_IDS),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": counts["true_negative"],
        "accuracy": (true_positive + counts["true_negative"]) / total if total else 0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def run_controls() -> dict[str, Any]:
    results = []
    with tempfile.TemporaryDirectory(prefix="skillgate-controls-") as temporary:
        root = Path(temporary)
        for case in CONTROL_CASES:
            case_root = root / case["name"]
            case_root.mkdir()
            (case_root / "SKILL.md").write_text(case["text"], encoding="utf-8")
            report = scan_repository(case_root)
            results.append(
                {
                    "name": case["name"],
                    "expected_rule_ids": case["expected_rule_ids"],
                    "actual_rule_ids": sorted({finding.rule_id for finding in report.findings}),
                }
            )
    return {"cases": results, "metrics": control_metrics(results)}


def render_markdown(payload: dict[str, Any]) -> str:
    scope = payload["scope"]
    summary = payload["summary"]
    lines = [
        "# SkillGate Skill-Inject Static Benchmark",
        "",
        "This is an opt-in, local-only differential scan. It measures new static SkillGate "
        "signals after inert text injection; it does not measure agent attack success.",
        "",
        f"- Source: `{scope['source']}` (user-provided local checkout)",
        f"- Definitions: {scope['definitions']}",
        f"- Representative tasks per definition: {scope['representative_tasks_per_definition']}",
        f"- Cases with any new signal: {summary['cases_with_any_new_signal']}/"
        f"{summary['cases_evaluated']}",
        f"- Cases with high/critical signal: {summary['cases_with_high_or_critical_signal']}/"
        f"{summary['cases_evaluated']}",
        f"- Total new findings: {summary['total_new_findings']}",
        f"- Missed cases: {summary['missed_cases']}",
        "- Payload execution: no",
        "- Network access: no",
        "- Docker or agent runtime: no",
        "",
        "## Category Summary",
        "",
        "| Category | Cases | Any new signal | High/critical signal | New findings |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for category, data in payload["categories"].items():
        lines.append(
            f"| {category} | {data['cases']} | {data['cases_with_any_new_signal']} | "
            f"{data['cases_with_high_or_critical_signal']} | {data['total_new_findings']} |"
        )
    lines.extend(
        [
            "",
            "## Rule Case Hits",
            "",
            "| Rule | Cases with a new finding |",
            "| --- | ---: |",
        ]
    )
    for rule_id, count in summary["rule_case_hits"].items():
        lines.append(f"| {rule_id} | {count} |")
    lines.extend(["", "## Misses", ""])
    if payload["misses"]:
        for miss in payload["misses"]:
            lines.append(f"- `{miss['id']}` {miss['title']} ({miss['category']})")
    else:
        lines.append("- None")
    controls = payload["controls"]
    metrics = controls["metrics"]
    lines.extend(
        [
            "",
            "## Authored Control Metrics",
            "",
            "These metrics apply only to the small control set with explicit expected rule IDs; "
            "they must not be generalized to Skill-Inject attack success.",
            "",
            f"- Accuracy: `{metrics['accuracy']:.3f}`",
            f"- Precision: `{metrics['precision']:.3f}`",
            f"- Recall: `{metrics['recall']:.3f}`",
            f"- F1: `{metrics['f1']:.3f}`",
            "",
            "## Reproduction",
            "",
            "```bash",
            "uv run python tools/benchmark_skill_inject.py /path/to/local/skill-inject "
            "--format markdown",
            "uv run python tools/benchmark_skill_inject.py /path/to/local/skill-inject "
            "--format json --output skill-inject.json",
            "```",
            "",
            "The benchmark reads only the supplied checkout. It does not fetch updates, execute "
            "task scripts, run the upstream harness, start Docker, or contact model APIs.",
            "",
        ]
    )
    return "\n".join(lines)


def render_text(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    return (
        "SkillGate Skill-Inject static benchmark\n"
        f"Cases: {summary['cases_evaluated']}\n"
        f"Any new signal: {summary['cases_with_any_new_signal']}\n"
        f"High/critical signal: {summary['cases_with_high_or_critical_signal']}\n"
        f"Misses: {summary['missed_cases']}\n"
        "Payload execution: no\n"
        "Network access: no\n"
    )


def build_payload(source: Path) -> dict[str, Any]:
    payload = run_injection_benchmark(source)
    payload["controls"] = run_controls()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a local-only static differential benchmark against Skill-Inject."
    )
    parser.add_argument("source", type=Path, help="Path to a local Skill-Inject checkout.")
    parser.add_argument("--format", choices=["markdown", "json", "text"], default="markdown")
    parser.add_argument("--output", type=Path, help="Write the report to this local path.")
    args = parser.parse_args()
    try:
        payload = build_payload(args.source)
    except BenchmarkInputError as exc:
        parser.error(str(exc))
    if args.format == "json":
        content = stable_json(payload)
    elif args.format == "text":
        content = render_text(payload)
    else:
        content = render_markdown(payload)
    if args.output:
        args.output.write_text(content, encoding="utf-8")
    else:
        print(content, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
