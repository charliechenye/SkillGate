from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from skillgate.baseline import create_baseline, diff_against_baseline, load_baseline, save_baseline
from skillgate.models import SEVERITY_ORDER, severity_at_or_above, stable_json
from skillgate.policy import evaluate_policy, load_policy
from skillgate.reporting import (
    append_scan_failure_text,
    check_text,
    diff_text,
    render_diff,
    render_scan,
    write_or_print,
)
from skillgate.rule_docs import RULE_DOCS, get_rule_doc, rule_doc_to_data, rule_docs_to_data
from skillgate.scan import filter_report_by_severity, scan_repository
from skillgate.sources import SourceError, fetch_github_sparse

app = typer.Typer(help="Trust checks for AI-agent skills and MCP configurations.")
baseline_app = typer.Typer(help="Create and manage approved SkillGate baselines.")
github_app = typer.Typer(help="Scan remote GitHub repositories before installing skills.")
rules_app = typer.Typer(help="Inspect SkillGate rule documentation.")
app.add_typer(baseline_app, name="baseline")
app.add_typer(github_app, name="github")
app.add_typer(rules_app, name="rules")
console = Console()


def validate_format(value: str, allowed: set[str]) -> str:
    if value not in allowed:
        raise typer.BadParameter(f"expected one of: {', '.join(sorted(allowed))}")
    return value


def validate_severity(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.lower()
    if normalized not in SEVERITY_ORDER:
        raise typer.BadParameter(
            f"expected one of: {', '.join(SEVERITY_ORDER)}",
            param_hint="--severity",
        )
    return normalized


def validate_fail_on(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.lower()
    allowed = {"medium", "high", "critical"}
    if normalized not in allowed:
        raise typer.BadParameter(
            f"expected one of: {', '.join(sorted(allowed))}",
            param_hint="--fail-on",
        )
    return normalized


def scan_failed(report, fail_on: str | None) -> bool:
    if fail_on is None:
        return False
    return any(severity_at_or_above(finding.severity, fail_on) for finding in report.findings)


def render_scan_command_output(report, output_format: str, fail_on: str | None) -> tuple[str, bool]:
    failed = scan_failed(report, fail_on)
    content = render_scan(report, output_format)
    if failed and output_format == "text":
        content = append_scan_failure_text(content, fail_on or "")
    return content, failed


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Repository path to scan.")] = Path("."),
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "text",
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity",
            help="Only show findings at or above this severity.",
        ),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit 1 when displayed findings are at or above this severity.",
        ),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to a file.")
    ] = None,
) -> None:
    """Scan a repository and report detected capabilities and findings."""
    output_format = validate_format(output_format, {"text", "json", "sarif"})
    severity = validate_severity(severity)
    fail_on = validate_fail_on(fail_on)
    report = filter_report_by_severity(scan_repository(path), severity)
    content, failed = render_scan_command_output(report, output_format, fail_on)
    write_or_print(content, output, console)
    raise typer.Exit(1 if failed else 0)


@github_app.command("scan")
def github_scan(
    url: Annotated[str, typer.Argument(help="GitHub repository URL to scan.")],
    ref: Annotated[str | None, typer.Option("--ref", help="Git ref to scan.")] = None,
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "text",
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity",
            help="Only show findings at or above this severity.",
        ),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit 1 when displayed findings are at or above this severity.",
        ),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to a file.")
    ] = None,
) -> None:
    """Sparse-scan a public GitHub repository before installing skills."""
    output_format = validate_format(output_format, {"text", "json", "sarif"})
    severity = validate_severity(severity)
    fail_on = validate_fail_on(fail_on)
    try:
        sparse = fetch_github_sparse(url, ref)
        report = filter_report_by_severity(scan_repository(sparse.root), severity)
        content, failed = render_scan_command_output(report, output_format, fail_on)
        write_or_print(content, output, console)
        raise typer.Exit(1 if failed else 0)
    except SourceError as exc:
        console.file.write(f"Error: {exc}\n")
        raise typer.Exit(2) from exc
    finally:
        if "sparse" in locals():
            sparse.cleanup()


@rules_app.command("list")
def rules_list(
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "text",
) -> None:
    """List supported SkillGate rules."""
    output_format = validate_format(output_format, {"text", "json"})
    if output_format == "json":
        console.file.write(stable_json({"rules": rule_docs_to_data()}))
        return
    lines = [
        f"{'Rule':<6}  {'Severity':<13}  {'Capability':<28}  {'Title':<58}  Remediation",
        "-" * 140,
    ]
    for rule in RULE_DOCS:
        lines.append(
            f"{rule.rule_id:<6}  {rule.severity:<13}  {rule.capability:<28}  "
            f"{rule.title:<58}  {rule.remediation}"
        )
    console.file.write("\n".join(lines) + "\n")


@app.command()
def explain(
    rule_id: Annotated[str, typer.Argument(help="Rule ID to explain, such as SG004.")],
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "text",
) -> None:
    """Explain a SkillGate rule."""
    output_format = validate_format(output_format, {"text", "json"})
    rule = get_rule_doc(rule_id)
    if rule is None:
        console.print(f"Unknown rule ID: {rule_id.upper()}")
        raise typer.Exit(2)
    if output_format == "json":
        console.file.write(stable_json(rule_doc_to_data(rule)))
        return
    lines = [
        f"{rule.rule_id}: {rule.title}",
        "",
        f"Severity: {rule.severity}",
        f"Capability: {rule.capability}",
        "",
        rule.description,
        "",
        "Examples:",
        *[f"- {example}" for example in rule.examples],
        "",
        f"Remediation: {rule.remediation}",
    ]
    console.file.write("\n".join(lines) + "\n")


@app.command()
def check(
    path: Annotated[Path, typer.Argument(help="Repository path to check.")] = Path("."),
    policy: Annotated[Path, typer.Option("--policy", help="Policy YAML file.")] = Path(
        "skillgate.yaml"
    ),
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "text",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to a file.")
    ] = None,
) -> None:
    """Scan a repository and enforce a SkillGate policy."""
    output_format = validate_format(output_format, {"text", "json", "sarif"})
    try:
        policy_data = load_policy(policy)
    except ValueError as exc:
        console.file.write(f"Error: {exc}\n")
        raise typer.Exit(2) from exc
    report = scan_repository(path)
    result = evaluate_policy(report, policy_data)
    if output_format == "text":
        content = check_text(result)
    else:
        content = render_scan(report, output_format)
        if output_format == "json":
            content = stable_json({"policy_result": result, "scan_report": report})
    write_or_print(content, output, console)
    raise typer.Exit(1 if result.blocked else 0)


@baseline_app.command("create")
def baseline_create(
    path: Annotated[Path, typer.Argument(help="Repository path to baseline.")] = Path("."),
    output: Annotated[Path, typer.Option("--output", "-o", help="Baseline lockfile path.")] = Path(
        "skillgate.lock"
    ),
) -> None:
    """Create an approved SkillGate baseline lockfile."""
    lock = create_baseline(path)
    save_baseline(lock, output)
    console.print(
        f"Created baseline: {output} "
        f"({len(lock.files)} files, {len(lock.capabilities)} capabilities)"
    )


@app.command()
def diff(
    path: Annotated[Path, typer.Argument(help="Repository path to compare.")] = Path("."),
    baseline: Annotated[Path, typer.Option("--baseline", help="Baseline lockfile path.")] = Path(
        "skillgate.lock"
    ),
    policy: Annotated[
        Path | None, typer.Option("--policy", help="Optional policy YAML file.")
    ] = None,
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "text",
) -> None:
    """Compare a repository against an approved baseline."""
    output_format = validate_format(output_format, {"text", "json"})
    try:
        lock = load_baseline(baseline)
    except ValueError as exc:
        console.file.write(f"Error: {exc}\n")
        raise typer.Exit(2) from exc
    report, scan_report = diff_against_baseline(path, lock)
    if policy:
        try:
            policy_data = load_policy(policy)
        except ValueError as exc:
            console.file.write(f"Error: {exc}\n")
            raise typer.Exit(2) from exc
        result = evaluate_policy(scan_report, policy_data, diff_findings=report.findings)
        if output_format == "json":
            content = stable_json({"diff_report": report, "policy_result": result})
        else:
            content = diff_text(report) + "\n" + check_text(result)
        console.file.write(content)
        raise typer.Exit(1 if result.blocked else 0)
    console.file.write(render_diff(report, output_format))
