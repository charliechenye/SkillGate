from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from skillgate.baseline import create_baseline, diff_against_baseline, load_baseline, save_baseline
from skillgate.models import stable_json
from skillgate.policy import evaluate_policy, load_policy
from skillgate.reporting import check_text, diff_text, render_diff, render_scan, write_or_print
from skillgate.scan import scan_repository

app = typer.Typer(help="Trust checks for AI-agent skills and MCP configurations.")
baseline_app = typer.Typer(help="Create and manage approved SkillGate baselines.")
app.add_typer(baseline_app, name="baseline")
console = Console()


def validate_format(value: str, allowed: set[str]) -> str:
    if value not in allowed:
        raise typer.BadParameter(f"expected one of: {', '.join(sorted(allowed))}")
    return value


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Repository path to scan.")] = Path("."),
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "text",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to a file.")
    ] = None,
) -> None:
    """Scan a repository and report detected capabilities and findings."""
    output_format = validate_format(output_format, {"text", "json", "sarif"})
    report = scan_repository(path)
    write_or_print(render_scan(report, output_format), output, console)


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
        console.print(f"Error: {exc}")
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
        console.print(f"Error: {exc}")
        raise typer.Exit(2) from exc
    report, scan_report = diff_against_baseline(path, lock)
    if policy:
        try:
            policy_data = load_policy(policy)
        except ValueError as exc:
            console.print(f"Error: {exc}")
            raise typer.Exit(2) from exc
        result = evaluate_policy(scan_report, policy_data, diff_findings=report.findings)
        if output_format == "json":
            content = stable_json({"diff_report": report, "policy_result": result})
        else:
            content = diff_text(report) + "\n" + check_text(result)
        console.file.write(content)
        raise typer.Exit(1 if result.blocked else 0)
    console.file.write(render_diff(report, output_format))
