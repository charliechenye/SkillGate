from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from skillgate.baseline import create_baseline, diff_against_baseline, load_baseline, save_baseline
from skillgate.fixtures import (
    FixtureSummaryError,
    fixture_summary_payload,
    fixture_summary_text,
    summarize_fixtures,
)
from skillgate.inventory import inventory_payload, inventory_text
from skillgate.mcp_registry import (
    DEFAULT_REGISTRY_URL,
    RegistryMetadataError,
    compare_registry_metadata,
    registry_compare_markdown,
    registry_scan_text,
    scan_registry_path,
)
from skillgate.models import SEVERITY_ORDER, DiffReport, severity_at_or_above, stable_json
from skillgate.policy import evaluate_policy, load_policy
from skillgate.policy_schema import POLICY_JSON_SCHEMA
from skillgate.policy_templates import POLICY_PROFILES, policy_template_yaml
from skillgate.provenance import (
    ProvenanceError,
    create_provenance_manifest,
    save_provenance_manifest,
    verify_provenance_manifest,
)
from skillgate.reporting import (
    append_scan_failure_text,
    check_text,
    diff_text,
    policy_suggestions,
    render_diff,
    render_scan,
    write_or_print,
)
from skillgate.review import render_review_markdown, review_summary_payload
from skillgate.rule_docs import RULE_DOCS, get_rule_doc, rule_doc_to_data, rule_docs_to_data
from skillgate.scan import filter_report_by_severity, scan_repository
from skillgate.sources import RemoteScanLimits, SourceError, fetch_github_sparse

app = typer.Typer(help="Trust checks for AI-agent skills and MCP configurations.")
baseline_app = typer.Typer(help="Create and manage approved SkillGate baselines.")
fixtures_app = typer.Typer(help="Inspect benchmark fixture expectations.")
github_app = typer.Typer(help="Scan remote GitHub repositories before installing skills.")
policy_app = typer.Typer(help="Inspect SkillGate policy helpers.")
provenance_app = typer.Typer(help="Create and verify SkillGate provenance manifests.")
rules_app = typer.Typer(help="Inspect SkillGate rule documentation.")
review_app = typer.Typer(help="Create reviewer-friendly SkillGate summaries.")
mcp_app = typer.Typer(help="Inspect MCP metadata without installing servers.")
mcp_registry_app = typer.Typer(help="Scan and compare MCP registry metadata.")
app.add_typer(baseline_app, name="baseline")
app.add_typer(fixtures_app, name="fixtures")
app.add_typer(github_app, name="github")
app.add_typer(mcp_app, name="mcp")
app.add_typer(policy_app, name="policy")
app.add_typer(provenance_app, name="provenance")
app.add_typer(review_app, name="review")
app.add_typer(rules_app, name="rules")
mcp_app.add_typer(mcp_registry_app, name="registry")
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


def render_scan_command_output(
    report,
    output_format: str,
    fail_on: str | None,
    sarif_category: str = "local_repository",
) -> tuple[str, bool]:
    failed = scan_failed(report, fail_on)
    content = render_scan(report, output_format, sarif_category=sarif_category)
    if failed and output_format == "text":
        content = append_scan_failure_text(content, fail_on or "")
    return content, failed


@mcp_registry_app.command("scan")
def mcp_registry_scan(
    path: Annotated[
        Path,
        typer.Argument(help="MCP registry metadata file or repository path to scan."),
    ] = Path("."),
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "text",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to a file.")
    ] = None,
) -> None:
    """Scan declared MCP registry metadata without installing the server."""
    output_format = validate_format(output_format, {"text", "json"})
    report = scan_registry_path(path)
    content = stable_json(report) if output_format == "json" else registry_scan_text(report)
    write_or_print(content, output, console)


@mcp_registry_app.command("compare")
def mcp_registry_compare(
    path: Annotated[
        Path,
        typer.Argument(help="Local MCP registry metadata file or repository path."),
    ] = Path("."),
    server: Annotated[str, typer.Option("--server", help="MCP server name to compare.")] = "",
    registry_url: Annotated[
        str,
        typer.Option("--registry-url", help="MCP registry servers endpoint."),
    ] = DEFAULT_REGISTRY_URL,
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "text",
    fail_on_drift: Annotated[
        bool,
        typer.Option("--fail-on-drift", help="Exit 1 when drift or risk findings exist."),
    ] = False,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to a file.")
    ] = None,
) -> None:
    """Compare local MCP metadata with remote registry metadata."""
    output_format = validate_format(output_format, {"text", "json", "sarif", "markdown"})
    if not server:
        console.file.write("Error: --server is required\n")
        raise typer.Exit(2)
    try:
        report = compare_registry_metadata(path, server, registry_url)
    except RegistryMetadataError as exc:
        console.file.write(f"Error: {exc}\n")
        raise typer.Exit(2) from exc
    if output_format == "json":
        content = stable_json(report)
    elif output_format == "sarif":
        content = render_scan(
            report,
            output_format,
            sarif_category="mcp_registry_compare",
        )
    elif output_format == "markdown":
        content = registry_compare_markdown(report)
    else:
        content = registry_scan_text(report)
    write_or_print(content, output, console)
    raise typer.Exit(1 if fail_on_drift and report.findings else 0)


@app.command()
def inventory(
    path: Annotated[Path, typer.Argument(help="Repository path to inventory.")] = Path("."),
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "text",
    capability: Annotated[
        list[str] | None,
        typer.Option("--capability", help="Only include this capability type. Repeatable."),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option("--severity", help="Only include findings at or above this severity."),
    ] = None,
    source_file: Annotated[
        list[str] | None,
        typer.Option(
            "--source-file",
            help="Only include POSIX-style source file globs. Repeatable.",
        ),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to a file.")
    ] = None,
) -> None:
    """Build a capability inventory and trust-boundary summary."""
    output_format = validate_format(output_format, {"text", "json"})
    severity = validate_severity(severity)
    payload = inventory_payload(
        scan_repository(path),
        capability_types=capability,
        severity=severity,
        source_files=source_file,
    )
    content = stable_json(payload) if output_format == "json" else inventory_text(payload)
    write_or_print(content, output, console)


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
    manifest_output: Annotated[
        Path | None,
        typer.Option("--manifest-output", help="Write the remote-scan manifest to a file."),
    ] = None,
    max_files: Annotated[int, typer.Option("--max-files", help="Maximum files to download.")] = 100,
    max_total_bytes: Annotated[
        int,
        typer.Option("--max-total-bytes", help="Maximum total downloaded bytes."),
    ] = 5_242_880,
    max_file_bytes: Annotated[
        int,
        typer.Option("--max-file-bytes", help="Maximum bytes for one downloaded file."),
    ] = 1_048_576,
    request_timeout: Annotated[
        int,
        typer.Option("--request-timeout", help="GitHub request timeout in seconds."),
    ] = 30,
    redirect_limit: Annotated[
        int,
        typer.Option("--redirect-limit", help="Maximum redirects per GitHub request."),
    ] = 3,
) -> None:
    """Sparse-scan a public GitHub repository before installing skills."""
    output_format = validate_format(output_format, {"text", "json", "sarif"})
    severity = validate_severity(severity)
    fail_on = validate_fail_on(fail_on)
    limits = RemoteScanLimits(
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        max_file_bytes=max_file_bytes,
        request_timeout=request_timeout,
        redirect_limit=redirect_limit,
    )
    if any(value <= 0 for value in limits.to_data().values()):
        console.file.write("Error: remote scan limits must be positive integers\n")
        raise typer.Exit(2)
    try:
        sparse = fetch_github_sparse(url, ref, limits=limits)
        report = filter_report_by_severity(scan_repository(sparse.root), severity)
        if manifest_output:
            write_or_print(stable_json(sparse.manifest), manifest_output, console)
        if output_format == "json":
            failed = scan_failed(report, fail_on)
            content = stable_json({"scan_report": report, "remote_manifest": sparse.manifest})
        else:
            content, failed = render_scan_command_output(
                report,
                output_format,
                fail_on,
                sarif_category="remote_github",
            )
        write_or_print(content, output, console)
        raise typer.Exit(1 if failed else 0)
    except SourceError as exc:
        if manifest_output and exc.manifest:
            write_or_print(stable_json(exc.manifest), manifest_output, console)
        console.file.write(f"Error: {exc}\n")
        raise typer.Exit(2) from exc
    finally:
        if "sparse" in locals():
            sparse.cleanup()


@policy_app.command("schema")
def policy_schema(
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write schema to a file.")
    ] = None,
) -> None:
    """Print the SkillGate policy JSON Schema."""
    write_or_print(stable_json(POLICY_JSON_SCHEMA), output, console)


@policy_app.command("init")
def policy_init(
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            help="Policy profile to generate: audit, preinstall, strict, or mcp.",
        ),
    ],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write policy YAML to a file.")
    ] = None,
) -> None:
    """Generate a starter SkillGate policy YAML file."""
    profile = profile.lower()
    if profile not in POLICY_PROFILES:
        console.file.write(
            f"Error: unknown policy profile '{profile}'. "
            f"Expected one of: {', '.join(sorted(POLICY_PROFILES))}\n"
        )
        raise typer.Exit(2)
    content = policy_template_yaml(profile)
    if output and output.exists():
        console.file.write(f"Error: output file already exists: {output}\n")
        raise typer.Exit(2)
    write_or_print(content, output, console)


@provenance_app.command("create")
def provenance_create(
    policy: Annotated[Path, typer.Option("--policy", help="Policy YAML file.")],
    baseline: Annotated[Path, typer.Option("--baseline", help="Baseline lockfile.")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Write provenance manifest to a file."),
    ] = Path("skillgate.provenance.json"),
) -> None:
    """Create a checksum manifest for approved policy and baseline files."""
    try:
        manifest = create_provenance_manifest(policy, baseline)
    except OSError as exc:
        console.file.write(f"Error: unable to read provenance input: {exc}\n")
        raise typer.Exit(2) from exc
    save_provenance_manifest(manifest, output)
    console.print(f"Created provenance manifest: {output}")


@provenance_app.command("verify")
def provenance_verify(
    manifest: Annotated[
        Path,
        typer.Option("--manifest", help="Provenance manifest JSON file."),
    ] = Path("skillgate.provenance.json"),
) -> None:
    """Verify approved policy and baseline checksums from a provenance manifest."""
    try:
        mismatches = verify_provenance_manifest(manifest)
    except ProvenanceError as exc:
        console.file.write(f"Error: {exc}\n")
        raise typer.Exit(2) from exc
    if mismatches:
        console.file.write("FAILED: provenance verification mismatch\n")
        for mismatch in mismatches:
            console.file.write(f"- {mismatch}\n")
        raise typer.Exit(1)
    console.file.write("ALLOWED: provenance verification passed\n")


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


@fixtures_app.command("summary")
def fixtures_summary(
    path: Annotated[Path, typer.Argument(help="Benchmark fixture directory.")] = Path(
        "fixtures/benchmark"
    ),
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "json",
) -> None:
    """Summarize benchmark fixture expectations and actual findings."""
    output_format = validate_format(output_format, {"text", "json"})
    try:
        summaries = summarize_fixtures(path)
    except FixtureSummaryError as exc:
        console.file.write(f"Error: {exc}\n")
        raise typer.Exit(2) from exc
    if output_format == "json":
        console.file.write(stable_json(fixture_summary_payload(path, summaries)))
    else:
        console.file.write(fixture_summary_text(path, summaries))
    raise typer.Exit(1 if any(summary.status == "fail" for summary in summaries) else 0)


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
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Show policy violations and suggested approvals without failing.",
        ),
    ] = False,
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
        content = check_text(result, dry_run=dry_run)
    else:
        content = render_scan(report, output_format, policy_result=result)
        if output_format == "json":
            content = stable_json(
                {
                    "policy_result": result,
                    "scan_report": report,
                    "suggestions": policy_suggestions(result),
                }
            )
    write_or_print(content, output, console)
    raise typer.Exit(0 if dry_run else 1 if result.blocked else 0)


@review_app.command("summary")
def review_summary(
    path: Annotated[Path, typer.Argument(help="Repository path to summarize.")] = Path("."),
    baseline: Annotated[
        Path | None, typer.Option("--baseline", help="Optional baseline lockfile path.")
    ] = None,
    policy: Annotated[
        Path | None, typer.Option("--policy", help="Optional policy YAML file.")
    ] = None,
    output_format: Annotated[str, typer.Option("--format", help="Output format.")] = "markdown",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write summary output to a file.")
    ] = None,
    json_output: Annotated[
        Path | None,
        typer.Option("--json-output", help="Also write machine-readable review JSON."),
    ] = None,
    sarif_artifact: Annotated[
        str | None,
        typer.Option("--sarif-artifact", help="SARIF artifact path or URL to include."),
    ] = None,
    json_artifact: Annotated[
        str | None,
        typer.Option("--json-artifact", help="Review JSON artifact path or URL to include."),
    ] = None,
) -> None:
    """Create a reviewer-friendly summary for CI and pull requests."""
    output_format = validate_format(output_format, {"markdown", "json"})
    diff_report = None
    if baseline:
        try:
            lock = load_baseline(baseline)
        except ValueError as exc:
            console.file.write(f"Error: {exc}\n")
            raise typer.Exit(2) from exc
        diff_report, report = diff_against_baseline(path, lock)
    else:
        report = scan_repository(path)
    policy_result = None
    if policy:
        try:
            policy_data = load_policy(policy)
        except ValueError as exc:
            console.file.write(f"Error: {exc}\n")
            raise typer.Exit(2) from exc
        policy_result = evaluate_policy(
            report,
            policy_data,
            diff_findings=diff_report.findings if diff_report else None,
        )
    payload = review_summary_payload(
        report,
        diff_report=diff_report,
        policy_result=policy_result,
        sarif_artifact=sarif_artifact,
        json_artifact=json_artifact or (str(json_output) if json_output else None),
    )
    if json_output:
        json_output.write_text(stable_json(payload), encoding="utf-8")
    content = stable_json(payload) if output_format == "json" else render_review_markdown(payload)
    write_or_print(content, output, console)


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
    fail_on_drift: Annotated[
        bool,
        typer.Option("--fail-on-drift", help="Exit 1 when baseline drift is detected."),
    ] = False,
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
    if fail_on_drift and baseline_drift_detected(report):
        raise typer.Exit(1)


def baseline_drift_detected(report: DiffReport) -> bool:
    return any(
        getattr(report, field)
        for field in [
            "added_files",
            "removed_files",
            "modified_files",
            "added_capabilities",
            "removed_capabilities",
            "findings",
        ]
    )
