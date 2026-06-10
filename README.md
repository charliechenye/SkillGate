# SkillGate: pre-merge and pre-install trust checks for AI-agent skills and MCP configurations

Agent skills, instruction files, scripts, and MCP configurations act like executable dependencies. SkillGate scans them recursively, infers risky capabilities, compares changes with an approved baseline, and blocks unapproved changes in CI.

## Quick Start

```bash
pip install skillgate
skillgate scan .
skillgate baseline create . --output skillgate.lock
skillgate check . --policy skillgate.yaml
```

For local development:

```bash
pip install -e .
skillgate --help
```

To scan installed Codex skills from a source checkout without installing SkillGate:

```bash
python samples/scan_installed_skills.py
python samples/scan_installed_skills.py --root ~/.codex/skills --fail-on high
```

## Threat Model

SkillGate is a deterministic static-analysis tool. It helps detect obvious risks and capability changes. It does not prove that a skill or MCP server is safe. It does not execute scripts. It does not replace sandboxing, runtime monitoring, or security review.

## Supported Surfaces

SkillGate recursively discovers common agent-relevant files while skipping build, cache, dependency, virtual environment, and Git directories.

Supported files include:

- `**/SKILL.md`
- `**/AGENTS.md`
- `**/CLAUDE.md`
- `.github/copilot-instructions.md`
- `.claude/skills/**`
- `.agents/skills/**`
- `**/mcp.json`
- `**/.mcp.json`
- `package.json`
- `pyproject.toml`
- Referenced local scripts ending in `.sh`, `.bash`, `.py`, `.js`, `.ts`, `.mjs`, `.cjs`, or `.ps1`

## Rules

| Rule | Description | Default severity |
| --- | --- | --- |
| `SG001` | Shell execution detected | medium |
| `SG002` | Destructive command detected | high |
| `SG003` | Network egress detected | medium |
| `SG004` | Remote download followed by execution | high |
| `SG005` | Secret or credential access detected | high |
| `SG006` | Filesystem write capability detected | medium |
| `SG007` | Prompt override or instruction-conflict language detected | high |
| `SG008` | Suspicious Unicode or obfuscation detected | medium |
| `SG009` | MCP server configuration discovered | informational |
| `SG010` | MCP capability changed from baseline | high |

## Policy Example

See [`skillgate.example.yaml`](skillgate.example.yaml).

```bash
skillgate check . --policy skillgate.example.yaml
```

Policy checks can block shell execution, unallowlisted filesystem writes, unallowlisted network hosts, denied secret access, high-risk findings, and MCP capability drift.
SkillGate validates the MVP policy schema and reports file, line, and column details for YAML and schema errors when available.

## Baselines and Diffs

```bash
skillgate baseline create . --output skillgate.lock
skillgate diff . --baseline skillgate.lock
skillgate diff . --baseline skillgate.lock --policy skillgate.example.yaml
```

Baseline files use stable JSON with relative paths so diffs stay reviewable.

## CI Integration

Use the included composite action:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with:
      python-version: "3.11"
  - uses: ./
    with:
      path: .
      policy: skillgate.example.yaml
      sarif-output: skillgate.sarif
```

The repository also includes `.github/workflows/skillgate.yml` as a complete example workflow.

## Output Formats

```bash
skillgate scan . --format text
skillgate scan . --format json
skillgate scan . --format sarif --output skillgate.sarif
skillgate scan . --severity high
skillgate scan . --fail-on high
```

`skillgate scan` exits `0` when findings exist. `skillgate check` exits `1` when policy blocks the repository.
`skillgate scan --fail-on medium|high|critical` exits `1` when displayed findings meet the threshold.

## GitHub Pre-Install Scans

SkillGate can sparse-scan a public GitHub repository before you install or copy skills from it:

```bash
skillgate github scan https://github.com/phuryn/pm-skills
skillgate github scan https://github.com/phuryn/pm-skills --ref main --fail-on high
skillgate github scan https://github.com/phuryn/pm-skills --format json
```

Remote scans do not clone the repository or download a full archive. SkillGate fetches GitHub tree metadata, downloads only supported agent files plus referenced local scripts into a temporary sparse mirror, runs static analysis, and deletes the temporary files. It never executes remote repository content.

## Rule Documentation

```bash
skillgate rules list
skillgate rules list --format json
skillgate explain SG004
skillgate explain SG004 --format json
```

`skillgate rules list` prints the supported rule IDs, default severities, capability types, titles, and remediation guidance. `skillgate explain` prints concise terminal documentation for a single rule ID.

## Policy Diagnostics

SkillGate reports YAML syntax and MVP policy validation errors with file, line, and column details when available.

```text
Error: skillgate.yaml:4:12: policy.risk_threshold.block must be one of: informational, low, medium, high, critical
```

## Benchmark Fixture Summaries

```bash
skillgate fixtures summary fixtures/benchmark --format json
skillgate fixtures summary fixtures/benchmark --format text
```

Fixture summaries compare each `expected-findings.yaml` file with actual scan output. JSON output is intended for benchmark reporting and CI jobs.

## Extraction Notes

SkillGate detects common Python, Node, shell, and PowerShell patterns for shell execution, destructive actions, network egress, and filesystem writes. Extraction stays conservative: when a path or host is not a clear literal value, SkillGate reports the finding without inventing a resource.

## Roadmap

- sandboxed trace runner
- trace-to-regression fixture promotion
- OpenTelemetry-compatible trace ingestion and export
- richer MCP tool-schema inspection
- repository badges
- expanded benchmark cases
