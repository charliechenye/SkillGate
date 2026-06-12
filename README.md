# SkillGate - Static trust checks for AI-agent skills and MCP configurations

[![SkillGate CI](https://github.com/charliechenye/SkillGate/actions/workflows/skillgate.yml/badge.svg?branch=master)](https://github.com/charliechenye/SkillGate/actions/workflows/skillgate.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-purple)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

![SkillGate social preview: static trust checks for AI-agent skills and MCP configurations](docs/assets/repo_image.png)

Pre-merge and pre-install trust checks for AI-agent skills and MCP configurations. Scan capabilities, detect risky changes, and block unapproved agent behavior in CI.

SkillGate is an AI-agent security scanner and MCP security scanner for teams that review Codex skills, Claude skills, Model Context Protocol server configs, agent instruction files, and helper scripts before they are installed or merged.

## Quick Start

```bash
pip install skillgate
skillgate scan .
skillgate baseline create . --output skillgate.lock
skillgate check . --policy skillgate.yaml
```

What SkillGate does:

- Scans agent instructions, skill files, scripts, package configs, and MCP server configs.
- Detects risky capabilities such as shell execution, network egress, secret access, filesystem writes, destructive commands, and prompt override language.
- Compares repositories against stable baselines to catch capability drift.
- Enforces policy-as-code for AI-agent tools in local checks and CI.
- Sparse-scans public GitHub skill repositories before installation without cloning the full repo.
- Emits text, JSON, and SARIF output for GitHub code scanning.

## What Is SkillGate?

SkillGate is a deterministic static analysis tool for agentic tooling supply chains. It treats AI-agent skills, MCP configurations, instruction files, and local helper scripts like executable dependencies: something you should inspect before installing, merging, or running in automation.

Use SkillGate when you need a pre-install skill scanner, Codex skills scanner, Claude skills scanner, or static analysis for agent instructions and MCP server definitions.

## Why Scan AI-Agent Skills And MCP Configurations?

Agent skills and MCP servers can request powerful access through plain text instructions, scripts, package commands, environment variables, and remote endpoints. A small change can introduce shell execution, credential access, network calls, or filesystem writes.

SkillGate helps reviewers answer practical security questions:

- Does this skill run shell commands?
- Does this MCP server reference secrets or remote endpoints?
- Did a pull request add a new capability since the last approved baseline?
- Can CI block unapproved agent behavior before it reaches users?

## Scan A GitHub Skills Repository Before Installing

SkillGate can sparse-scan a public GitHub repository before you install or copy skills from it:

```bash
skillgate github scan https://github.com/phuryn/pm-skills
skillgate github scan https://github.com/addyosmani/agent-skills/tree/main/skills
skillgate github scan https://github.com/phuryn/pm-skills --ref main --fail-on high
skillgate github scan https://github.com/phuryn/pm-skills --format json
skillgate github scan https://github.com/phuryn/pm-skills --manifest-output remote-manifest.json
```

Remote scans do not clone the repository or download a full archive. SkillGate resolves the requested branch or tag to an immutable commit SHA, fetches GitHub tree metadata at that SHA, downloads only supported agent files plus referenced local scripts into a temporary sparse mirror, runs static analysis, and deletes the temporary files. It never executes remote repository content.

GitHub tree URLs scan only the selected subtree. If a tree URL includes a branch and you also pass `--ref`, the explicit `--ref` value wins.

Remote scan JSON output includes a `remote_manifest` with the source URL,
requested ref, resolved commit SHA, downloaded paths, SHA-256 hashes, byte
counts, skipped files, and resource limits. Use `--manifest-output` to write the
same manifest as a CI artifact for text or SARIF scans. If a selected file,
referenced script, ref resolution, or resource limit makes the remote scan
incomplete, SkillGate exits `2` rather than reporting a partial scan as
complete.

See [GitHub pre-install scans](docs/github-preinstall-scan.md) for the full workflow.

## Use SkillGate In CI

Use the included composite action:

```yaml
steps:
  - uses: actions/checkout@v6
  - uses: actions/setup-python@v6
    with:
      python-version: "3.11"
  - uses: charliechenye/SkillGate@master
    with:
      path: .
      policy: skillgate.example.yaml
      sarif-output: skillgate.sarif
```

For repositories that want blocking policy enforcement, run `skillgate check . --policy skillgate.example.yaml` in CI. SkillGate's own workflow scans the full repository nonblocking because `fixtures/benchmark/` intentionally contains risky examples used to test detector behavior. It still runs a passing policy smoke check against a safe fixture and uploads SARIF for visibility.

The repository also includes `.github/workflows/skillgate.yml` as a complete example workflow.

## What Does SkillGate Detect?

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
| `SG011` | MCP tool metadata risk detected | high |
| `SG012` | MCP transport risk detected | high |
| `SG013` | MCP registry metadata drift detected | high |

SkillGate detects common Python, Node, shell, and PowerShell patterns for shell execution, destructive actions, network egress, and filesystem writes. Extraction stays conservative: when a path or host is not a clear literal value, SkillGate reports the finding without inventing a resource.

## Does SkillGate Execute Code?

No. SkillGate is a deterministic static-analysis tool. It does not execute scripts, run package commands, start MCP servers, call LLMs, send telemetry, or access a database.

SkillGate helps detect obvious risks and capability changes. It does not prove that a skill or MCP server is safe, and it does not replace sandboxing, runtime monitoring, or human security review.

## Supported Surfaces

SkillGate recursively discovers common agent-relevant files while skipping build, cache, dependency, virtual environment, and Git directories.

Supported files include:

- `**/SKILL.md`
- `**/AGENTS.md`
- `**/CLAUDE.md`
- `.github/copilot-instructions.md`
- `.claude/skills/**`
- `.agents/skills/**`
- `skills/**/SKILL.md`
- `agents/**`
- `.claude/commands/**`
- `.gemini/commands/**`
- `hooks/**`
- `**/mcp.json`
- `**/.mcp.json`
- `**/mcp-registry.json`
- `**/mcp-server.json`
- MCP registry-style `server.json`
- `package.json`
- `pyproject.toml`
- Referenced local scripts ending in `.sh`, `.bash`, `.py`, `.js`, `.ts`, `.mjs`, `.cjs`, or `.ps1`

## Local Installed Skills Scan

To scan installed Codex skills from a source checkout without installing SkillGate:

```bash
python samples/scan_installed_skills.py
python samples/scan_installed_skills.py --root ~/.codex/skills --fail-on high
```

## Policy Example

See [`skillgate.example.yaml`](skillgate.example.yaml), the full [policy schema reference](docs/policy-schema.md), [schema-aware editor setup snippets](docs/editor-setup.md), and the machine-readable JSON Schema at [`schemas/skillgate-policy.schema.json`](schemas/skillgate-policy.schema.json).

```bash
skillgate check . --policy skillgate.example.yaml
skillgate check . --policy skillgate.example.yaml --dry-run
skillgate policy schema
skillgate policy schema --output skillgate-policy.schema.json
skillgate policy init --profile strict --output skillgate.yaml
```

Policy checks can block shell execution, unallowlisted commands, unallowlisted filesystem writes, unallowlisted network hosts or host categories, denied capability groups, denied secret access, high-risk findings, and MCP capability drift. SkillGate validates the policy schema and reports file, line, and column details for YAML and schema errors when available. Use `--dry-run` to see why a policy would block and which narrow allowlist or capability-group entry would approve expected behavior.

Policy templates are available for common adoption modes:

```bash
skillgate policy init --profile audit
skillgate policy init --profile preinstall
skillgate policy init --profile strict
skillgate policy init --profile mcp
```

## Baselines And Diffs

```bash
skillgate baseline create . --output skillgate.lock
skillgate diff . --baseline skillgate.lock
skillgate diff . --baseline skillgate.lock --policy skillgate.example.yaml
```

Baseline files use stable JSON with relative paths so diffs stay reviewable.

To pin approved policy and baseline files by checksum:

```bash
skillgate provenance create --policy skillgate.yaml --baseline skillgate.lock --output skillgate.provenance.json
skillgate provenance verify --manifest skillgate.provenance.json
```

## MCP Registry Metadata

```bash
skillgate mcp registry scan .
skillgate mcp registry scan mcp-registry.json --format json
skillgate mcp registry compare . --server io.example.server
skillgate mcp registry compare . --server io.example.server --fail-on-drift
skillgate mcp registry compare fixtures/registry-compare-drift/local \
  --server io.example.registry-drift \
  --registry-url fixtures/registry-compare-drift/registry.json
```

Registry scanning is static: SkillGate reads declared MCP registry metadata,
publisher-provided tool metadata, remotes, packages, headers, and app-surface
hints without installing packages, starting servers, or introspecting runtime
tools. Remote registry comparison is opt-in and compares local declarations
against registry/package metadata for reviewable drift. The local
`fixtures/registry-compare-drift` example intentionally emits `SG013`.

`SG013` means the local MCP metadata does not match the registry metadata for
the selected server. Review each mismatch by field:

- Repository, package, remote URL, transport type, version, and secret/header
  differences can indicate stale local metadata, a registry update, or a
  substituted package/server identity.
- A mismatch can be expected during a planned release, registry migration,
  package rename, endpoint cutover, or before local metadata has been published.
- Treat unexpected repository, package, remote endpoint, or secret-header drift
  as a review blocker until the intended source of truth is clear.
- Keep intentional drift reviewable by recording the reason in the PR and, when
  possible, attaching the JSON compare output as a CI artifact.

## Capability Inventory

```bash
skillgate inventory .
skillgate inventory . --format json
skillgate inventory . --capability network_egress
skillgate inventory . --severity high
skillgate inventory . --source-file "scripts/*"
```

Inventory output groups detected capabilities and findings by source file and
summarizes trust boundaries for local execution, remote endpoints, secrets,
generated files, MCP servers, prompt controls, and obfuscation. This command is
nonblocking and is intended for review, reporting, and adoption planning.

## Output Formats

```bash
skillgate scan . --format text
skillgate scan . --format json
skillgate scan . --format sarif --output skillgate.sarif
skillgate scan . --severity high
skillgate scan . --fail-on high
```

`skillgate scan` exits `0` when findings exist. `skillgate check` exits `1` when policy blocks the repository. `skillgate scan --fail-on medium|high|critical` exits `1` when displayed findings meet the threshold.

## Rule Documentation

```bash
skillgate rules list
skillgate rules list --format json
skillgate explain SG004
skillgate explain SG004 --format json
```

`skillgate rules list` prints the supported rule IDs, default severities, capability types, titles, and remediation guidance. `skillgate explain` prints concise terminal documentation for a single rule ID.

## Benchmark Fixture Summaries

```bash
skillgate fixtures summary fixtures/benchmark --format json
skillgate fixtures summary fixtures/benchmark --format text
```

Fixture summaries compare each `expected-findings.yaml` file with actual scan output. JSON output is intended for benchmark reporting and CI jobs. Benchmark fixtures include reduced, nonverbatim cases based on common public skill and MCP repository patterns.
Public-pattern fixtures include machine-readable attribution metadata in
`expected-findings.yaml`.

## FAQ

### Is SkillGate an AI-agent security scanner?

Yes. SkillGate is a static AI-agent security scanner focused on skills, instruction files, helper scripts, and MCP server configuration changes.

### Is SkillGate an MCP security scanner?

Yes. SkillGate parses MCP config files, extracts server commands, args, environment variable names, and endpoint values, scans declared MCP registry/tool metadata for risky tool and transport surfaces, and reports MCP capability drift against approved baselines or opt-in registry comparisons.

### Can SkillGate scan a GitHub repository before I install skills?

Yes. `skillgate github scan URL` sparse-scans supported files from a public GitHub repository before installation. It does not clone the full repository and does not execute remote code.

### Can SkillGate produce SARIF for GitHub code scanning?

Yes. Use `skillgate scan . --format sarif --output skillgate.sarif` and upload the SARIF file in GitHub Actions.
SARIF output includes SkillGate capability tags and taxa for filtering in code scanning views.

### Does SkillGate replace a sandbox?

No. SkillGate is static analysis and policy enforcement. Use it alongside sandboxing, least-privilege credentials, runtime monitoring, and code review.

## Contributing And Security

- See [CONTRIBUTING.md](CONTRIBUTING.md) to add rules, fixtures, expected findings, tests, or documentation.
- See [SECURITY.md](SECURITY.md) to report vulnerabilities or unsafe behavior.

## Citation, License, And Brand Assets

SkillGate source code is available under the [MIT License](LICENSE).

To cite this project in technical writing, research, or presentations, use the
metadata in [`CITATION.cff`](CITATION.cff).

The SkillGate name, logo, social-preview images, and other visual brand assets
are governed separately by [`BRAND.md`](BRAND.md). Community sharing with clear
attribution and a link to the canonical repository is encouraged.

## Roadmap

- sandboxed trace runner
- trace-to-regression fixture promotion
- OpenTelemetry-compatible trace ingestion and export
- richer MCP tool-schema inspection
- expanded benchmark cases
