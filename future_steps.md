# Future Steps

## Product Direction

SkillGate is a local-first, deterministic trust gate for AI-agent skills, MCP
configurations, MCP bundles, and agent-tooling supply chains. Its clearest job
is to answer this question before install, merge, or approval:

> What new capability surface does this artifact introduce?

The roadmap prioritizes complete review workflows, low-friction distribution,
and public evidence over a large number of loosely connected rules. SkillGate
should not become a hosted dashboard, runtime gateway, malware scanner, or
generic agent framework without a deliberate product decision.

## Current Baseline

The current stable release is `v0.1.2`. The shipped baseline includes:

- local and sparse GitHub static scans;
- deterministic findings for agent instructions, scripts, MCP metadata, and
  capability risks;
- policy-as-code, waivers, baselines, capability drift, and provenance checks;
- text, JSON, SARIF, Markdown review summaries, and GitHub Step Summary output;
- MCP registry comparison and MCPB pre-install inspection without execution;
- a composite GitHub Action with policy, baseline, review artifact, and MCPB
  support;
- a checksummed GitHub-first Node wrapper;
- `skillgate skills validate` and deterministic Agent Skill/MCPB demos; and
- guided review sessions for local review, pre-install review, and approval.

These are release history, not future work. Keep detailed records in
`CHANGELOG.md`.

## 0.1.3 Adoption Priorities

The original adoption priorities are now implemented on `main` and should be
released as `0.1.3`. The next implementation batch is the review-evidence and
capability-contract work below.

The next minor release is a focused pre-install adoption release. The target is
one copy-pasteable review flow that produces a decision-ready packet without
executing code or making network requests for local inputs.

### 1. Standardize contributor setup

Use the pinned `.python-version`, committed `uv.lock`, `uv sync --locked`, and
`uv run` as the canonical development workflow. CI and contributor docs should
use the same commands.

### 2. Add one unified pre-install review

Provide:

```bash
skillgate review preinstall SOURCE
```

The command should accept a local file or directory, a GitHub repository or
subtree URL, and a local `.mcpb` bundle. It should produce Markdown by default
and optional stable JSON containing source identity, capabilities, findings,
Agent Skills validation results, reviewer next actions, limitations, and the
no-execution guarantee. Results remain advisory unless the caller supplies an
explicit `--fail-on` threshold.

Existing enforcement remains in `check`, `diff`, and `review summary`; this
release does not add MCPB policy enforcement or declared-intent diffing.

### 3. Publish reproducible evidence

Add a Markdown benchmark report generated from the committed fixtures. Include
scanner version, fixture totals, rule coverage, expected-versus-actual results,
attribution, reproduction commands, and limitations. Do not present fixture
results as real-world detection accuracy.

Keep public scan reports in `docs/public-scan-reports/` and label findings as
review items unless there is evidence for a stronger claim.

### 4. Make first adoption copyable

Add a starter repository with a minimal safe Agent Skill and a first-run local
pre-install review command. An optional GitHub Action may retain Markdown, JSON,
and SARIF as artifacts. If a repository owner enables that integration,
main-branch and manual runs may publish SARIF to Code Scanning; pull requests
should remain reviewable without making intentional fixture findings a blocking
status.

The documented escalation path is:

```text
review preinstall → review summary → check with policy → diff with baseline
```

### 5. Keep distribution decisions explicit

PyPI publication is deferred for `0.1.3`. When publication is revisited, use
the existing distribution name `openevalgate-skillgate`; the `skillgate` PyPI
name is already occupied by another project. Do not rename the Python package
or publish a second distribution as a workaround.

The root npm package remains private and npm publication is also deferred. The
GitHub-first Node wrapper remains the supported Node entry point until a package
name, ownership, and publication strategy are intentionally approved.

The supported source-checkout example remains:

```bash
npx --yes github:charliechenye/SkillGate#v0 -- scan .
```

## Later Work

### Declared intent versus observed capability

After the unified review flow has real usage, add an explainable comparison of
declared tools and metadata against capabilities observed in files and scripts.
This should report undeclared capabilities, unused declarations, and
contradictions without inferring intent speculatively.

### Targeted MCPB and Agent Skills expansion

Expand MCPB policy controls and Agent Skills validation only in response to
real adoption evidence. Do not add new rule families or rule IDs merely to make
the roadmap look larger.

## Maintenance Requirements

Keep the documented Action behavior stable for advisory scans, blocking policy
checks, baseline drift blocking, GitHub Step Summary, Markdown summaries, JSON
artifacts, and SARIF review artifacts. Preserve copy-pasteable examples for:

- nonblocking scan with SARIF retained as a pull-request artifact;
- blocking policy check with policy-aware SARIF;
- baseline drift blocking; and
- review-summary artifact upload.

The composite Action can enforce a supplied `baseline` plus `fail-on-drift` when
a repository explicitly opts into that gate.

Do not add telemetry without an explicit privacy design and opt-in decision.

## Release Checklist References

The release checklist covers the `v0.1.2` launch history and remains the source
for tag and binary verification details. For the next release, use the same
checks with `uv sync --locked`, the generated benchmark report, the starter
repository smoke test, and the final no-execution review.
