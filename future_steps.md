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

### Semantic artifact linting

Explore semantic artifact linting only as an opt-in, local-first extension to
pre-install and pre-merge review. The goal is to surface suspicious
agent-directed instructions that are already shipped in skills, MCP configs,
MCPB bundles, manifests, prompt templates, and explicitly agent-facing static
text artifacts. Ordinary README prose, arbitrary comments, binaries, rendered
pages, and unclassified bundled assets are not semantic inputs by default.

This is not a pivot into runtime prompt-injection protection. Runtime web
content, email, RAG stores, MCP server execution, hosted prompt firewalls,
sandboxing, and action approval enforcement remain out of scope unless the
project makes a separate product decision.

Use the staged roadmap in
[`docs/roadmaps/semantic-artifact-linting.md`](docs/roadmaps/semantic-artifact-linting.md)
before implementing any semantic scanner. Rebase implementation work onto the
current Review Packet schema and preserve existing `SG007`/`SG008` behavior.
The initial compatibility, source-role, and inventory decisions are recorded
in [`docs/semantic-artifact-inventory.md`](docs/semantic-artifact-inventory.md).
The staged sequence is:

```text
contract and SG007 compatibility
→ bounded text inventory
→ narrow advisory rules and adversarial evaluation
→ semantic instruction drift
→ opt-in review integration and public evidence
→ declared-purpose/capability/instruction comparison
→ policy and suppression support
```

The first milestone is a bounded deterministic text inventory; a small,
high-precision advisory rule pack follows only after an overlap matrix and
reviewed benchmark gates exist. Semantic policy remains gated on representative
repository evidence. This is not a classifier or blocking-policy commitment.

The committed synthetic semantic-artifact corpus and its internal evaluation
harness now validate source selection, labels, and future category metrics.
They are test tooling, not a public product surface. A semantic CLI, including
`review preinstall --semantic` or a standalone semantic command, is explicitly
deferred until advisory `SA###` rules have produced useful benchmark evidence.

### Declared purpose, capability, and instruction comparison

After semantic review and drift have real usage, add an explainable comparison of
what an artifact claims to do, what its code/configuration can do, and what its
agent-facing instructions request. Report potential mismatches with evidence;
do not infer maintainer intent or label a mismatch malicious without proof.

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
