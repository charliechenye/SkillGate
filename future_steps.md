# Future Steps

## Product Direction

SkillGate should remain a local-first, deterministic trust gate for AI-agent skills, MCP configurations, MCP bundles, and agent-tooling supply chains.

The project should answer one practical question better than anyone else:

> Before I install, merge, or approve this agent skill or MCP server, what new capability surface does it introduce?

SkillGate should stay focused on pre-install and pre-merge review. It should not become a hosted dashboard, generic agent framework, runtime gateway, malware scanner, or broad observability platform until the local trust-gate workflow is widely useful and clearly differentiated.

The roadmap should prioritize complete user workflows, distribution, and public proof over adding large numbers of loosely connected rules.

---

## Current Baseline

The current stable release is `v0.1.1`.

The shipped baseline includes:

- local static scans for agent-relevant files;
- sparse GitHub pre-install scans;
- deterministic rules for shell execution, destructive commands, network egress, remote download execution, secret access, filesystem writes, prompt override language, suspicious Unicode, and MCP-related risks;
- policy-as-code checks;
- expiring finding waivers;
- baseline creation and capability-drift detection;
- provenance verification for policy and baseline files;
- SARIF output and GitHub code-scanning integration;
- MCPB SARIF output and composite Action support for scanning committed MCPB artifacts;
- reviewer-friendly Markdown and JSON summaries;
- GitHub Step Summary support;
- structured MCP registry drift output;
- a composite GitHub Action that can enforce a supplied `baseline` plus `fail-on-drift`;
- a GitHub-first Node wrapper backed by checksummed release binaries;
- bounded release-manifest and binary downloads;
- a reusable, fail-closed ZIP archive inspection foundation organized into focused internal modules;
- the MCPB pre-install scan MVP with text and JSON output, manifest output, retained nested-archive inventory, embedded-artifact review findings, and no bundle execution;
- a packaged `skillgate demo mcpb` first-run demo that builds a deterministic synthetic bundle and can scan it immediately.
- the first `skillgate skills validate` workflow for deterministic Agent Skills structure and metadata checks.

These capabilities are release history, not future work. Keep detailed records in `CHANGELOG.md`.

---

## Near-Term Priority

The next phase should reduce first-use friction, publish evidence, and expand MCPB only where real usage justifies it.

The execution order is:

1. Publish the Python package through a low-friction distribution path.
2. Publish credible public scan reports.
3. Simplify onboarding and demonstrate the workflow visually.
4. Expand the MCPB workflow only where real usage justifies it.
5. Expand Agent Skills validation and documentation where real usage justifies it.
6. Build the declared-intent-versus-observed-capability model.

Do not add more generic rule families unless they are necessary to complete one of these workflows.

---

# Milestone 0.2.0: Safe MCPB Pre-Install Scanner

## Product Outcome

A user can inspect an MCP bundle before installing or executing it and receive a deterministic answer about:

- what starts;
- which file is the entry point;
- which commands or runtimes are involved;
- which environment variables and secrets are referenced;
- which URLs and endpoints are declared;
- which files are bundled;
- whether binaries or nested archives require review;
- which existing SkillGate findings apply.

The first public workflow should be:

```bash
skillgate mcpb scan bundle.mcpb
```

# Batch 2B: Distribution And Adoption

The scanner will not gain broad adoption through feature depth alone. Reduce first-use friction and publish evidence.

## Publish The Python Package

Target installation:

```bash
pipx install openevalgate-skillgate
skillgate scan .
```

Also validate:

```bash
uvx openevalgate-skillgate scan .
```

Before publication:

- verify package ownership and the final distribution name;
- verify README metadata and project URLs;
- build source and wheel distributions;
- install from a clean environment;
- test all CLI entry points and version output;
- test upgrade behavior;
- verify dependency bounds;
- publish to a test index when appropriate;
- perform post-publication smoke tests;
- document rollback and yanking procedures.

Keep GitHub tags and full commit SHA installation documented for high-trust users.

## Publish Three Public Scan Reports

Create:

```text
docs/public-scan-reports/
```

Publish:

1. a clean agent skill repository;
2. a repository with meaningful shell, network, secret, or helper-script review items;
3. an MCPB bundle report.

Each report should include:

- immutable source revision or archive hash;
- exact command used;
- scanner version;
- capability inventory;
- findings summary;
- classification of each finding as expected behavior, review item, or demonstrated vulnerability;
- limitations;
- suggested policy;
- what SkillGate cannot conclude.

Do not shame maintainers or label findings as vulnerabilities without evidence.

## Simplify README Onboarding

The top-level README should initially present three workflows:

### Before installing

```bash
skillgate github scan URL
skillgate mcpb scan bundle.mcpb
```

### Before merging

```bash
skillgate scan .
```

### When ready to enforce

```bash
skillgate check . --policy skillgate.yaml
```

Move baselines, provenance, inventory, MCP registry comparison, SARIF details, and advanced Action settings below the primary onboarding path.

## Add A Visual Demo

Publish a short terminal recording or animated demonstration that shows:

```text
bundle.mcpb
→ archive inspected
→ entry point detected
→ startup command detected
→ secret and endpoint references identified
→ review result produced
```

The demo should use a committed deterministic fixture.

## Adoption Signals

Track:

- repository stars;
- unique cloners;
- package downloads;
- GitHub Action usage;
- external issues and pull requests;
- public references;
- successful scans of third-party repositories;
- number of public scan reports;
- time from installation to first useful result.

Do not add telemetry to the CLI without an explicit privacy design and opt-in decision.

---

# Batch 2C: MCPB Workflow Expansion

Only begin this batch after the MCPB text and JSON output contracts have been exercised through fixtures and public reports.

Potential additions:

- policy controls for bundle-specific findings;
- richer package metadata interpretation;
- declared file inventory comparisons;
- stronger unexpected-file detection;
- example CI workflows;
- additional public bundle reports.

Do not add all of these automatically. Prioritize based on observed user requests.

---

# Milestone 0.3.0: Agent Skills Standards Alignment

## Product Outcome

A user can validate whether a skill is structurally complete and compare its declared intent with the capabilities detected in its files and scripts.

## Add Skills Validation

Ship:

```bash
skillgate skills validate PATH
```

Validate:

- required `name` and `description`;
- name format;
- parent-directory naming consistency;
- optional `license`, `compatibility`, and metadata;
- experimental `allowed-tools`;
- supported optional directories: `scripts/`, `references/`, and `assets/`.

Report malformed frontmatter, missing required fields, invalid names, directory-name mismatches, missing referenced files, missing license metadata, ambiguous compatibility declarations, executables outside expected directories, missing referenced scripts or assets, and broad or ambiguous `allowed-tools`.

Treat `allowed-tools` as declared metadata, not proof of runtime enforcement.

## Required Evidence

Ship with:

- valid minimal skill;
- valid complex skill;
- malformed frontmatter;
- missing referenced script;
- hidden executable;
- broad `allowed-tools`;
- one public standards-aligned scan report.

---

# Milestone 0.4.0: Declared Intent Versus Observed Capability

This should become SkillGate’s strongest long-term differentiator.

## Product Outcome

SkillGate should explain where an agent artifact’s stated purpose or declared permissions do not match the capabilities observed in its implementation.

Add:

```bash
skillgate skills diff PATH
```

Compare declared tools, compatibility, environment variables, network access, and filesystem behavior with detected shell commands, network hosts, secret names, filesystem writes, executable references, MCP server references, and package scripts.

Report:

- observed but undeclared capabilities;
- declared but unused capabilities;
- newly introduced capabilities;
- removed capabilities;
- capability severity changes;
- missing scripts, references, or assets;
- contradictions between description and observed behavior.

Core concept:

> Declared intent versus observed capability.

Policy hooks may later allow:

```yaml
policy:
  skills:
    require_declared_capabilities: true
    block_undeclared_high_risk_capabilities: true
```

This milestone should focus on explainable mismatches, not speculative intent inference.

---

# Maintenance Requirements

## Maintain GitHub Action Reliability

Keep the documented Action behavior stable for nonblocking scans, blocking policy checks, policy-aware SARIF, baseline drift blocking, GitHub Step Summary, Markdown summaries, and machine-readable review artifacts.

Maintain copy-paste examples for:

- nonblocking scan with SARIF;
- blocking policy check with policy-aware SARIF;
- baseline drift blocking;
- review-summary artifact upload.

## Maintain Release Verification

For every release:

- verify the concrete release tag and stable `v0` tag;
- verify GitHub Action usage from a clean external repository;
- verify GitHub-tag and package installation paths;
- verify the Node wrapper from a clean environment;
- verify binary hashes and manifest sizes;
- verify unsupported-platform failures;
- verify offline cached-binary behavior.

Continue recommending full commit SHA pinning for high-trust GitHub Action users, explicit release tags for Python installation, and explicit `SKILLGATE_VERSION` for Node wrapper downloads.

## Maintain GitHub-First Node Distribution

Keep the Python implementation canonical. Do not maintain a second scanner in TypeScript.

Current intended Node usage:

```bash
npx --yes github:charliechenye/SkillGate#v0 -- scan .
```

Maintain platform-specific binary selection, release-manifest checksum validation, bounded downloads, cache support, offline cached-binary mode, explicit version pinning, and clear unsupported-platform messages.

Do not promote bare `npx skillgate scan .` until an npm package is intentionally published.

---

# Prioritization Rules

1. Prefer a complete user workflow over another isolated capability.
2. Prefer deterministic evidence over heuristic breadth.
3. Prefer reuse of the existing scanner over parallel implementations.
4. Prefer adoption friction reduction over advanced configuration.
5. Prefer public examples over unsupported security claims.
6. Add new rule IDs only when existing rules cannot express the review decision.
7. Keep stable output contracts small and versioned.
8. Treat cleanup, bounded resource use, provenance, and no-execution guarantees as product requirements.
9. Keep `future_steps.md` future-only.
10. Record completed work under `CHANGELOG.md > Unreleased`.

---

# Immediate Execution Order

```text
release: prepare low-friction Python distribution
docs: publish public scan evidence and simplify onboarding
```

This order keeps the project focused on user-visible adoption now that the MCPB pre-install scan MVP is part of the baseline.
