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
- reviewer-friendly Markdown and JSON summaries;
- GitHub Step Summary support;
- structured MCP registry drift output;
- a composite GitHub Action that can enforce a supplied `baseline` plus `fail-on-drift`;
- a GitHub-first Node wrapper backed by checksummed release binaries;
- bounded release-manifest and binary downloads;
- a reusable, fail-closed ZIP archive inspection foundation organized into focused internal modules.

These capabilities are release history, not future work. Keep detailed records in `CHANGELOG.md`.

---

## Near-Term Priority

The next phase should convert the archive foundation into one memorable public workflow, then remove the largest barriers to adoption.

The execution order is:

1. Ship the narrow MCPB pre-install scan MVP.
2. Publish the Python package through a low-friction distribution path.
3. Publish credible public scan reports.
4. Simplify onboarding and demonstrate the workflow visually.
5. Expand the MCPB workflow only where real usage justifies it.
6. Add Agent Skills validation.
7. Build the declared-intent-versus-observed-capability model.

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

## Batch 2A.1: MCPB Scan MVP

### Required Commands

Ship:

```bash
skillgate mcpb scan bundle.mcpb
skillgate mcpb scan bundle.mcpb --format json
skillgate mcpb scan bundle.mcpb --fail-on high
skillgate mcpb scan bundle.mcpb --manifest-output bundle-manifest.json
```

Defer SARIF until the text and JSON output contracts stabilize.

### MCPB Adapter

Implement MCPB as a source adapter over the safe archive layer and existing scanner.

The adapter should:

1. inspect and safely extract the bundle;
2. locate and parse `manifest.json`;
3. validate the minimal required bundle structure;
4. identify the declared server type and entry point;
5. identify referenced files;
6. identify environment-variable and user-configuration declarations;
7. identify commands, scripts, URLs, endpoints, package metadata, and binaries;
8. pass extracted static files into existing SkillGate discovery and rules;
9. combine archive, manifest, and scan results into one deterministic report;
10. clean up temporary files after the result has been rendered or persisted.

Do not create a second scanning engine.

### Narrow Manifest Scope

Parse only the fields needed to answer:

- What starts?
- Where is the entry point?
- Which files are required?
- Which configuration values and environment variables are referenced?
- Which URLs or endpoints are declared?
- Are all referenced files present?
- Does the declared startup behavior match bundled content?

Do not attempt complete interpretation of every MCPB manifest field in the first release.

### Bundle-Specific Findings

Add no more than three bundle-specific findings unless implementation proves that another finding is essential:

1. malformed or unsafe MCP bundle structure;
2. manifest references missing, conflicting, or unexpected files;
3. embedded binary or retained nested archive requiring explicit review.

Reuse existing SG rules for shell execution, remote download execution, network egress, secret access, filesystem writes, suspicious package scripts, prompt override behavior, obfuscation, and MCP transport or metadata risks.

### Deterministic Bundle Manifest

The bundle manifest should include:

- archive SHA-256;
- scanner version;
- member count;
- total compressed bytes;
- total uncompressed bytes;
- normalized member paths;
- member SHA-256 values;
- compressed and uncompressed sizes;
- compression ratios;
- file classification;
- whether each member was scanned;
- stable skip reasons;
- manifest path;
- detected entry point;
- declared server type;
- referenced environment variables;
- detected URLs and endpoints;
- embedded binary inventory;
- retained nested archive inventory.

Do not include temporary extraction paths, local archive filesystem paths, timestamps, environment-specific values, or raw file contents.

### Required Fixtures

Ship the MVP with:

- safe MCPB;
- shell startup command;
- remote endpoint;
- secret reference;
- malformed manifest;
- missing entry point;
- embedded binary;
- nested archive.

Continue relying on archive-layer tests for low-level ZIP traversal, absolute paths, symlinks, compression bombs, and resource limits.

### Tests

For each fixture, assert as applicable:

- exit code;
- finding IDs;
- detected entry point;
- detected commands and endpoints;
- referenced environment variables;
- manifest state;
- deterministic JSON;
- member scan and skip state;
- temporary-file cleanup;
- no archive content execution.

### Explicitly Deferred From The MVP

Do not include:

- MCPB SARIF;
- GitHub Action MCPB inputs;
- MCPB-specific policy schema;
- recursive nested archive inspection;
- remote registry lookups;
- package installation;
- dependency resolution;
- binary malware analysis;
- YARA;
- sandboxing;
- automatic remediation;
- complete MCPB specification modeling.

---

# Batch 2B: Distribution And Adoption

The scanner will not gain broad adoption through feature depth alone. After the MCPB MVP, reduce first-use friction and publish evidence.

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

- SARIF output;
- `skillgate/mcp-bundle` SARIF run category;
- GitHub Action support for scanning committed MCPB artifacts;
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

## Next PR

```text
refactor: split archive inspection into focused modules
```

Behavior-preserving only.

## Following PR

```text
feat: add MCPB scan MVP
```

Public text and JSON workflow, deterministic bundle manifest, existing scanner reuse, and focused fixtures.

## Following Release Work

```text
release: prepare low-friction Python distribution
docs: publish public scan evidence and simplify onboarding
```

This order protects implementation quality while keeping the project focused on user-visible adoption.
