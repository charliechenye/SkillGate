# Future Steps

## Product Direction

SkillGate should remain a local-first, deterministic trust gate for AI-agent skills, MCP configurations, MCP bundles, and agent-tooling supply chains.

The project should answer one practical question better than anyone else:

> Before I install, merge, or approve this agent skill or MCP server, what new capability surface does it introduce?

SkillGate should stay focused on pre-install and pre-merge review. It should not become a hosted dashboard, generic agent framework, runtime gateway, or broad observability platform until the core trust-gate workflow is widely useful.

## Current Baseline

The current stable release is `v0.1.1`.

The shipped baseline already includes:

- local static scans for agent-relevant files;
- sparse GitHub pre-install scans;
- deterministic rules for shell execution, destructive commands, network egress, remote download execution, secret access, filesystem writes, prompt override language, suspicious Unicode, and MCP-related risks;
- policy-as-code checks;
- expiring finding waivers;
- baseline creation and drift detection;
- provenance verification for policy and baseline files;
- SARIF output and GitHub code-scanning integration;
- reviewer-friendly Markdown and JSON summaries;
- GitHub Step Summary support;
- structured MCP registry drift output;
- a composite GitHub Action;
- a GitHub-first Node wrapper backed by checksummed release binaries;
- bounded release-manifest and binary downloads;
- release-binary workflows and release verification guidance.

These capabilities are release history, not future work. Keep their detailed record in `CHANGELOG.md`.

---

## Immediate Maintenance: `0.1.x`

The purpose of `0.1.x` releases is reliability, adoption, and correction. Do not add major new product surfaces in patch releases.

### Maintain GitHub Action Reliability

Keep the documented Action behavior stable:

- no `policy` means a nonblocking static scan;
- supplied `policy` means a blocking policy check;
- supplied `policy` plus `sarif-output` means policy-aware SARIF;
- supplied `baseline` plus `fail-on-drift` can block capability drift without a full policy file;
- supplied `step-summary` appends a Markdown review summary to GitHub Step Summary;
- supplied `summary-output` writes a Markdown review artifact;
- supplied `json-output` writes a machine-readable review artifact.

Maintain copy-paste examples for:

- nonblocking scan with SARIF;
- blocking policy check with policy-aware SARIF;
- baseline drift blocking;
- review-summary artifact upload.

### Maintain Release Verification

For every patch release:

- verify the concrete release tag;
- verify the stable `v0` tag;
- verify GitHub Action usage from a clean external repository;
- verify GitHub-tag Python installation;
- verify the Node wrapper from a clean environment;
- verify binary hashes and manifest sizes;
- verify unsupported-platform failures;
- verify offline cached-binary behavior.

Continue recommending:

- full commit SHA pinning for high-trust GitHub Action users;
- explicit release tags for Python installation;
- explicit `SKILLGATE_VERSION` for Node wrapper downloads.

### Maintain GitHub-First Distribution

Keep the Python implementation canonical.

Do not maintain a second scanner in TypeScript.

Current intended Node usage:

```bash
npx --yes github:charliechenye/SkillGate#v0 -- scan .
```

Maintain:

- platform-specific binary selection;
- release-manifest checksum validation;
- bounded downloads;
- cache support;
- offline cached-binary mode;
- explicit version pinning;
- clear unsupported-platform messages.

Do not promote bare:

```bash
npx skillgate scan .
```

until an npm package is intentionally published.

Do not publish the Python distribution to PyPI until the release checklist includes clean-environment installation, ownership verification, and post-publication smoke tests.

### Build Adoption Evidence

Publish neutral example reports under:

```text
docs/public-scan-reports/
```

Initial examples should include:

- one Agent Skills repository;
- one Claude or Codex skill repository;
- one MCP server or registry example;
- one repository with helper scripts;
- one repository with no high-risk findings.

Each report should include:

- immutable source revision;
- command used;
- findings summary;
- capability inventory;
- limitations;
- suggested policy;
- whether each result is a vulnerability, expected capability, or review item.

Do not shame maintainers or label a finding a vulnerability without evidence.

---

## Milestone `0.2.0`: Safe MCPB Pre-Install Scanner

This should be the next major product milestone.

MCP bundles are concrete installation artifacts. SkillGate should become useful before a user installs or runs one.

### Build A Reusable Safe-Archive Layer

Create a reusable archive-inspection foundation before adding MCPB-specific validation.

Required controls:

- reject path traversal;
- reject ZIP-slip paths;
- reject absolute paths;
- reject unsafe symlinks;
- enforce maximum file count;
- enforce maximum total uncompressed bytes;
- enforce maximum individual file size;
- enforce maximum compression ratio;
- detect nested archives;
- hash every archive member;
- delete temporary extraction directories after success or failure;
- never execute archive contents.

Use fail-closed semantics:

- exit `0`: scan completed and no blocking threshold was reached;
- exit `1`: scan completed and blocking findings were detected;
- exit `2`: bundle could not be safely or completely inspected.

### Add `mcpb scan`

Add:

```bash
skillgate mcpb scan bundle.mcpb
```

Inspect:

- `manifest.json`;
- declared server type;
- entry point;
- referenced files;
- environment variables;
- user-configurable parameters;
- bundled MCP configuration;
- bundled scripts;
- bundled package metadata;
- embedded binaries;
- remote URLs;
- localhost and private-network endpoints;
- sensitive filesystem references;
- secret references;
- startup and post-install commands.

Reuse the existing discovery and rule engine after safe extraction. MCPB should be a new source adapter, not a second scanner implementation.

### Add Bundle-Specific Findings

Only add new rule IDs where existing rules cannot express the review decision.

Candidate rules:

- malformed or unsafe MCP bundle structure;
- manifest references missing or unexpected files;
- embedded binary or nested archive requiring review.

Avoid creating a separate rule for every manifest field.

### Add Deterministic Outputs

Support:

```bash
skillgate mcpb scan bundle.mcpb
skillgate mcpb scan bundle.mcpb --format json
skillgate mcpb scan bundle.mcpb --format sarif --output skillgate.sarif
skillgate mcpb scan bundle.mcpb --manifest-output bundle-manifest.json
skillgate mcpb scan bundle.mcpb --fail-on high
```

The bundle manifest should record:

- archive SHA-256;
- scanner version;
- file count;
- total compressed and uncompressed bytes;
- every member path;
- member SHA-256;
- compressed and uncompressed sizes;
- compression ratio;
- file classification;
- whether the member was scanned or skipped;
- skip reason;
- detected entry point;
- referenced environment variables;
- embedded binaries;
- nested archives.

Add a SARIF run category:

```text
skillgate/mcp-bundle
```

### Required Fixtures

Ship the feature with hostile and normal fixtures:

- safe MCPB;
- shell startup command;
- remote endpoint;
- secret reference;
- embedded binary;
- ZIP-slip path;
- absolute path;
- unsafe symlink;
- too many files;
- oversized member;
- high compression ratio;
- nested archive;
- malformed manifest;
- missing entry point;
- suspicious package scripts.

For each fixture, assert:

- exit code;
- finding IDs;
- manifest state;
- deterministic JSON;
- cleanup of temporary files;
- no archive content was executed.

### Release Evidence

Before publishing `0.2.0`, add:

```text
docs/public-scan-reports/mcpb-example.md
```

The report should show:

- archive hash;
- bundle structure;
- entry point;
- scripts;
- endpoints;
- secret references;
- binary inventory;
- findings;
- limitations;
- what SkillGate can and cannot conclude.

---

## Milestone `0.3.0`: Agent Skills Standards Alignment

This milestone should make SkillGate useful for standards-aligned skill review.

### Add Agent Skills Validation

Add:

```bash
skillgate skills validate PATH
```

Validate:

- required `name`;
- required `description`;
- name format;
- parent-directory naming consistency;
- optional `license`;
- optional `compatibility`;
- optional `metadata`;
- experimental `allowed-tools`;
- supported optional directories:
  - `scripts/`;
  - `references/`;
  - `assets/`.

Add findings for:

- malformed frontmatter;
- missing required fields;
- invalid skill names;
- parent-directory mismatch;
- missing referenced files;
- missing license metadata;
- ambiguous compatibility declarations;
- executable files hidden outside expected directories;
- scripts referenced but missing;
- broad or ambiguous `allowed-tools`.

Treat `allowed-tools` as experimental metadata. Do not assume every agent implementation enforces it.

### Compare Declared Intent With Observed Capability

Add:

```bash
skillgate skills diff PATH
```

Compare:

- declared tools;
- declared compatibility;
- detected shell commands;
- detected network hosts;
- detected secret names;
- detected filesystem write paths;
- detected local executable references;
- detected MCP server references.

Report:

- observed but undeclared capabilities;
- declared but unused capabilities;
- newly introduced capabilities;
- removed capabilities;
- capability severity changes;
- missing scripts, references, or assets.

This should become a core SkillGate concept:

> Declared intent versus observed behavior.

### Add Policy Hooks

Allow policies to require declaration consistency:

```yaml
policy:
  skills:
    require_declared_capabilities: true
    block_undeclared_high_risk_capabilities: true
```

Keep the first implementation conservative and explain unsupported declarations clearly.

---

## Milestone `0.4.0`: MCP Security Review Pack

SkillGate already detects MCP metadata and transport risks. This milestone should make MCP security review more explicit for enterprise teams.

### Add Remote-Server Security Linting

Add best-effort static checks for:

- token-passthrough indicators;
- static bearer tokens;
- static client secrets;
- long-lived client credentials;
- unauthenticated remote endpoints;
- plain HTTP where HTTPS is expected;
- loopback bridges;
- private-network endpoints;
- link-local endpoints;
- cloud metadata endpoints;
- broad OAuth scopes;
- wildcard scopes;
- suspicious redirect URIs;
- secret-bearing remote headers;
- local servers exposed beyond loopback;
- predictable session identifiers where statically visible;
- startup commands mixing package installation, download, and execution.

Document the limit:

> Static inspection can identify risky patterns and review requirements, but it cannot prove a remote authorization flow is secure.

### Add MCP Risk Profiles

Add:

```bash
skillgate policy init --profile mcp-local
skillgate policy init --profile mcp-remote
skillgate policy init --profile mcp-enterprise
```

Profiles should make different default choices for:

- local stdio servers;
- package-backed servers;
- remote HTTP servers;
- private-network endpoints;
- secret-bearing headers;
- registry drift;
- OAuth metadata;
- startup command risk.

### Expand Registry Review

Add:

```bash
skillgate mcp registry batch-scan FILE_OR_URL
skillgate mcp registry version-diff BEFORE AFTER
```

Support:

- immutable version comparison;
- package and repository provenance;
- semantic-version changes;
- endpoint changes;
- transport changes;
- secret and header requirement changes;
- artifact-friendly output.

Keep registry comparison opt-in and deterministic.

---

## Milestone `0.5.0`: Public Benchmark And Evidence Package

This milestone should establish SkillGate as a credible community artifact, not just a CLI.

### Add Fixture Verification

Add:

```bash
skillgate fixtures verify fixtures/benchmark
```

Validate:

- expected finding IDs;
- expected capability types;
- unexpected findings;
- missing findings;
- fixture metadata;
- attribution metadata;
- deterministic output.

### Publish A Versioned Benchmark Manifest

The manifest should include:

- benchmark version;
- fixture ID;
- threat category;
- supported surface;
- expected findings;
- expected capabilities;
- source attribution;
- detector limitations;
- false-positive notes;
- false-negative notes.

### Generate A Public Benchmark Report

Add:

```bash
skillgate benchmark report fixtures/benchmark --output benchmark-report.md
```

Report:

- fixture coverage by rule;
- fixture coverage by threat category;
- surface coverage;
- maintained-fixture recall;
- known blind spots;
- unsupported surfaces;
- changes since the previous benchmark version.

Do not claim broad real-world accuracy from curated fixtures.

### Add A Fixture Contribution Guide

Create:

```text
docs/contributing-fixtures.md
```

Explain:

- how to reduce public examples into nonverbatim fixtures;
- how to add attribution;
- how to add expected findings;
- how to update snapshots;
- how to avoid secrets and exploit-ready payloads;
- how benchmark fixtures differ from regression fixtures.

---

## Milestone `0.6.0`: Provenance And Release Attestation

SkillGate already publishes release binaries and checksum manifests. The next trust step is stronger provenance.

### Strengthen Release Artifact Provenance

Include:

- source commit SHA;
- build workflow reference;
- build timestamp;
- Python version;
- platform;
- wheel and source-distribution hashes;
- binary hashes;
- clean-environment installation verification.

### Explore Standard Attestations

Evaluate:

- GitHub artifact attestations;
- Sigstore;
- in-toto attestations;
- signed SkillGate scan-result manifests;
- signed approved baselines;
- signed maintainer capability declarations.

Do not invent custom cryptography.

Do not claim SLSA compliance unless the implementation and documentation satisfy the relevant requirements.

---

## Milestone `0.7.0`: Static-To-Runtime Evidence Bridge

This should remain a later milestone. Do not start it before MCPB scanning, Agent Skills validation, MCP security profiles, and benchmark credibility are in place.

### Import Runtime Evidence

Explore:

```bash
skillgate trace import FILE
skillgate trace compare FILE --baseline skillgate.lock
```

Preserve, when available:

- MCP method name;
- protocol version;
- session ID;
- tool name;
- prompt name;
- resource URI;
- transport;
- network protocol;
- request ID;
- error type;
- response status.

Tool arguments and results must remain disabled by default and safely redacted when enabled.

### Compare Static And Observed Capability

Report:

- runtime tools absent from the approved static baseline;
- undeclared network destinations;
- undeclared write paths;
- newly observed secret references;
- dynamic MCP tool-list changes;
- unexpected transport changes;
- session-level capability drift.

Default to local processing and redaction.

### Track Dynamic Tool Registration

Support controlled, opt-in review of:

- `notifications/tools/list_changed`;
- newly registered tools;
- removed tools;
- schema changes;
- description changes;
- annotation changes;
- tool-list changes during an active session.

Do not build a runtime gateway or proxy as part of this milestone.

---

## Community And Adoption Work

Community work should run alongside product milestones without blocking core releases.

### Open Focused Starter Issues

Examples:

- `good first issue`: add one MCPB fixture;
- `good first issue`: add one Agent Skills validation fixture;
- `good first issue`: improve one public scan report;
- `help wanted`: test SkillGate on a public skill repository;
- `help wanted`: test the composite Action externally;
- `research`: map MCP security guidance to SkillGate rules;
- `research`: compare declared tools with observed capabilities;
- `docs`: improve interpretation guidance for MCP registry drift.

### Publish Technical Evidence

Potential posts:

1. **Agent skills are executable dependencies**
2. **Declared intent versus observed capability**
3. **MCP bundles need pre-install security review**
4. **What a useful agent capability review artifact should contain**

Each post should include reproducible commands and concrete artifacts.

### Contribute Upstream

Participate in MCPB, Agent Skills, MCP security, and registry discussions with:

- reduced fixtures;
- scan reports;
- detector examples;
- capability-declaration feedback;
- safe archive-scanning requirements;
- checksum and provenance suggestions.

Do not contribute only opinions. Contribute reproducible evidence.

---

## Ecosystem Watch Items

Track, but do not prioritize until formats stabilize or users request them:

- MCP Skills-over-MCP distribution;
- MCP Server Cards;
- MCP Tasks retry and expiry semantics;
- enterprise-managed MCP authorization extensions;
- OAuth client-credentials extensions;
- A2A and ACP configuration layouts;
- Agent Bill of Materials proposals;
- AI Bill of Materials proposals;
- memory-poisoning defenses;
- runtime sandbox interoperability;
- signed skill catalogs;
- MCP interceptors;
- hosted MCP registries;
- marketplace review workflows.

---

## Deferred Non-Goals

Do not build these until adoption clearly justifies them:

- hosted service;
- web dashboard;
- user accounts;
- database;
- browser extension;
- IDE extension;
- runtime execution by default;
- runtime gateway;
- MCP proxy;
- automatic remediation;
- LLM-based scoring;
- marketplace publishing;
- public leaderboard before benchmark credibility;
- second scanner implementation in TypeScript;
- broad agent framework;
- policy-management SaaS;
- custom cryptography.

---

## Release Discipline

For every release:

1. Add new work under `## Unreleased` in `CHANGELOG.md`.
2. Move completed work from `Unreleased` into the concrete release entry.
3. Remove completed items from `future_steps.md`.
4. Keep only future or ongoing work in this file.
5. Verify docs, examples, tags, binaries, manifests, and clean installs.
6. Publish a concrete artifact or example that demonstrates the release value.

Release notes should use one complete sentence per physical Markdown line so GitHub preserves readable bullets.

## Operating Principle

For every proposed feature, ask:

> Does this make SkillGate more useful for someone deciding whether to install, merge, or approve an agent skill, MCP config, or MCP bundle?

If yes, prioritize it.

If no, defer it.

For release notes, keep active `CHANGELOG.md` entries as one complete sentence
per physical line. Avoid hard-wrapping bullets or paragraphs mid-sentence so
GitHub release notes preserve the intended bullet readability.
