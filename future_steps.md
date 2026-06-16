# Future Steps

## Product Direction

SkillGate should remain a local-first, deterministic trust gate for AI-agent skills, MCP configurations, MCP bundles, and agent-tooling supply chains.

The project should answer one practical question better than anyone else:

> Before I install, merge, or approve this agent skill or MCP server, what new capability surface does it introduce?

SkillGate should stay focused on pre-install and pre-merge review. It should not become a hosted dashboard, generic agent framework, runtime gateway, or broad observability platform until the core trust-gate workflow is widely useful.

The next milestones should prioritize:

1. Release consistency and distribution hardening
2. Safe pre-install scanning for concrete installation artifacts
3. Standards-aligned Agent Skills inspection
4. MCP-specific security review packs
5. Public benchmark credibility
6. Provenance and artifact verification
7. A controlled bridge from static analysis to runtime evidence

---

## Immediate Fixes: Do Now Before Broader Promotion

These are not long-term roadmap items. They are release-consistency and trust issues that should be fixed before a larger launch post, community push, or broader social sharing.

### 1. Validate Stable `v0` Action After `v0.1.1`

Status: pending maintainer release validation. The repo should keep README and
example workflows on `charliechenye/SkillGate@v0`; publishing `v0.1.1` and
moving the stable `v0` tag is the intended fix.

Current issue:

The README and example workflows document `step-summary`, `summary-output`, and `json-output` with `charliechenye/SkillGate@v0`, but the stable `v0` Action tag may not yet expose those inputs.

Fix this using one of two paths:

#### Preferred path

Publish `v0.1.1`, validate the release, and move the stable `v0` Action tag forward.

Acceptance criteria:

* `charliechenye/SkillGate@v0` supports:

  * `step-summary`
  * `summary-output`
  * `json-output`
* The README examples work as written.
* `docs/examples/github-action-minimal.md` works as written.
* A test repository can run the documented workflows successfully.

#### Temporary path

If `v0.1.1` is not ready, update the README and examples to mark review-summary inputs as available on `main` or planned for `v0.1.1`.

Do not leave public docs showing stable Action inputs that the stable Action does not support.

### 2. Harden Release-Binary Workflow Checkout Ref

Status: addressed in the current release-prep work. Keep this covered by
workflow structure assertions so release assets are built from the uploaded tag.

Current issue:

The release-binary workflow accepts a release tag input, then uploads assets to that tag. Manual dispatch should build the exact tag being published, not whatever branch happens to be checked out.

Fix:

* Resolve the intended release tag before checkout in every job that builds release assets.
* Use the resolved tag as the checkout ref.
* Ensure manual `workflow_dispatch` and release-published triggers both build from the same tag that receives the assets.

Acceptance criteria:

* Manual dispatch with `tag=v0.1.1` checks out `v0.1.1`.
* Release-published trigger checks out the release tag.
* The manifest records the intended release version.
* The release binary contents match the tag being published.

### 3. Prevent Accidental npm Publication

Status: addressed in the current distribution-hardening work. Keep this guard in
place until npm registry publication is intentionally chosen.

Current issue:

The root `package.json` uses the package name `skillgate`, but the project currently documents GitHub-first `npx` usage rather than npm registry publication.

Fix:

Add:

```json
"private": true
```

until an npm package name and publication strategy are intentionally chosen.

Acceptance criteria:

* `npm publish` is blocked by default.
* GitHub-first `npx --yes github:charliechenye/SkillGate#v0 -- scan .` still works.
* Docs continue to say that bare `npx skillgate scan .` is future work unless an npm registry package is intentionally published.

### 4. Add Bounded Downloads To The Node Wrapper

Status: addressed in the current distribution-hardening work. Keep these limits
covered by wrapper tests as the release manifest evolves.

Current issue:

The Node wrapper verifies SHA-256 hashes after download, but it should also bound downloads before fully buffering manifest or binary responses.

Fix:

* Add a small manifest download limit, for example 1 MB.
* Use `asset.size_bytes` from `skillgate-release.json` to bound binary downloads.
* Reject responses with `Content-Length` larger than expected.
* Reject streams that exceed the allowed byte limit.
* Prefer HTTPS by default.
* Keep `file:` support for tests.
* Require an explicit test-only flag for insecure HTTP if tests need it.

Acceptance criteria:

* Oversized manifest downloads fail before unbounded buffering.
* Oversized binary downloads fail before unbounded buffering.
* Hash verification still happens after bounded download.
* Existing tests pass.
* New tests cover oversized manifest, oversized binary, cached binary verification, and checksum mismatch.

### 5. Maintainer Validation And Publication For `v0.1.1`

`v0.1.1` should be treated as a release-consistency and adoption-hardening release, not a large feature release.

Expected contents:

* review summary command
* Markdown and JSON review summaries
* GitHub Step Summary support
* improved `SG013` registry drift review tables
* GitHub-first Node wrapper
* release-binary workflow
* distribution hardening fixes listed above

Acceptance criteria:

* `v0.1.1` GitHub Release exists.
* `v0` points to the validated `v0.1.1` commit.
* Release assets are uploaded.
* `skillgate-release.json` exists and contains correct hashes and sizes.
* GitHub-first Node wrapper works from a clean environment.
* README examples work as written.

---

## Milestone 0.1.x: Adoption And Release Hardening

This milestone keeps the published project reliable while new users try it.

### Maintain GitHub Action Adoption

Keep the composite Action behavior explicit:

* no `policy` means nonblocking static scan
* supplied `policy` means blocking policy check
* supplied `policy` plus `sarif-output` means policy-aware SARIF
* supplied `baseline` plus `fail-on-drift` means baseline drift can block CI without a full policy file
* supplied `step-summary` means a Markdown summary is appended to GitHub Step Summary
* Maintain `fail-on-drift` examples for teams that want baseline drift to block without a policy file

Maintain copy-paste examples for:

* nonblocking scan with SARIF
* blocking policy check with policy-aware SARIF
* baseline drift blocking
* review summary and JSON artifact upload

### Maintain Release Verification

Document and keep testing:

```bash
git ls-remote https://github.com/charliechenye/SkillGate.git refs/tags/v0
git ls-remote https://github.com/charliechenye/SkillGate.git refs/tags/v0.1.1
```

High-trust users should be told to pin:

* full Git commit SHA for GitHub Actions
* full Git commit SHA for GitHub install
* explicit `SKILLGATE_VERSION` for Node wrapper binary downloads

### Stabilize GitHub-First Node Distribution

Keep the Python scanner as the canonical implementation.

Do not maintain a second TypeScript scanner.

Current intended usage:

```bash
npx --yes github:charliechenye/SkillGate#v0 -- scan .
```

Maintain:

* release manifest checksum validation
* platform-specific binary selection
* cache directory support
* offline cached-binary mode
* explicit release version pinning through `SKILLGATE_VERSION`
* bounded downloads
* clear unsupported-platform errors

Do not document bare:

```bash
npx skillgate scan .
```

until an npm registry package is intentionally published.

When npm publication is ready, remove `"private": true` only as part of the
release checklist, verify `npm pack --dry-run` and `npm publish --dry-run`, and
then update README and wrapper docs to promote:

```bash
npx skillgate scan .
```

When PyPI publication is ready, publish `openevalgate-skillgate` through the
release checklist, verify a clean install, and then update README to make:

```bash
python -m pip install openevalgate-skillgate
```

the primary Python install path.

### Add Dogfood Evidence

Create a small `docs/public-scan-reports/` directory with neutral review artifacts for public skill or MCP repositories.

Guidelines:

* Do not shame maintainers.
* Do not imply a finding is a vulnerability unless it clearly is.
* Use language such as “example review artifact.”
* Include command used, resolved commit SHA, findings, limitations, and suggested policy.
* Prefer repositories that are already public examples or intentionally security-relevant fixtures.

Suggested initial reports:

* one Agent Skills repository
* one Claude skills or command repository
* one MCP server registry example
* one repository with helper scripts
* one repository with no high-risk findings, to show normal output

---

## Milestone 0.2.0: Safe MCPB Pre-Install Scanner

This should be the next major product milestone.

MCP bundles are concrete installable artifacts. SkillGate should become a useful pre-install scanner for them.

### Add MCPB Bundle Scanning

Add:

```bash
skillgate mcpb scan bundle.mcpb
```

Treat `.mcpb` as an untrusted archive. Never execute bundle contents.

Scan:

* `manifest.json`
* declared server type
* entry point
* environment variables
* user-configurable parameters
* bundled MCP configuration
* bundled scripts
* bundled package metadata
* embedded binaries
* remote URLs
* localhost and private-network endpoints
* sensitive filesystem references
* secret references
* post-install or startup commands, if present

### Add Archive Safety Controls

Required protections:

* reject path traversal
* reject ZIP-slip paths
* reject absolute paths
* reject unsafe symlinks
* enforce maximum file count
* enforce maximum total extracted bytes
* enforce maximum individual file size
* enforce decompression-ratio limits
* detect nested archives
* hash every scanned archive member
* delete temporary extraction directories
* never execute anything

### Output Requirements

`skillgate mcpb scan` should support:

```bash
skillgate mcpb scan bundle.mcpb
skillgate mcpb scan bundle.mcpb --format json
skillgate mcpb scan bundle.mcpb --format sarif --output skillgate.sarif
skillgate mcpb scan bundle.mcpb --manifest-output bundle-manifest.json
skillgate mcpb scan bundle.mcpb --fail-on high
```

Report binary files conservatively. Do not claim static analysis proves a binary is safe.

### Add Fixtures

Add fixtures for:

* safe MCPB
* MCPB with shell startup command
* MCPB with remote endpoint
* MCPB with secret reference
* MCPB with embedded binary
* MCPB with ZIP-slip path
* MCPB with too many files
* MCPB with decompression bomb pattern
* MCPB with nested archive
* MCPB with suspicious package scripts

---

## Milestone 0.3.0: Agent Skills Standards Alignment

This milestone should make SkillGate useful for standards-aligned skill review.

### Add Agent Skills Validation

Add:

```bash
skillgate skills validate PATH
```

Validate `SKILL.md` frontmatter and directory structure:

* required `name`
* required `description`
* name format
* parent-directory naming consistency
* optional `license`
* optional `compatibility`
* optional `metadata`
* experimental `allowed-tools`
* supported optional directories:

  * `scripts/`
  * `references/`
  * `assets/`

Add findings for:

* malformed frontmatter
* missing required fields
* invalid skill names
* parent directory mismatch
* missing referenced files
* missing license metadata
* ambiguous compatibility declarations
* executable files hidden outside expected directories
* scripts referenced but missing
* broad or ambiguous `allowed-tools`

Treat `allowed-tools` as experimental metadata. Report declaration mismatches clearly without assuming every agent implementation enforces the field.

### Compare Declared And Observed Capabilities

Add:

```bash
skillgate skills diff PATH
```

Compare declared intent against observed capability surface.

Inputs:

* declared tools
* declared compatibility
* detected shell commands
* detected network hosts
* detected secret names
* detected filesystem write paths
* detected local executable references
* detected MCP server references

Report:

* observed but undeclared capabilities
* declared but unused capabilities
* newly introduced capabilities
* removed capabilities
* capability severity changes
* missing script/reference/assets files

This should become a core SkillGate concept:

> declared intent versus observed behavior.

### Add Policy Hooks

Allow policies to require declaration consistency:

```yaml
policy:
  skills:
    require_declared_capabilities: true
    block_undeclared_high_risk_capabilities: true
```

Keep the first implementation conservative.

---

## Milestone 0.4.0: MCP Security Review Pack

SkillGate already detects MCP metadata and transport risks. This milestone should make MCP security review more explicit and useful for enterprise teams.

### Add MCP Remote-Server Security Linting

Add best-effort static findings for:

* token-passthrough indicators
* static bearer tokens
* static client secrets
* long-lived client credentials
* unauthenticated remote endpoints
* plain HTTP endpoints where HTTPS is expected
* loopback bridges
* private-network endpoints
* link-local endpoints
* cloud metadata endpoints
* broad OAuth scopes
* wildcard scopes
* suspicious redirect URIs
* secret-bearing remote headers
* local servers exposed beyond loopback
* predictable or static session identifiers when visible in configuration
* startup commands that mix package installation, network download, and execution

Document the limitation clearly:

> Static inspection can identify risky patterns and review requirements, but it cannot prove a remote authorization flow is secure.

### Add MCP Risk Profiles

Add policy profile templates:

```bash
skillgate policy init --profile mcp-local
skillgate policy init --profile mcp-remote
skillgate policy init --profile mcp-enterprise
```

Each profile should make different default choices around:

* local stdio servers
* package-backed servers
* remote HTTP servers
* private-network endpoints
* secret-bearing headers
* registry drift
* OAuth metadata
* startup command risk

### Expand MCP Registry Review

Add batch-oriented registry workflows:

```bash
skillgate mcp registry batch-scan FILE_OR_URL
skillgate mcp registry version-diff BEFORE AFTER
```

Support:

* immutable version comparison
* package and repository provenance
* semantic-version changes
* declared endpoint changes
* transport changes
* secret and header requirement changes
* artifact-friendly reports for downstream registries and aggregators

Keep this opt-in and deterministic.

---

## Milestone 0.5.0: Public Benchmark And Evidence Package

This milestone should establish SkillGate as a serious community artifact, not just a CLI.

### Add Contributor-Facing Fixture Verification

Add:

```bash
skillgate fixtures verify fixtures/benchmark
```

Validate:

* expected finding IDs
* expected capability types
* unexpected findings
* missing findings
* fixture metadata
* attribution metadata
* deterministic output

### Publish A Versioned Benchmark Manifest

Create a machine-readable benchmark manifest containing:

* benchmark version
* fixture ID
* threat category
* supported surface
* expected findings
* expected capabilities
* source attribution when derived from public patterns
* detector limitations
* false-positive notes
* false-negative notes

### Generate A Public Benchmark Report

Add:

```bash
skillgate benchmark report fixtures/benchmark --output benchmark-report.md
```

The report should summarize:

* fixture coverage by rule
* fixture coverage by threat category
* surface coverage:

  * Agent Skills
  * Claude skills and commands
  * Codex skills
  * MCP configs
  * MCP registry metadata
  * MCPB bundles
  * package metadata
  * helper scripts
* detector recall on the maintained fixture set
* known blind spots
* unsupported surfaces
* changes since the prior benchmark version

Do not claim broad real-world accuracy based only on curated fixtures. State the scope precisely.

### Add Community Contribution Guide For Fixtures

Create:

```text
docs/contributing-fixtures.md
```

Explain:

* how to reduce public examples into nonverbatim fixtures
* how to add attribution metadata
* how to add expected findings
* how to update snapshots
* how to avoid publishing secrets or exploit-ready payloads
* how to distinguish benchmark fixtures from regression fixtures

---

## Milestone 0.6.0: Provenance And Release Attestation

SkillGate now has release binaries and checksum manifests. The next trust step is stronger provenance.

### Strengthen Release Artifact Provenance

For SkillGate's own releases:

* build wheels and source distributions in CI
* publish checksums
* publish release manifest
* include build commit SHA
* include build workflow reference
* include build timestamp
* include Python version and platform
* verify installation from the published package in a clean environment
* document release verification workflow

### Explore Artifact Attestations

Use established signing and attestation formats rather than inventing custom cryptography.

Explore optional support for:

* GitHub artifact attestations
* Sigstore
* in-toto attestations
* signed SkillGate scan-result manifests
* signed approved baselines
* signed maintainer-declared capability manifests

Potential future workflow:

```bash
skillgate provenance attest REPORT.json
skillgate provenance verify ATTESTATION
```

Do not claim SLSA compliance unless the implementation satisfies the relevant requirements and documentation.

---

## Milestone 0.7.0: Static-To-Runtime Evidence Bridge

This should remain later. Do not jump here before MCPB scanning, Agent Skills validation, MCP security packs, and benchmark credibility.

### Align Trace Import With OpenTelemetry MCP Semantics

Add future support for importing OpenTelemetry-compatible MCP traces.

Preserve relevant fields where available:

* MCP method name
* MCP protocol version
* MCP session ID
* tool name
* prompt name
* resource URI
* transport
* network protocol
* request ID
* error type
* response status
* tool-call arguments and results only when explicitly enabled and safely redacted

### Compare Static And Observed Capabilities

Add:

```bash
skillgate trace import FILE
skillgate trace compare FILE --baseline skillgate.lock
```

Report:

* tools observed at runtime but absent from the approved static baseline
* network destinations observed but undeclared
* write paths observed but undeclared
* newly observed secret references
* dynamic MCP tool-list changes
* unexpected transport changes
* session-level capability drift

Default to redaction and local processing.

### Track Dynamic MCP Tool Registration

Add controlled, opt-in coverage for:

* `notifications/tools/list_changed`
* newly registered tools
* removed tools
* changed tool schemas
* changed descriptions
* changed annotations
* tool-list changes during an active session

Keep runtime collection disabled by default.

---

## Ecosystem Watch Items

Track these, but do not prioritize implementation until formats stabilize or users ask for them:

* MCP Skills-over-MCP distribution
* MCP Server Cards
* MCP Tasks retry and expiry semantics
* enterprise-managed MCP authorization extensions
* OAuth client-credentials extensions
* A2A and ACP configuration layouts
* Agent Bill of Materials and AI Bill of Materials proposals
* memory-poisoning defenses
* runtime sandbox interoperability
* signed skill catalogs
* MCP interceptors
* hosted MCP registries
* marketplace review workflows

---

## Community And Adoption Work

Useful projects become useful because other people can understand, try, and contribute to them.

### Open Starter Issues

Create labeled GitHub issues:

* `good first issue`: add one MCPB fixture
* `good first issue`: add one Agent Skills validation fixture
* `good first issue`: improve one public scan report
* `help wanted`: test SkillGate on a real public skill repository
* `help wanted`: test the composite Action in an external repository
* `research`: map MCP security guidance to SkillGate rules
* `research`: compare Agent Skills `allowed-tools` declarations with observed capabilities
* `docs`: write a short guide for interpreting `SG013` registry drift

### Publish Public Scan Reports

Create neutral review artifacts under:

```text
docs/public-scan-reports/
```

Each report should include:

* repository scanned
* resolved commit SHA
* command used
* findings summary
* capability inventory
* limitations
* suggested policy
* whether the result is a vulnerability, expected capability, or review item

Avoid shaming maintainers. The goal is to show how SkillGate review works.

### Write Technical Posts

Potential posts:

1. **Agent skills are executable dependencies**

   * Explain why skills, scripts, MCP configs, and package metadata should be reviewed before install.
   * Show `skillgate github scan`.
   * End with a call for fixture contributions.

2. **Declared intent versus observed capability**

   * Explain Agent Skills metadata.
   * Show how SkillGate compares declarations with detected behavior.
   * Position this as a bridge between standards and practical review.

3. **MCP bundles need pre-install security review**

   * Explain `.mcpb` as an installation artifact.
   * Show archive inspection and manifest review.
   * Explain why static review is not a sandbox replacement.

### Contribute Upstream

Participate in MCPB, Agent Skills, MCP security, and registry discussions with concrete artifacts:

* reduced fixtures
* scan reports
* detector examples
* spec feedback around capability declarations
* safe archive scanning requirements
* provenance and checksum suggestions

Do not show up with generic opinions. Show up with reproducible examples.

---

## Deferred Non-Goals

Do not build these until adoption justifies them:

* hosted service
* web dashboard
* user accounts
* database
* browser extension
* IDE extension
* runtime execution by default
* runtime gateway
* MCP proxy
* auto-remediation
* LLM-based scoring
* marketplace publishing
* public leaderboard before benchmark quality is credible
* second scanner implementation in TypeScript
* broad agent framework
* policy management SaaS

---

## Operating Principle

For each release, ask:

> Does this make SkillGate more useful for someone deciding whether to install, merge, or approve an agent skill, MCP config, or MCP bundle?

If yes, prioritize it.

If no, defer it.
