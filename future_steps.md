# Future Steps

## Product Direction

SkillGate should remain a local-first, deterministic trust gate for AI-agent
skills, MCP configurations, and agent-tooling supply chains.

The next milestones should prioritize:

1. Reliable open-source adoption
2. Reviewer-friendly CI workflows
3. Standards-aligned skill and MCP inspection
4. Reproducible provenance
5. A controlled bridge from static analysis to runtime evidence

SkillGate should not expand into a hosted platform, generic observability
dashboard, or broad agent framework before the core pre-install and pre-merge
workflow is widely usable.

---

## Priority 0: Ship An Adoption-Ready Release

### Publish A Tagged Release

* Publish the first tagged GitHub release as `v0.1.0`.
* Publish the Python package to PyPI.
* Add a stable GitHub Action release tag such as `v0`.
* Replace documentation examples that use `charliechenye/SkillGate@master` with a
  versioned tag such as `charliechenye/SkillGate@v0`.
* Document commit-SHA pinning for teams that require immutable GitHub Action
  references.
* Add a release checklist covering tests, linting, snapshots, benchmark fixture
  verification, package build verification, changelog updates, and release notes.

### Add Stable SARIF Alert Identity

* Emit deterministic SARIF `partialFingerprints` so GitHub code-scanning alerts
  remain stable across repeated runs and line shifts.
* Add stable SARIF run categories for:

  * local repository scans
  * remote GitHub scans
  * MCP registry comparisons
  * future MCP bundle scans
* Add tests that verify fingerprint stability when unrelated lines change.
* Document how SkillGate findings appear in pull requests and GitHub code
  scanning.

### Add Reviewable Policy Waivers

* Support narrow policy waivers with:

  * finding or capability selector
  * owner
  * reason
  * creation date
  * expiry date
  * optional issue or ticket reference
* Reject expired waivers during CI checks.
* Surface active and expired waivers in text, JSON, and SARIF output.
* Avoid broad repository-wide suppressions unless the policy explicitly allows
  them.
* Add examples showing how teams approve a known network host, shell command, or
  MCP server change without disabling the gate.

### Improve Pull-Request Review Ergonomics

* Add reviewer-friendly Markdown summary output for GitHub Actions.
* Summarize:

  * newly introduced capabilities
  * removed capabilities
  * changed trust boundaries
  * new high-risk findings
  * policy violations
  * active waivers
  * links to SARIF findings and downloadable JSON artifacts
* Add an optional GitHub Step Summary integration before implementing automated
  pull-request comments.
* Add automated PR comments only after the summary format is stable and concise.
* Make `SG013` registry drift easier to review through before-and-after tables
  and artifact-friendly JSON output.

---

## Priority 1: Align With Agent Skills And MCP Installation Artifacts

### Add Agent Skills Specification Validation

Add a standards-aligned command:

```bash
skillgate skills validate PATH
```

Validate `SKILL.md` frontmatter and directory structure:

* required `name`
* required `description`
* optional `license`
* optional `compatibility`
* optional `metadata`
* experimental `allowed-tools`
* parent-directory naming consistency
* supported optional directories:

  * `scripts/`
  * `references/`
  * `assets/`

Add findings for:

* malformed frontmatter
* missing required fields
* invalid skill names
* excessive or ambiguous compatibility requirements
* missing license metadata
* declared `allowed-tools` that are broader than necessary
* observed capabilities that are not reflected in `allowed-tools`
* instructions or scripts that reference missing files
* executable files hidden outside expected skill directories

Treat `allowed-tools` as experimental metadata. Report declaration mismatches
clearly without assuming that every agent implementation enforces the field.

### Compare Declared And Observed Capabilities

Add an explicit declaration-diff workflow:

```bash
skillgate skills diff PATH
```

Compare:

* declared tools
* detected shell commands
* network hosts
* secret names
* filesystem write paths
* local executable references
* MCP server references

Report:

* undeclared observed capabilities
* declared but unused capabilities
* newly introduced capabilities
* removed capabilities
* capability severity changes

This should become a core SkillGate concept: declared intent versus observed
behavior.

### Add Safe `.mcpb` Bundle Scanning

Add:

```bash
skillgate mcpb scan bundle.mcpb
```

Treat MCP Bundles as untrusted ZIP archives. Never execute bundle contents.

Validate:

* archive format
* `manifest.json`
* declared server type
* entry point
* environment variables
* user-configurable parameters
* MCP configuration
* bundled scripts
* bundled package metadata
* embedded binaries
* network references
* sensitive filesystem references

Add archive safety controls:

* reject path traversal and ZIP-slip paths
* reject absolute paths
* reject unsafe symlinks
* enforce file-count and byte-size limits
* enforce decompression-ratio limits
* detect nested archives
* calculate SHA-256 hashes for extracted members
* delete temporary files after scanning

Report binary files conservatively. Do not claim that static analysis proves a
binary safe.

### Support Downloaded Skill And Plugin Bundles

Generalize the pre-install workflow for local archives:

```bash
skillgate archive scan FILE
```

Support an intentionally small initial set of formats:

* `.zip`
* `.tar.gz`
* `.tgz`
* `.mcpb`

Apply the same extraction safety limits and scan manifest format used for remote
repository scans.

---

## Priority 1: Add MCP Security Review Packs

### Add MCP Remote-Server Security Linting

Add best-effort static findings for suspicious MCP security patterns:

* token-passthrough indicators
* static bearer tokens in configuration
* long-lived client secrets
* unauthenticated remote endpoints
* plain HTTP endpoints where HTTPS is expected
* loopback, private-network, link-local, and cloud-metadata endpoints
* overly broad OAuth scopes
* wildcard scopes
* suspicious redirect URIs
* remote headers containing secret references
* local servers exposed beyond loopback
* predictable or static session identifiers when visible in configuration
* startup commands that mix package installation, network download, and
  execution

Document the limitation clearly: static inspection can identify risky patterns
and review requirements, but it cannot prove that a remote authorization flow is
secure.

### Expand MCP Apps And Dynamic Tool-Surface Review

Deepen existing MCP Apps and WebMCP-style metadata coverage:

* compare UI resource URIs
* detect newly introduced external origins
* diff CSP-like origin allowlists
* diff microphone, camera, clipboard, and other device permissions
* detect newly introduced postMessage-style communication surfaces
* detect dynamic tool registration metadata
* detect lifecycle changes that expand the tool surface after initialization

Report these as trust-boundary changes, not merely text-pattern findings.

### Track MCP Server Cards

Monitor the MCP Server Card work and add support when the schema stabilizes.

Future workflow:

```bash
skillgate mcp server-card scan URL
skillgate mcp server-card compare URL --config .mcp.json
```

Compare Server Card declarations with:

* local MCP configuration
* MCP registry metadata
* approved baseline
* package identifiers
* remote endpoints
* authentication requirements
* declared tools and capabilities

Support `.well-known` discovery only after the public schema is stable.

### Expand MCP Registry Scanning

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

## Priority 1: Build A Public Benchmark

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

Generate a public report summarizing:

* fixture coverage by rule
* fixture coverage by threat category
* detector recall on the maintained fixture set
* known blind spots
* unsupported surfaces
* changes since the prior benchmark version

Do not claim broad real-world accuracy based only on curated fixtures. State the
scope precisely.

---

## Priority 2: Add Provenance And Attestation

### Verify Existing Provenance More Rigorously

Extend current checksum provenance manifests with:

* schema version
* generated timestamp
* source URL
* requested ref
* resolved immutable revision
* scanner version
* policy hash
* baseline hash
* file hashes
* scan-result hash

### Explore Signed Attestations

Use established signing and attestation formats rather than inventing custom
cryptography.

Explore optional support for:

* Sigstore
* in-toto attestations
* GitHub artifact attestations
* signed SkillGate scan-result manifests
* signed approved baselines
* signed maintainer-declared capability manifests

Potential workflow:

```bash
skillgate provenance attest REPORT.json
skillgate provenance verify ATTESTATION
```

Do not claim SLSA compliance unless the implementation satisfies the relevant
requirements and documentation.

### Add Release Artifact Provenance

For SkillGate's own releases:

* build wheels and source distributions in CI
* publish checksums
* publish release notes
* generate artifact attestations where supported
* verify installation from the published package in a clean environment
* document the release verification workflow

---

## Priority 2: Bridge Static Analysis And Runtime Evidence

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
* tool-call arguments and results only when explicitly enabled and safely
  redacted

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

### Explore Interceptor-Compatible Policy Export

Monitor MCP interceptor standardization.

Explore exporting selected SkillGate policies as validator or audit-mode
configurations for future MCP interceptor implementations.

Do not build a gateway or runtime proxy until a stable interoperability target
exists.

---

## Priority 3: Ecosystem Watch Items

Track, but do not prioritize implementation until formats stabilize:

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

---

## Operational Launch Checklist

Move one-time administrative tasks out of the product roadmap:

* Confirm the social-preview image renders correctly on GitHub.
* Confirm GitHub repository description and topics.
* Publish `v0.1.0`.
* Publish the PyPI package.
* Confirm installation with `pip`, `pipx`, and `uvx`.
* Replace `@master` Action examples with a versioned tag.
* Create a minimal launch post and demo GIF.
* Open GitHub Discussions or use Issues for community feedback.
* Track package downloads, GitHub Action usage, stars, forks, external mentions,
  and contributed fixtures.

---

## Deferred Non-Goals

Do not prioritize:

* hosted service
* web dashboard
* user accounts
* database
* browser extension
* IDE extension
* runtime execution by default
* Docker sandboxing in the initial releases
* LLM-based scoring
* automatic remediation
* marketplace or registry publishing
* enterprise RBAC
* custom cryptography
* a generic agent framework
