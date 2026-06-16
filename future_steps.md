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

## Priority 0: Post-Release Adoption

### Release State

* Keep the published `v0.1.0` GitHub Release and stable `v0` Action tag
  healthy as post-release polish is reviewed.
* Treat `v0.1.0` as the immutable release tag and `v0` as the moving
  compatibility tag for compatible `0.x` Action releases.
* Keep release replacement guidance in `docs/release-checklist.md`; do not
  treat publishing the first `v0.1.0` release as pending product work.

### Tighten GitHub Action Adoption

* Keep the composite Action install path verified through `github.action_path`.
* Maintain explicit policy behavior:

  * no `policy` means nonblocking scan
  * supplied `policy` means blocking policy check
  * supplied `policy` plus `sarif-output` means policy-aware SARIF

* Maintain `fail-on-drift` so baseline drift can block CI without a full policy
  file.
* Maintain minimal copy-paste Action examples for:

  * nonblocking scan with SARIF
  * blocking policy check with policy-aware SARIF
  * baseline drift blocking

* Keep example workflows complete, including SARIF generation and explicit
  `github/codeql-action/upload-sarif` upload steps.

### Maintain Developer Ergonomics

* Keep regression tests split by subsystem so future work can load focused
  context instead of the full suite.
* Prefer small private helper modules for dense policy and MCP internals when
  the boundary is already clear and behavior remains unchanged.

### Improve Release Verification

* Document how users can verify `v0.1.0` and `v0` tags.
* Encourage commit-SHA pinning for high-trust environments.
* Confirm release install paths from a clean environment after each release.
* Confirm GitHub-tag installation works with `pip`, `pipx`, and `uv`.
* Defer PyPI publication until the GitHub-first release has customer feedback.
* Keep README badges focused on release status and product attributes. Avoid
  stars, issues, forks, or download counters until they provide useful adoption
  signal.

### Stabilize GitHub-First Node Distribution

* Keep the Python scanner as the canonical implementation.
* Do not maintain a second TypeScript scanner.
* Validate the thin Node wrapper against real GitHub Release binary assets.
* Keep the GitHub-only command documented as:

  ```bash
  npx --yes github:charliechenye/SkillGate#v0 -- scan .
  ```

* Avoid documenting bare `npx skillgate scan .` until an npm registry package is
  intentionally published.
* Keep PyPI and npm publication deferred until customer demand justifies those
  channels.

---

## Priority 1: Stabilize Pull-Request Review Ergonomics

SkillGate `0.1.1` is planned to add reviewer-friendly Markdown/JSON summaries,
optional GitHub Step Summary output, and before/after `SG013` registry drift
tables. The next review milestone should stabilize that format before adding
noisier automation.

* Collect feedback on the `skillgate review summary` Markdown structure in real
  pull requests.
* Add automated PR comments only after the Step Summary format is stable and
  concise.
* Add direct links from summaries to uploaded workflow artifacts when GitHub
  exposes stable artifact URLs to the job.
* Consider a compact Markdown capability diff report for teams that want a
  standalone file separate from the full review summary.

---

## Priority 2: Align With Agent Skills And MCP Installation Artifacts

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

## Priority 2: Add MCP Security Review Packs

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

## Priority 2: Build A Public Benchmark

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

## Priority 3: Add Provenance And Attestation

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

## Priority 3: Bridge Static Analysis And Runtime Evidence

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

## Priority 4: Ecosystem Watch Items

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
* Confirm GitHub repository description and topics using the discovery notes and
  README FAQ search phrases as the source of truth.
* Confirm the published `v0.1.0` release and stable `v0` Action tag point to
  the intended release commit.
* Confirm GitHub-tag installation with `pip`, `pipx`, and `uv`.
* Follow `docs/release-checklist.md` for local checks, package validation,
  replacement-release guidance, and deferred PyPI guidance.
* Publish the PyPI package later if customer demand or distribution needs justify
  marketplace publication.
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
