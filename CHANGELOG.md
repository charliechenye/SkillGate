# Change Log

## Unreleased - Review evidence foundations

### Added

- Added deterministic pre-install packet digests, scanned-file manifests, skipped-file accounting, richer Markdown evidence, and a public review packet JSON Schema.
- Added `skillgate review schema` for exporting the review packet contract.

### Changed

- Fixed GitHub pre-install packets so source identity prefers the resolved immutable commit SHA.
- Made capability baselines stable across source-line movement and expanded MCP drift evidence to include all changed metadata fields.

## 0.1.2 - Guided review workflows

Released 2026-07-09.

### Added

- Added `skillgate demo skill` for a packaged deterministic Agent Skill review input that can be validated and scanned without executing helper files.
- Added guided review sessions for first local review, pre-install review, and policy/baseline approval workflows.
- Added `skillgate mcpb scan` for deterministic pre-install inspection of MCP bundles without executing server content.
- Added text, JSON, and SARIF MCPB reports with startup metadata, member scan state, embedded-artifact inventory, and optional bundle manifest output.
- Added composite Action inputs for scanning committed MCPB artifacts and emitting separate MCPB SARIF for GitHub code scanning.
- Added `SG014` for MCPB startup and reference mismatches and `SG015` for embedded executables and retained nested archives requiring review.
- Added `skillgate --version` for quick CLI identity checks.
- Added `skillgate demo mcpb` for a packaged deterministic first run MCPB demo with optional immediate scan output.
- Added a deterministic MCPB demo source fixture and builder for public scan reports and release smoke tests.
- Added `skillgate skills validate` for deterministic Agent Skills structure and metadata validation without code execution.
- Added Agent Skills validation fixtures and documentation covering frontmatter, tool declarations, local references, and misplaced executables.
- Added public scan report examples for a clean documentation skill, a remote download review item, and a reviewable MCPB bundle.
- Added a reusable, bounded ZIP inspection foundation with deterministic archive and member manifests for future MCPB pre-install scanning.
- Added fail-closed protections for unsafe paths, duplicate normalized entries, path type collisions, symlinks, special files, nested archives, unsupported compression, encryption, and resource limit violations.
- Added streaming archive and member hashing with automatic temporary file cleanup and no execution of extracted content.

### Changed

- Bumped the Python and Node wrapper metadata to `0.1.2` for this release.
- Expanded first run README onboarding from one MCPB demo to paired Agent Skill and MCPB demos, with explicit reviewer decision checkpoints.
- Simplified README onboarding around pre-install scans, pre-merge scans, and policy enforcement before advanced workflows.
- Updated the release checklist with explicit PyPI, `pipx`, `uvx`, and yanking/rollback validation steps.
- Reorganized the archive inspection foundation into focused internal modules without changing its safety behavior, stable errors, or manifest contract.

### Fixed

- Kept intentional demo and test findings visible in local and pull request scans while making SARIF Code Scanning publication non blocking for pull request CI.

## 0.1.1 - Release consistency and review ergonomics

### Added

- Added `skillgate review summary` for reviewer-friendly Markdown and JSON summaries of introduced capabilities, removed capabilities, changed trust boundaries, high-risk findings, policy violations, active waivers, and artifact locations.
- Added optional composite Action inputs for Markdown review summaries, machine-readable review JSON artifacts, and GitHub Step Summary output.
- Added Markdown output for `skillgate mcp registry compare` so `SG013` registry drift is easier to review through before-and-after tables.
- Added a GitHub-first Node wrapper for `npx --yes github:charliechenye/SkillGate#v0 -- ...` usage, backed by checksummed GitHub Release binaries instead of PyPI or npm registry publication.
- Added bounded Node wrapper downloads so release manifests are limited to 1 MB and binary downloads are capped by `asset.size_bytes` before buffering.

### Changed

- Extended MCP registry comparison JSON summaries with structured `registry_drift` rows for artifact-friendly review.
- Updated GitHub Action examples to include review summaries, downloadable review JSON artifacts, and standard artifact upload steps.
- Added README release and product-attribute badges that showcase the latest release, static analysis, no runtime execution, and policy-as-code without surfacing early social-traction counters.
- Added a release-binary workflow and manifest builder so future stable GitHub Releases can publish verified platform binaries for the Node wrapper.
- Hardened the release-binary workflow so manual dispatch and release-published runs check out the exact tag that receives the uploaded assets.
- Marked the root npm package private to prevent accidental registry publication until the package name and npm strategy are intentionally chosen.
- Documented the Node wrapper's HTTPS default, test-only insecure HTTP escape hatch, and future npm and PyPI publication steps.
- Formatted the active changelog release entry without hard-wrapped mid-sentence lines so GitHub release notes preserve intended bullet readability.
- Updated future planning state after publishing `v0.1.1` as the stable release.
- Upgraded GitHub artifact workflows to `actions/upload-artifact@v7` and `actions/download-artifact@v8` while preserving archived uploads, merged extraction, and fail-closed digest verification.
- Clarified the adoption and release-hardening roadmap after `v0.1.1` so ongoing Action behavior, release verification, GitHub-first Node distribution, and public example reports are easier to maintain.

## 0.1.0 - Initial public release

Initial public release of SkillGate, a deterministic static-analysis tool for
AI-agent skills, instruction files, helper scripts, and MCP configurations.

### Added

**Core CLI and data model**

- Created the `skillgate` Python package using a `src/` layout and Python 3.11+.
- Added typed Pydantic models for scanned files, findings, capabilities, scan reports, baselines, diffs, policy results, and stable JSON serialization.
- Added the `skillgate` CLI with scan, check, diff, baseline, GitHub scan, MCP registry scan/compare, inventory, policy, provenance, rules, explain, and fixture-summary commands.
- Added scan severity filtering and `scan --fail-on medium|high|critical` for lightweight CI gates.
- Added rule documentation commands with text and JSON output.

**Static analysis and discovery**

- Implemented deterministic recursive discovery for agent-relevant files, MCP configs, package configs, public agent-skill layouts, and referenced local scripts.
- Implemented static rules `SG001` through `SG013` for shell execution, destructive commands, network egress, remote download execution, secret access, filesystem writes, prompt override language, Unicode obfuscation, MCP server configuration, MCP capability drift, MCP tool metadata risks, MCP transport risks, and MCP registry drift.
- Added richer MCP parsing for nested server maps, top-level HTTP server maps, string arguments, transport/auth/header metadata, endpoint extraction, and secret-name detection.
- Added MCP registry metadata discovery for `mcp-registry.json`, `mcp-server.json`, and MCP registry-style `server.json` files without installing or starting servers.
- Added static MCP tool metadata checks for hidden instructions, suspicious or lookalike tool names, high-risk input schema fields, MCP Apps/WebMCP-style origin and UI hints, and mid-session tool registration concepts.
- Added known dangerous MCP transport checks for stdio package transports, shell wrappers, localhost/private-network bridges, unauthenticated remote endpoints, and secret-bearing remote headers.
- Added opt-in MCP registry comparison for local-vs-registry repository URLs, package identifiers, remote URLs, transport types, versions, and secret/header requirements.
- Added sparse public GitHub repository scans that fetch supported agent files and referenced scripts without cloning the full repository, including GitHub tree/subdirectory URL support.
- Added reproducible remote GitHub scan manifests with resolved commit SHAs, downloaded file hashes, skipped-file reasons, byte counts, and resource limits.
- Added remote GitHub scan resource limits for file count, total bytes, individual file size, request timeout, and redirect count.
- Added a no-install local sample at `samples/scan_installed_skills.py` for scanning installed Codex skills from a source checkout.

**Policy, baselines, and provenance**

- Added YAML policy evaluation for shell, command allowlists, filesystem write allowlists, network host and category allowlists, secret environment allowlists, MCP drift, and severity thresholds.
- Added named policy capability groups for common shell, network, MCP remote HTTP, and cloud secret review decisions.
- Added policy violation explanations, approval hints, and structured suggested policy additions.
- Added `skillgate check --dry-run` for advisory policy blocking output and suggested approvals without a failing exit code.
- Added expiring, reviewable finding waivers with owner, reason, dates, optional ticket metadata, text/JSON/SARIF output, and separate documentation for durable capability approvals.
- Added line-aware YAML policy diagnostics for parser and schema validation errors.
- Added a Draft 2020-12 JSON Schema for SkillGate policy files and `skillgate policy schema` for machine-readable schema export.
- Added `skillgate policy init` starter templates for audit, preinstall, strict, and MCP-focused adoption modes.
- Added stable JSON baseline lockfile creation and baseline diffing.
- Added checksum provenance manifests for approved policy and baseline files.

**Output, SARIF, and inventory**

- Added text, JSON, and SARIF 2.1.0 output with deterministic ordering.
- Added SARIF capability tags, result metadata, and capability taxa for easier GitHub code scanning filtering.
- Added stable SARIF alert fingerprints and run categories for local repository scans, remote GitHub scans, MCP registry comparisons, and future MCP bundle scans.
- Added shared stable finding fingerprints for SARIF, JSON output, and reviewable finding waivers.
- Added exact validation and matching for fingerprint-based finding waivers.
- Added capability inventory output with trust-boundary summaries for local execution, remote endpoints, secrets, generated files, MCP servers, prompt controls, and obfuscation.
- Added inventory filters for capability type, severity, and source file globs.

**Fixtures and regression workflow**

- Added benchmark fixtures, expected finding summaries, and reduced public-pattern fixtures for Python, Node, shell, PowerShell, MCP, plugin hook, command-pack, local bridge, metadata, MCP registry, MCP tool metadata, MCP Apps/WebMCP-style metadata, dangerous transport, and agent-skill layouts.
- Added machine-readable attribution metadata for public-pattern fixtures and fixture summary JSON output.
- Added golden-output snapshots for scan text, JSON, SARIF, and rule documentation output.
- Added a repo-local snapshot helper with check and accept modes plus CI artifact upload for snapshot review.

**Integrations and documentation**

- Added a composite GitHub Action and example GitHub Actions workflow with SARIF upload and optional provenance verification support.
- Added README documentation, policy schema reference, schema-aware editor setup snippets, GitHub pre-install scan docs, contributor workflow guidance, security policy, MIT license, citation metadata, and brand asset provenance.
- Restructured the README around supported use cases, clearer getting-started paths, and direct links to policy, schema, GitHub scan, SARIF, MCP, and contributor documentation.
- Added discovery and agent-answer documentation plus expanded package keywords for AI-agent security, MCP security, agent-skill scanning, and GitHub code-scanning searches.
- Added a README FAQ for discovery queries and reflowed README prose so raw Markdown is easier to read.
- Added release-ready GitHub tag install and GitHub Action guidance, including the stable `v0` Action tag, commit-SHA pinning guidance, a deferred PyPI path, and a maintainer release checklist.
- Added release trust fixes for the GitHub-first `v0.1.0` release, including the noncolliding `openevalgate-skillgate` distribution name, canonical repository metadata, explicit Action policy behavior, and bounded remote reads.
- Added release polish for policy-aware SARIF Action ordering, published-release roadmap state, and safer waiver guidance.
- Added baseline drift blocking with `skillgate diff --fail-on-drift`, a matching composite Action input, minimal GitHub Action examples, release tag verification guidance, and Dependabot configuration.
- Expanded release-polish regression coverage for baseline drift blocking, exact fingerprint waivers, composite Action behavior, and complete SARIF upload examples.
- Modernized package license metadata to use SPDX-style `license` and `license-files` fields without deprecated license classifiers.
- Added documentation for interpreting `SG013` MCP registry drift and deciding when mismatch is expected.
- Added contributor guidance for non-benchmark comparison fixtures such as local registry drift examples.
- Added the repository social preview image as a sanitized visual asset.
- Split the monolithic regression test module into focused test files and extracted policy waiver helpers without changing public behavior.

### Changed

**Detection behavior**

- Tightened shell detection so Markdown references such as `scripts/build.sh` are not incorrectly counted as `sh` execution.
- Increased finding evidence length enough for MCP before/after drift details while keeping secret redaction.

**CLI and reporting behavior**

- Switched CLI machine-readable output to raw stdout so JSON and SARIF are not wrapped by terminal rendering.
- Deduplicated repeated policy violation messages to keep blocked output easier to review.

**CI and project workflow**

- Updated the project workflow to avoid blocking on intentional benchmark fixtures while still uploading SARIF.
- Updated workflow actions for Node.js 24 and CodeQL Action v4 compatibility.

### Notes

- This is the first public release of SkillGate.
- `skillgate check fixtures/benchmark/05-remote-download-execute --policy skillgate.example.yaml` correctly exits with code `1`.
