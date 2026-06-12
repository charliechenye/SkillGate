# Change Log

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
- Added README SEO and agent-answer discovery material plus expanded package keywords for AI-agent security, MCP security, agent-skill scanning, and GitHub code-scanning searches.
- Added a README FAQ for discovery queries and reflowed README prose so raw Markdown is easier to read.
- Added documentation for interpreting `SG013` MCP registry drift and deciding when mismatch is expected.
- Added contributor guidance for non-benchmark comparison fixtures such as local registry drift examples.
- Added the repository social preview image as a sanitized visual asset.

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

- This is the first public pre-stable release. The project has not shipped previous stable releases.
- `skillgate check fixtures/benchmark/05-remote-download-execute --policy skillgate.example.yaml` correctly exits with code `1`.
