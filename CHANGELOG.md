# Change Log

## 0.1.0 - Initial public release

Initial public release of SkillGate, a deterministic static-analysis tool for
AI-agent skills, instruction files, helper scripts, and MCP configurations.

### Added

- Created the `skillgate` Python package using a `src/` layout and Python 3.11+.
- Added the `skillgate` CLI with:
  - `skillgate scan`
  - `skillgate check`
  - `skillgate baseline create`
  - `skillgate diff`
  - `skillgate github scan`
  - `skillgate rules list`
  - `skillgate explain`
  - `skillgate fixtures summary`
- Added typed Pydantic models for scanned files, findings, capabilities, scan reports, baselines, diffs, and policy results.
- Implemented deterministic recursive discovery for agent-relevant files, MCP configs, package configs, public agent-skill layouts, and referenced local scripts.
- Implemented static rules `SG001` through `SG010`:
  - Shell execution detection
  - Destructive command detection
  - Network egress detection
  - Remote download execution detection
  - Secret and credential access detection
  - Filesystem write detection
  - Prompt override language detection
  - Suspicious Unicode and obfuscation detection
  - MCP server configuration parsing
  - MCP capability drift detection
- Added richer MCP parsing for nested server maps, top-level HTTP server maps, string arguments, and transport/auth/header metadata.
- Added text, JSON, and SARIF 2.1.0 output with deterministic ordering and stable serialization.
- Added scan severity filtering and `scan --fail-on medium|high|critical` for lightweight CI gates.
- Added YAML policy evaluation for shell, filesystem write, network, secrets, MCP drift, and severity thresholds.
- Added line-aware YAML policy diagnostics for parser and schema validation errors.
- Added a Draft 2020-12 JSON Schema for SkillGate policy files and `skillgate policy schema` for machine-readable schema export.
- Added stable JSON baseline lockfile creation and baseline diffing.
- Added sparse public GitHub repository scans that fetch supported agent files and referenced scripts without cloning the full repository, including GitHub tree/subdirectory URL support.
- Added a no-install local sample at `samples/scan_installed_skills.py` for scanning installed Codex skills from a source checkout.
- Added rule documentation commands with text and JSON output.
- Added benchmark fixtures, expected finding summaries, and reduced public-pattern fixtures for Python, Node, shell, PowerShell, MCP, plugin hook, command-pack, and agent-skill layouts.
- Added golden-output snapshots for scan text, JSON, SARIF, and rule documentation output.
- Added a repo-local snapshot helper with check and accept modes plus CI artifact upload for snapshot review.
- Added a composite GitHub Action and example GitHub Actions workflow with SARIF upload support.
- Added README documentation, policy schema reference, GitHub pre-install scan docs, contributor guidance, security policy, MIT license, citation metadata, and brand asset provenance.
- Added the repository social preview image as a sanitized visual asset.

### Changed

- Tightened shell detection so Markdown references such as `scripts/build.sh` are not incorrectly counted as `sh` execution.
- Switched CLI machine-readable output to raw stdout so JSON and SARIF are not wrapped by terminal rendering.
- Deduplicated repeated policy violation messages to keep blocked output easier to review.
- Increased finding evidence length enough for MCP before/after drift details while keeping secret redaction.
- Updated the project workflow to avoid blocking on intentional benchmark fixtures while still uploading SARIF.
- Updated workflow actions for Node.js 24 and CodeQL Action v4 compatibility.

### Notes

- This is the first public pre-stable release. The project has not shipped previous stable releases.
- `skillgate check fixtures/benchmark/05-remote-download-execute --policy skillgate.example.yaml` correctly exits with code `1`.
