# Change Log

## 0.2.0 - Local skills and sparse GitHub scans

### Added

- Added `skillgate github scan URL` for sparse pre-install scans of public GitHub repositories.
- Added sparse GitHub fetching that downloads only relevant agent files and referenced local scripts.
- Added a no-install local sample at `samples/scan_installed_skills.py` for scanning installed Codex skills from a source checkout.
- Added local Codex root discovery for `CODEX_HOME` or the default `.codex` home.
- Added mocked tests for GitHub URL parsing, sparse fetching, remote scan output, fail-on behavior, cleanup, and local sample behavior.
- Added richer policy schema validation for known sections, allowed keys, and field types.
- Added more Python, Node, shell, and PowerShell extraction patterns for filesystem writes, network egress, and destructive actions.
- Added `skillgate fixtures summary` for machine-readable benchmark fixture reporting.
- Added a policy schema reference page with examples for every supported field.
- Added reduced public-pattern benchmark fixtures for Python, Node, shell, PowerShell, and MCP extraction cases.
- Added SEO/AEO-oriented README sections, contributor guidance, security policy, and a focused GitHub pre-install scan documentation page.
- Added the repository social preview image as a versioned README asset.

### Changed

- Bumped package version to `0.2.0`.
- Documented local installed-skill scans and remote sparse GitHub pre-install scans.
- Updated practical improvement tracking to remove completed policy, extraction, and fixture summary items.
- Linked the policy schema reference from the README and documented the new public-pattern fixture coverage.
- Updated package metadata and GitHub Action metadata for repository and package discovery.
- Documented the social preview asset in the public README.

## 0.1.1 - CLI rule documentation and filtering

### Added

- Added `skillgate rules list` to print supported rule IDs, default severity, capability type, title, and remediation.
- Added `skillgate explain RULE_ID` for concise terminal documentation of a single rule.
- Added `skillgate scan --severity informational|low|medium|high|critical` as a minimum-severity finding filter.
- Added `skillgate scan --fail-on medium|high|critical` for lightweight scan-only CI failure thresholds.
- Added JSON output for `skillgate rules list` and `skillgate explain`.
- Added line-aware policy diagnostics for YAML parse errors and selected MVP semantic validation errors.
- Added richer filesystem write target extraction for common Python and Node patterns.
- Added safer network host extraction from package scripts, command arguments, and MCP string fields.
- Added benchmark fixture expectation validation against `expected-findings.yaml`.
- Added golden-output snapshots for scan text, JSON, SARIF, and rule documentation output.
- Added a static rule documentation registry used by the new CLI documentation commands.
- Added tests for rule listing, rule explanation, case-insensitive rule IDs, unknown rule handling, and filtered text, JSON, and SARIF scan output.

### Changed

- Scan severity filtering leaves scanned files and capabilities unchanged but recomputes finding summary counts to match displayed findings.
- `scan --fail-on` evaluates the final displayed report after `--severity` filtering.
- Updated README examples for rule documentation commands, severity-filtered scans, fail-on thresholds, JSON rule docs, and policy diagnostics.
- Moved completed practical improvements out of `future_steps.md`.

## 0.1.0 - SkillGate MVP

Initial OpenEvalGate SkillGate implementation.

### Added

- Created the `skillgate` Python package using a `src/` layout and `pyproject.toml`.
- Added the `skillgate` CLI with:
  - `skillgate scan`
  - `skillgate check`
  - `skillgate baseline create`
  - `skillgate diff`
- Added typed Pydantic models for scanned files, findings, capabilities, scan reports, baselines, diffs, and policy results.
- Implemented deterministic recursive discovery for agent-relevant files, MCP configs, package configs, and referenced local scripts.
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
- Added stable terminal, JSON, and SARIF 2.1.0 output.
- Added YAML policy evaluation for shell, filesystem write, network, secrets, MCP drift, and severity thresholds.
- Added stable JSON baseline lockfile creation and baseline diffing.
- Added public benchmark fixtures under `fixtures/benchmark/`.
- Added pytest coverage for discovery, rules, redaction, MCP parsing, policy checks, baselines, diffs, JSON, SARIF, and CLI behavior.
- Added a composite GitHub Action and example GitHub Actions workflow.
- Added README documentation, example policy, MIT license, and project `.gitignore`.

### Changed

- Tightened shell detection so Markdown references such as `scripts/build.sh` are not incorrectly counted as `sh` execution.
- Switched CLI machine-readable output to raw stdout so JSON and SARIF are not wrapped by terminal rendering.
- Deduplicated repeated policy violation messages to keep blocked output easier to review.
- Increased finding evidence length enough for MCP before/after drift details while keeping secret redaction.

### Verified

- `pip install -e .`
- `skillgate --help`
- `skillgate scan fixtures/benchmark/02-shell-execution`
- `skillgate scan fixtures/benchmark/05-remote-download-execute`
- `skillgate scan fixtures/benchmark/06-secret-access`
- `skillgate scan fixtures/benchmark/10-mcp-config`
- `skillgate baseline create fixtures/benchmark/11-mcp-capability-drift-before --output C:\tmp\skillgate.lock`
- `skillgate diff fixtures/benchmark/12-mcp-capability-drift-after --baseline C:\tmp\skillgate.lock`
- `skillgate check fixtures/benchmark/05-remote-download-execute --policy skillgate.example.yaml`
- `pytest`
- `ruff check .`
- `ruff format --check .`

### Notes

- `skillgate check fixtures/benchmark/05-remote-download-execute --policy skillgate.example.yaml` correctly exits with code `1`.
- On this Windows environment, the user Python Scripts directory was not on `PATH`; the installed CLI was verified by adding that directory to the shell path for the check.
