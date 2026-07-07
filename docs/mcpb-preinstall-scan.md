# MCPB Pre-Install Scan

SkillGate can inspect a local MCP bundle before installation:

```bash
skillgate mcpb scan bundle.mcpb
skillgate mcpb scan bundle.mcpb --format json
skillgate mcpb scan bundle.mcpb --fail-on high
skillgate mcpb scan bundle.mcpb --manifest-output bundle-manifest.json
```

For a deterministic demo from a source checkout:

```bash
python tools/build_demo_mcpb.py --output test-outputs/reviewable-node.mcpb
skillgate mcpb scan test-outputs/reviewable-node.mcpb
```

The demo source lives in `fixtures/mcpb-demo/reviewable-node`. It intentionally
declares a runtime endpoint and secret-like configuration reference so reviewers
can see a useful pre-install result without using a real third-party bundle.

## Threat Model

The scan is a local, deterministic pre-install review. It answers what the bundle declares it will start, which files and endpoints are referenced, which secrets are named, and whether bundled executables or nested archives require review. It does not execute code, start MCP servers, install packages, resolve dependencies, fetch schemas, call registries, or perform malware analysis.

## Output Fields

Text output summarizes bundle identity, manifest version, server type, entry point, startup variants, archive members, scanned and skipped members, embedded executables, nested archives, capabilities, and findings. JSON output contains `schema_version`, `tool_version`, `bundle_manifest`, and `scan_report`; nested findings preserve normal SkillGate fingerprints.

`--manifest-output` writes only the deterministic bundle manifest: archive hash and limits, manifest summary, member states, embedded binary inventory, and nested archive paths. It is written on successful scans, including scans that later exit `1` because `--fail-on` matched.

## Exit Codes

- `0`: scan completed and no finding met `--fail-on`, or `--fail-on` was not supplied.
- `1`: scan completed and at least one finding met or exceeded `--fail-on`.
- `2`: invalid arguments, output-path conflict, fatal archive error, or fatal MCPB error.

## Limits And Cleanup

MCPB scans reuse SkillGate's bounded ZIP archive layer. Normal archive size, member count, compression, path, symlink, special-file, encryption, and extraction protections remain active. The root `manifest.json` is capped at 1,048,576 bytes and is checked before decoding.

Temporary extraction directories are removed before scan results are returned to the CLI. Stable text and JSON output must not contain the source bundle path, extraction path, raw manifest contents, environment values, user-configuration defaults, URL credentials, queries, fragments, or secret values.

## Nested Archives And Executables

Nested `.zip`, `.whl`, `.jar`, and `.mcpb` artifacts are retained, hashed, inventoried, and reported with `SG015`, but they are not opened recursively. Executable detection uses fixed prefix bytes and filename extensions for PE, ELF, thin Mach-O, `.exe`, `.dll`, `.so`, `.dylib`, and declared binary entry points. These findings are review signals, not malware verdicts.

## First-Party Source Selection

SkillGate does not scan every extracted file. It scans selected first-party text: the text entry point, scannable text under the entry-point parent, explicit local text references, top-level runtime files such as `package.json`, `pyproject.toml`, lockfiles, and root `requirements*.txt`, plus safe results from existing repository discovery. Dependency and build directories are excluded at every depth. The root `manifest.json` is never passed through generic source rules; startup declarations are analyzed separately.

## Findings

- `SG014`: MCPB startup or bundle reference mismatch, including missing entry points, missing startup or ancillary references, conflicting manifest version fields, unfamiliar server types, and obvious Node/Python entry-point extension mismatches.
- `SG015`: embedded executable, shared library, or retained nested archive requiring review.

Existing rules are reused where their semantics fit: `SG001` for shell-wrapper startup commands, `SG003` for runtime HTTP/HTTPS endpoints, and `SG005` for sensitive user-config references or secret-like environment names. Metadata URLs are listed in the manifest summary but do not create network-egress findings.

## Fatal Errors

MCPB fatal errors use stable codes such as `mcpb_manifest_missing`, `mcpb_manifest_too_large`, `mcpb_manifest_invalid_utf8`, `mcpb_manifest_invalid_json`, `mcpb_manifest_duplicate_key`, `mcpb_manifest_invalid_shape`, `mcpb_entry_point_unsafe`, and `mcpb_reference_unsafe`. Archive fatal errors are sanitized for MCPB output so local bundle paths are not shown.

## Non-Goals

This MVP does not include SARIF output for MCPB, MCPB policy schema, GitHub Action MCPB inputs, remote registry lookups, package or dependency installation, dependency resolution, recursive archive inspection, YARA, sandbox execution, malware verdicts, automatic remediation, full MCPB JSON Schema validation, or remote schema downloads.
