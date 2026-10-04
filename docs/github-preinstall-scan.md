# GitHub Pre-Install Skill Scans

SkillGate can scan public GitHub repositories before you install or copy AI-agent skills, Codex skills, Claude skills, MCP configurations, or related helper scripts.

```bash
skillgate github scan https://github.com/phuryn/pm-skills
skillgate github scan https://github.com/phuryn/pm-skills --ref main
skillgate github scan https://github.com/addyosmani/agent-skills/tree/main/skills
skillgate github scan https://github.com/phuryn/pm-skills --fail-on high
skillgate github scan https://github.com/phuryn/pm-skills --format sarif --output skillgate.sarif
skillgate github scan https://github.com/phuryn/pm-skills --manifest-output remote-manifest.json
```

## What Gets Downloaded

The remote scan does not clone the full repository and does not download a
repository archive. SkillGate resolves the requested branch, tag, or default
branch to an immutable commit SHA, fetches GitHub tree metadata at that SHA,
downloads only supported files, follows referenced local scripts, scans a
temporary sparse mirror, and then deletes the temporary files.

Supported remote files include:

- `SKILL.md`
- `AGENTS.md`
- `CLAUDE.md`
- `.github/copilot-instructions.md`
- `.claude/skills/**`
- `.agents/skills/**`
- `skills/**/SKILL.md`
- `agents/**`
- `.claude/commands/**`
- `.gemini/commands/**`
- `hooks/**`
- `mcp.json`
- `.mcp.json`
- `package.json`
- `pyproject.toml`
- Referenced local scripts ending in `.sh`, `.bash`, `.py`, `.js`, `.ts`, `.mjs`, `.cjs`, or `.ps1`
- Markdown files and scripts bundled under a discovered skill directory, even
  when `SKILL.md` does not name them directly

Supporting files use the same download limits and exclusions as the initial
selection. Every downloaded file is included in the static scan. Other file
types remain in the skipped-file manifest; this is not complete coverage of
arbitrary binaries or formats.

Bare names such as `Next.js` or `skills.sh` are treated as script references
only when they match a file in the repository. Explicit local paths such as
`scripts/install.sh` still produce an incomplete-scan error when missing.

## Scanning A Subdirectory

GitHub tree URLs scan only the selected subtree:

```bash
skillgate github scan https://github.com/OWNER/REPO/tree/main/path/to/skills
```

SkillGate materializes the selected subtree as the scan root, so report paths are relative to that subtree. Referenced scripts are followed only when the referenced file stays inside the selected subtree. If the URL includes a branch and `--ref` is also supplied, `--ref` wins.

For `review preinstall`, a root skill is validated against its original
repository directory name. Temporary directory names do not affect validation,
and skills discovered below the root retain their own directory-name checks.

The unified packet also distinguishes zero findings from missing review
coverage. Add `--require-complete` to reject unreviewed files or declared asset
gaps while retaining the packet:

```bash
skillgate review preinstall https://github.com/OWNER/REPO/tree/main/path/to/skills \
  --require-complete --fail-on high --json-output skillgate-review.json
```

Standard excluded paths do not alone fail this coverage gate. Other skipped
files do, including unsupported files. See the
[coverage contract and exit codes](adoption.md#review-coverage-and-exit-codes).

## Reproducible Scan Manifest

`skillgate github scan --format json` returns an object with `scan_report` and
`remote_manifest`. For text and SARIF scans, write the manifest separately:

```bash
skillgate github scan https://github.com/OWNER/REPO \
  --format sarif \
  --output skillgate.sarif \
  --manifest-output remote-manifest.json
```

The manifest records the source URL, requested ref, resolved commit SHA, scan
timestamp, downloaded relative paths, SHA-256 hashes, byte counts, skipped files
with reasons, and the resource limits used for the scan.

## Resource Limits

Remote scans use conservative defaults:

- `--max-files 100`
- `--max-total-bytes 5242880`
- `--max-file-bytes 1048576`
- `--request-timeout 30`
- `--redirect-limit 3`

Raise these only for repositories you intend to review. If a selected file,
referenced script, ref resolution, timeout, redirect, or resource limit prevents
a complete sparse scan, SkillGate exits with code `2` and does not report the
result as a successful scan.

## GitHub Code Scanning

Remote scan SARIF output uses the `skillgate/remote-github` run category. Each
finding includes a deterministic `partialFingerprints` entry, capability and
severity tags, and SkillGate capability taxa. GitHub uses those fields to group
alerts across repeated uploads, while the displayed location still points to the
current best line in the sparse scan output. In pull requests, matching alerts
appear inline when GitHub can map them to changed lines; other findings remain
available in the code-scanning alert list and uploaded SARIF artifact.

## What SkillGate Looks For

GitHub pre-install scans use the same static rules as local scans. They can detect shell execution, destructive commands, network egress, remote download execution, secret access, filesystem writes, prompt override language, suspicious Unicode, MCP server configuration, and MCP capability drift when used with baselines.

## Safety Model

SkillGate never executes remote repository content. It is a static AI-agent security scanner and MCP security scanner, not a sandbox. Use scan results as one layer in a review process before installing third-party skills or agent tooling.
