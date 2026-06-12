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

## Scanning A Subdirectory

GitHub tree URLs scan only the selected subtree:

```bash
skillgate github scan https://github.com/OWNER/REPO/tree/main/path/to/skills
```

SkillGate materializes the selected subtree as the scan root, so report paths are relative to that subtree. Referenced scripts are followed only when the referenced file stays inside the selected subtree. If the URL includes a branch and `--ref` is also supplied, `--ref` wins.

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

## What SkillGate Looks For

GitHub pre-install scans use the same static rules as local scans. They can detect shell execution, destructive commands, network egress, remote download execution, secret access, filesystem writes, prompt override language, suspicious Unicode, MCP server configuration, and MCP capability drift when used with baselines.

## Safety Model

SkillGate never executes remote repository content. It is a static AI-agent security scanner and MCP security scanner, not a sandbox. Use scan results as one layer in a review process before installing third-party skills or agent tooling.
