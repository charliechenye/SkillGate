# GitHub Pre-Install Skill Scans

SkillGate can scan public GitHub repositories before you install or copy AI-agent skills, Codex skills, Claude skills, MCP configurations, or related helper scripts.

```bash
skillgate github scan https://github.com/phuryn/pm-skills
skillgate github scan https://github.com/phuryn/pm-skills --ref main
skillgate github scan https://github.com/phuryn/pm-skills --fail-on high
skillgate github scan https://github.com/phuryn/pm-skills --format sarif --output skillgate.sarif
```

## What Gets Downloaded

The remote scan does not clone the full repository and does not download a repository archive. SkillGate fetches GitHub tree metadata, downloads only supported files, follows referenced local scripts, scans a temporary sparse mirror, and then deletes the temporary files.

Supported remote files include:

- `SKILL.md`
- `AGENTS.md`
- `CLAUDE.md`
- `.github/copilot-instructions.md`
- `.claude/skills/**`
- `.agents/skills/**`
- `mcp.json`
- `.mcp.json`
- `package.json`
- `pyproject.toml`
- Referenced local scripts ending in `.sh`, `.bash`, `.py`, `.js`, `.ts`, `.mjs`, `.cjs`, or `.ps1`

## What SkillGate Looks For

GitHub pre-install scans use the same static rules as local scans. They can detect shell execution, destructive commands, network egress, remote download execution, secret access, filesystem writes, prompt override language, suspicious Unicode, MCP server configuration, and MCP capability drift when used with baselines.

## Safety Model

SkillGate never executes remote repository content. It is a static AI-agent security scanner and MCP security scanner, not a sandbox. Use scan results as one layer in a review process before installing third-party skills or agent tooling.
