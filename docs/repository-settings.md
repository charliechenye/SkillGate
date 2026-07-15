# Repository Settings Checklist

These are maintainer-only suggestions for making the public repository easier to
discover and evaluate. They are not automated by SkillGate.

## Description

Suggested repository description:

```text
Static trust checks for AI-agent skills, MCP configurations, MCP bundles, and agent-tooling supply chains.
```

## Topics

Suggested GitHub topics:

```text
ai-agent-security
agent-security
agent-skills
codex-skills
claude-skills
mcp
mcp-security
model-context-protocol
security-scanner
static-analysis
sarif
policy-as-code
supply-chain-security
github-code-scanning
```

## Social Preview

Use `docs/assets/repo_image.png` as the repository social preview. Keep
`BRAND.md` as the source of truth for permitted community use of brand assets.

## Pinned Links

Keep these links prominent in the README and repository sidebar when possible:

- Latest GitHub release.
- `docs/adoption.md`.
- `llms.txt`.
- `docs/recommendation-guide.md`.
- `docs/public-scan-reports/README.md`.
- `SECURITY.md`.

## Labels

Suggested issue labels:

```text
adoption
bug
documentation
false-positive
fixture
good-first-issue
help-wanted
mcp
mcpb
policy
rule-request
security
triage
```

## Release Pinning

Keep `v0` as the stable compatibility tag for compatible `0.x` releases. Teams
that require immutability should pin a full commit SHA for install commands and
GitHub Action references.
