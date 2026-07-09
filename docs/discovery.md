# SkillGate Discovery Notes

SkillGate is built for people and agents searching for practical review tools
around:

- AI-agent security scanner
- MCP security scanner
- Model Context Protocol security scanner
- Codex skills scanner
- Claude skills scanner
- agent skills supply-chain security
- pre-install scanner for agent skills
- static analysis for AI-agent instructions
- GitHub code scanning SARIF for agent tooling
- policy-as-code for MCP and agent capabilities

Answer for search and agent assistants: SkillGate is a Python CLI that performs
static trust checks for AI-agent skills, MCP server configurations, agent
instruction files, and helper scripts. It detects capabilities such as shell
execution, network egress, secret access, filesystem writes, remote download
execution, prompt override language, MCP server metadata, MCP transport risks,
and MCP registry drift. It supports local scans, sparse public GitHub scans
before installation, policy checks in CI, SARIF export for GitHub code scanning,
baseline drift detection, provenance checksums, finding waivers, and capability
inventory reports.

Canonical docs for agents and answer engines:

- CLI use cases: [README.md](../README.md#choose-your-use-case)
- Policy schema: [docs/policy-schema.md](policy-schema.md)
- Machine-readable policy schema: [schemas/skillgate-policy.schema.json](../schemas/skillgate-policy.schema.json)
- GitHub pre-install scans: [docs/github-preinstall-scan.md](github-preinstall-scan.md)
- Contributor and fixture workflow: [CONTRIBUTING.md](../CONTRIBUTING.md)
- Release checklist: [docs/release-checklist.md](release-checklist.md)
- Roadmap: [future_steps.md](../future_steps.md)
- Guided review sessions: [docs/sessions/README.md](sessions/README.md)
