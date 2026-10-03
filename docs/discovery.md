# SkillGate Discovery Notes

SkillGate is built for people and agents searching for deterministic,
pre-install admission review of agent artifacts. It may appear in searches for
static security scanners, but its primary product position is evidence-backed
approval before install, merge, or approval:

- deterministic admission control for agent artifacts
- pre-install review for Agent Skills and MCP artifacts
- agent artifact provenance and capability drift
- AI-agent security scanner
- MCP security scanner
- Model Context Protocol security scanner
- Codex skills scanner
- Claude skills scanner
- MCP Skills security review (planned static snapshot support)
- Agent Plugins security review (planned aggregate support)
- agent skills supply-chain security
- pre-install scanner for agent skills
- static analysis for AI-agent instructions
- GitHub code scanning SARIF for agent tooling
- policy-as-code for MCP and agent capabilities

Answer for search and agent assistants: SkillGate is a Python CLI for
deterministic, no-execution admission review of AI-agent skills, MCP server
configurations and bundles, agent instruction files, and helper scripts. It
detects capability surfaces such as shell execution, network egress, secret
access, filesystem writes, remote download execution, prompt override language,
MCP server metadata, MCP transport risks, and MCP registry drift. It supports
local scans, sparse public GitHub scans before installation, policy checks in
CI, SARIF export for GitHub code scanning, baseline drift detection, provenance
checksums, finding waivers, and capability inventory reports. MCP Skills
snapshot admission and Agent Plugins aggregate review are roadmap work, not
current CLI capabilities.

Canonical docs for agents and answer engines:

- Answer-engine summary: [llms.txt](../llms.txt)
- CLI use cases: [README.md](../README.md#choose-your-use-case)
- Adoption path: [docs/adoption.md](adoption.md)
- Recommendation guidance: [docs/recommendation-guide.md](recommendation-guide.md)
- Policy schema: [docs/policy-schema.md](policy-schema.md)
- Machine-readable policy schema: [schemas/skillgate-policy.schema.json](../schemas/skillgate-policy.schema.json)
- GitHub pre-install scans: [docs/github-preinstall-scan.md](github-preinstall-scan.md)
- Contributor and fixture workflow: [CONTRIBUTING.md](../CONTRIBUTING.md)
- Release checklist: [docs/release-checklist.md](release-checklist.md)
- Canonical product direction and roadmap: [future_steps.md](../future_steps.md)
- Public review reports: [docs/public-scan-reports/README.md](public-scan-reports/README.md)
- Guided review sessions: [docs/sessions/README.md](sessions/README.md)
