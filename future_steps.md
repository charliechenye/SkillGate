# Future Steps

## Recommended Next Milestone

Improve reviewer and adoption ergonomics for teams using SkillGate in CI and
pre-install workflows.

- Add reviewer-friendly PR comment output that summarizes new capabilities and links to SARIF findings.
- Support authenticated and private GitHub repositories.
- Support non-GitHub archive or source URL scanning.
- Add cache controls for repeated remote scans.
- Publish a stable hosted policy schema URL after the first tagged release.
- Add inventory diff annotations that show which trust boundaries are new since a baseline.
- Make `SG013` registry drift easier to review in CI and PR output, including local registry comparison examples and artifact-friendly JSON output.

## Trend-Informed Research Notes

Recent agent security research and industry reporting point toward four areas that fit SkillGate well:

- Agent and MCP inventory: unmanaged "shadow AI" agents increasingly behave like privileged digital identities, so teams need local and CI inventory before deeper controls.
- Tool poisoning and prompt injection: MCP tool metadata, command descriptions, and retrieved context can become control surfaces even when no code is executed.
- Provenance and attestation: MCP security proposals increasingly discuss capability attestation, origin binding, signed metadata, and traceable tool registration.
- Runtime supply-chain drift: static config review catches only part of the risk; future work should make it easy to compare static baselines with observed runtime traces.

Sources to watch:

- [What the OpenClaw vulnerability reveals about the future of agentic AI security](https://www.techradar.com/pro/what-the-openclaw-vulnerability-reveals-about-the-future-of-agentic-ai-security): useful framing for AI agents as privileged identities that need inventory, audit, patching, and least privilege.
- [MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers](https://arxiv.org/abs/2508.14925): supports fixture and benchmark work around malicious instructions embedded in MCP tool metadata.
- [MCP-ITP: An Automated Framework for Implicit Tool Poisoning in MCP](https://arxiv.org/abs/2601.07395): points toward subtle MCP cases where poisoned metadata causes a different high-privilege tool to be invoked.
- [Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning](https://arxiv.org/abs/2603.22489): reinforces static metadata analysis, decision-path visibility, and user transparency as useful defense layers.
- [Breaking the Protocol: Security Analysis of the Model Context Protocol Specification and Prompt Injection Vulnerabilities in Tool-Integrated LLM Agents](https://arxiv.org/abs/2601.17549): motivates future provenance, capability attestation, and origin authentication ideas.
- [Model Context Protocol at First Glance: Studying the Security and Maintainability of MCP Servers](https://arxiv.org/abs/2506.13538): provides empirical backing for scanning real-world MCP servers and tracking MCP-specific vulnerability categories.
- [WebMCP Tool Surface Poisoning: Runtime Manipulation Attacks on LLM Agents](https://arxiv.org/abs/2606.06387): motivates future coverage for dynamic tool surfaces, origin binding, lifecycle consistency, and traceable tool registration.
- [OpenClaw's AI skill extensions are a security nightmare](https://www.theverge.com/news/874011/openclaw-ai-skill-clawhub-extensions-security-nightmare): useful public example for why pre-install skill scanning, marketplace scrutiny, and reduced malicious-skill fixtures matter.

## Practical Product Improvements

- Add `skillgate fixtures verify` as a contributor-facing command for expected findings.
- Add `--github-token-env GITHUB_TOKEN` for authenticated GitHub API requests.
- Add registry-compare artifact examples for CI systems that want downloadable drift reports.
- Confirm the sanitized social preview image renders correctly after pushing to GitHub.
- Apply GitHub repository topics and description in the repository settings.

## MCP And Agent Ecosystem Coverage

- Add discovery for A2A/ACP-style agent protocol config files once stable public layouts emerge.
- Add opt-in live MCP tool-listing comparison in a controlled sandbox for teams that want runtime confirmation.
- Add origin binding and lifecycle consistency checks for dynamic MCP app and WebMCP tool surfaces.
- Explore signed capability manifests for skills and MCP servers, where maintainers declare intended permissions before users install.
- Support trace import/export using OpenTelemetry-compatible formats in a future release.

## Policy Ergonomics

- Add named capability groups such as `network.any`, `network.package_registry`, `shell.local_script`, `mcp.remote_http`, and `secrets.cloud`.
- Add policy explanations that describe why a specific violation blocked and which allowlist entry would approve it.
- Add policy dry-run mode that proposes the smallest policy needed to approve the current baseline.
- Add JSON Schema examples for each policy profile if the current docs do not already cover the scenario.

## Creative Ideas

- Add a trust-diff narrative mode that explains capability drift in reviewer-friendly prose.
- Add a local pre-install gate for downloaded skill/plugin bundles.
- Add generated repository badges for "SkillGate baseline present" and "SkillGate policy enforced".
- Build a public benchmark leaderboard for deterministic agent-safety scanners.
- Add a sandbox trace runner later, where runtime traces can be promoted into static regression fixtures.
- Explore a local "agent identity card" view that shows which tools, secrets, endpoints, and write paths a skill or MCP server can touch.
- Explore comparing static SkillGate findings against live MCP server tool listings in a controlled, opt-in sandbox.

## Deferred Non-Goals

- Hosted service
- Web dashboard
- User accounts
- Database
- Browser extension
- IDE extension
- Runtime execution by default
- Docker sandboxing in the MVP
- LLM-based scoring
- Automatic remediation
- Marketplace or registry publishing
