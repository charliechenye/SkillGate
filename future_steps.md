# Future Steps

## Recommended Next Milestone

Expand real-world MCP coverage and policy ergonomics.

- Expand MCP config parsing for additional real-world shapes, including nested server definitions and richer transport metadata.
- Add fixture cases from public MCP and agent-skill repositories, reduced to safe minimal examples.
- Document a contributor workflow for adding a new rule, fixture, expected findings file, and regression test together.
- Add a snapshot update workflow so intentional output changes are easy to review.
- Support GitHub tree/subdirectory URLs for scanning only part of a repository.
- Support authenticated and private GitHub repositories.
- Support non-GitHub archive or source URL scanning.
- Add cache controls for repeated remote scans.

## Practical Product Improvements

- Add snapshot update tooling for maintainers.
- Add `skillgate fixtures verify` as a contributor-facing command for expected findings.
- Add `--github-token-env GITHUB_TOKEN` for authenticated GitHub API requests.
- Add a policy schema reference page with examples for every supported field.
- Add more real-world extraction fixture cases from public skills and MCP repos.

## Creative Ideas

- Create a "capability bill of materials" view: a compact inventory of what each skill or MCP server can do.
- Add a trust-diff narrative mode that explains capability drift in reviewer-friendly prose.
- Generate a PR comment summary that groups risks by capability instead of by file.
- Add a local pre-install gate for downloaded skill/plugin bundles.
- Add repository badges for "SkillGate baseline present" and "SkillGate policy enforced".
- Build a public benchmark leaderboard for deterministic agent-safety scanners.
- Add a sandbox trace runner later, where runtime traces can be promoted into static regression fixtures.
- Support trace import/export using OpenTelemetry-compatible formats in a future release.

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
