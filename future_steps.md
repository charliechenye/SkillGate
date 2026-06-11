# Future Steps

## Recommended Next Milestone

Expand real-world MCP coverage and policy ergonomics.

- Document a contributor workflow for adding a new rule, fixture, expected findings file, and regression test together.
- Support authenticated and private GitHub repositories.
- Support non-GitHub archive or source URL scanning.
- Add cache controls for repeated remote scans.
- Publish a stable hosted policy schema URL after the first tagged release.

## Practical Product Improvements

- Add `skillgate fixtures verify` as a contributor-facing command for expected findings.
- Add `--github-token-env GITHUB_TOKEN` for authenticated GitHub API requests.
- Expand sourced fixture attribution metadata beyond README notes.
- Add schema-aware editor setup snippets for VS Code and other common editors.
- Add more public-pattern fixtures with explicit attribution metadata for each reduced case.
- Confirm the sanitized social preview image renders correctly after pushing to GitHub.
- Apply GitHub repository topics and description in the repository settings.

## Creative Ideas

- Create a "capability bill of materials" view: a compact inventory of what each skill or MCP server can do.
- Add a trust-diff narrative mode that explains capability drift in reviewer-friendly prose.
- Generate a PR comment summary that groups risks by capability instead of by file.
- Add a local pre-install gate for downloaded skill/plugin bundles.
- Add generated repository badges for "SkillGate baseline present" and "SkillGate policy enforced".
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
