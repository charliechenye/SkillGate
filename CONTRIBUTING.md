# Contributing To SkillGate

Thanks for helping improve SkillGate. The project is a deterministic static scanner for AI-agent skills, MCP configurations, instruction files, and helper scripts, so changes should stay stable, reviewable, and easy to reproduce.

## Development Setup

```bash
python -m pip install -e ".[dev]"
python -m pytest
python tools/update_snapshots.py --check
python -m ruff check .
python -m ruff format --check .
```

Use Python 3.11 or newer. The repository uses LF line endings through `.gitattributes`.

## Contribution Workflow

1. Open an issue or describe the behavior you want to change.
2. Keep changes narrowly scoped.
3. Add or update tests for scanner behavior, CLI output, policy diagnostics, or fixtures.
4. Update `CHANGELOG.md` and `future_steps.md` when the user-facing behavior or roadmap changes.
5. Run the full verification commands before submitting a pull request.

## Adding A Rule Or Detector

Rules should be deterministic and static. Do not execute repository code, call LLMs, access external services, or add telemetry.

Use this workflow when adding detection behavior:

1. Add or update the scanner rule with a stable rule ID and deterministic ordering.
2. Add or update rule metadata in the rule documentation registry so `skillgate rules list` and `skillgate explain` stay complete.
3. Add a reduced benchmark fixture under `fixtures/benchmark/`.
4. Add `expected-findings.yaml` with the exact expected rule IDs.
5. Add a focused regression test in `tests/test_skillgate.py`.
6. Run `python -m skillgate fixtures summary fixtures/benchmark --format json`.
7. Update golden snapshots only when public CLI output intentionally changes.
8. Update `CHANGELOG.md` and `future_steps.md` for user-facing or roadmap changes.

Detection rules must redact secret values and report names such as `GITHUB_TOKEN`.
Prefer conservative extraction. If a host or path is uncertain, keep the resource
unknown rather than inventing a value.

## Adding Benchmark Fixtures

Benchmark fixtures should be small, safe, and reproducible. Public-pattern fixtures should be reduced and nonverbatim unless the source license and attribution are explicitly handled.

Name new fixtures with a two-digit sequence and a short behavior label, such as
`22-public-pattern-mcp-tool-poisoning`. Keep examples synthetic or reduced from
public patterns; do not vendor upstream content verbatim.

Each fixture should include:

- A short `README.md`.
- One or more supported agent files or referenced scripts.
- `expected-findings.yaml` with the expected rule IDs.

Verify fixtures with:

```bash
python -m skillgate fixtures summary fixtures/benchmark --format json
```

## Adding Non-Benchmark Comparison Fixtures

Use non-benchmark fixtures for workflows that require two inputs, mocked remote
metadata, or command-specific comparison behavior. For example,
`fixtures/registry-compare-drift` demonstrates `SG013` by comparing local MCP
registry metadata against a local registry index.

Use this workflow:

1. Place the fixture outside `fixtures/benchmark/` so it is not included in the
   single-repository fixture summary contract.
2. Add a `README.md` with the exact command to run from the repository root.
3. Keep all inputs reduced, synthetic, and safe; do not copy upstream registry
   records verbatim.
4. Prefer local JSON inputs over network calls so tests and examples are
   deterministic.
5. Add a focused CLI regression test that exercises the example and asserts the
   expected rule ID, such as `SG013`.
6. Update `CHANGELOG.md` and `future_steps.md` when the comparison fixture
   changes public examples, contributor workflow, or roadmap status.

## Updating Golden Snapshots

Snapshot outputs are maintained by a repo-local helper rather than the public
`skillgate` CLI. To review generated output and diffs without changing tracked
files, run:

```bash
python tools/update_snapshots.py --check --artifacts test-outputs/snapshots
```

If the output change is intentional, update the tracked snapshots with:

```bash
python tools/update_snapshots.py --accept
```

## Documentation

Documentation should be clear about the threat model. SkillGate detects static risks and capability drift; it does not prove that an agent skill or MCP server is safe.

# Development setup

SkillGate uses Python 3.12 for its reproducible development environment. Install
[`uv`](https://docs.astral.sh/uv/) and run:

```bash
uv sync --locked --group dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
npm test
```

Use `uv run` for repository tools so local execution matches CI. If dependency
metadata changes, regenerate `uv.lock` with `uv lock`, review the diff, and
verify it with `uv sync --locked` before opening a pull request.
