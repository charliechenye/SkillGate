# Contributing To SkillGate

Thanks for helping improve SkillGate. The project is a deterministic static scanner for AI-agent skills, MCP configurations, instruction files, and helper scripts, so changes should stay stable, reviewable, and easy to reproduce.

## Development Setup

```bash
python -m pip install -e ".[dev]"
python -m pytest
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

When adding detection behavior:

- Use stable rule IDs and deterministic ordering.
- Redact secret values and report names such as `GITHUB_TOKEN`.
- Prefer conservative extraction. If a host or path is uncertain, keep the resource unknown.
- Add fixture coverage under `fixtures/benchmark/`.
- Add or update `expected-findings.yaml`.
- Add focused tests in `tests/test_skillgate.py`.

## Adding Benchmark Fixtures

Benchmark fixtures should be small, safe, and reproducible. Public-pattern fixtures should be reduced and nonverbatim unless the source license and attribution are explicitly handled.

Each fixture should include:

- A short `README.md`.
- One or more supported agent files or referenced scripts.
- `expected-findings.yaml` with the expected rule IDs.

Verify fixtures with:

```bash
python -m skillgate fixtures summary fixtures/benchmark --format json
```

## Documentation

Documentation should be clear about the threat model. SkillGate detects static risks and capability drift; it does not prove that an agent skill or MCP server is safe.
