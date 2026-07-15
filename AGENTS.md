# SkillGate Agent Guide

This repository contains SkillGate, a deterministic static trust gate for
AI-agent skills, instruction files, helper scripts, MCP metadata, MCP registry
metadata, and MCP bundles.

## Mission

Keep SkillGate focused on one review question:

> What new agent capability would this artifact introduce?

The scanner should help reviewers make pre-install, pre-merge, and CI decisions
without executing the artifact being reviewed.

## Hard Invariants

- Do not execute scanned repository code, helper scripts, package commands, or
  MCP servers as part of scanning.
- Do not call LLM APIs, add telemetry, or upload findings automatically.
- Keep detection deterministic, static, and reproducible.
- Redact secret values; report secret names such as `GITHUB_TOKEN`.
- Prefer conservative extraction. If a host, command, or path is uncertain,
  leave it unknown instead of inventing a value.
- Preserve stable CLI, JSON, SARIF, policy schema, and rule semantics unless the
  task explicitly asks for a breaking change.

## Implementation Guidance

- Read `README.md`, `future_steps.md`, and the nearest tests before changing
  behavior.
- Keep changes narrowly scoped to the requested behavior.
- Use existing rule, model, reporting, and fixture patterns instead of adding a
  new abstraction first.
- Add or update benchmark fixtures for scanner behavior changes.
- Update rule documentation when rule behavior changes so `skillgate rules list`
  and `skillgate explain` stay complete.
- Keep docs clear that SkillGate reports review signals and capability surfaces;
  it does not prove an artifact is safe.

## Verification

Use the repository-local environment:

```bash
uv sync --locked --group dev
uv run pytest
uv run python tools/update_snapshots.py --check
uv run ruff check .
uv run ruff format --check .
npm test
```

For focused adoption docs and workflow checks:

```bash
uv run pytest tests/test_adoption_workflow.py
```

If `uv` cache access is unavailable in a restricted environment, use the checked
out virtual environment when present:

```bash
.venv/bin/python -m pytest tests/test_adoption_workflow.py
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
```
