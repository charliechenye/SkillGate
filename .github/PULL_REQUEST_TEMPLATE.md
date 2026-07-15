## Summary

- Describe the change and why it belongs in SkillGate.

## Review Notes

- User-facing behavior changed:
- CLI, JSON, SARIF, policy schema, or Action interface changed:
- Docs or examples updated:

## Verification

```bash
uv run pytest
uv run python tools/update_snapshots.py --check
uv run ruff check .
uv run ruff format --check .
npm test
```

## SkillGate Invariants

- [ ] Scanned content is not executed.
- [ ] No package installation, MCP server startup, LLM call, or telemetry was added.
- [ ] Secret values are redacted or avoided in output.
- [ ] Claims stay bounded to static review signals and capability surfaces.
