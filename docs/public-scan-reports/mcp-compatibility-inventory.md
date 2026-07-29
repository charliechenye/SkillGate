# MCP compatibility inventory

## Purpose

This report shows the advisory compatibility evidence produced for the committed
`28-mcp-compatibility-inventory` fixture. It demonstrates protocol revision,
extension, and malformed-declaration inventory; it is not a claim about a
real-world server.

## Reproduce

```bash
skillgate review preinstall fixtures/benchmark/28-mcp-compatibility-inventory \
  --json-output test-outputs/mcp-compatibility-review.json
```

## What reviewers see

- Declared protocol revision `2026-07-28`.
- Declared `com.example/audit`, `com.example/tasks`, and
  `io.modelcontextprotocol/ui` extensions with explicit versions where supplied.
- A malformed extension identifier retained as an advisory unknown declaration.
- Existing `SG003` and `SG009` review signals for the remote MCP configuration.

Reviewers should confirm that the protocol revision and extension set are
expected, then approve the resulting baseline or registry comparison change.
The extension inventory does not interpret settings, negotiate support, or make
claims about runtime behavior.

## What SkillGate cannot conclude

This report cannot prove that a server implements its declarations correctly or
is safe to run. SkillGate did not start a server, fetch an extension, resolve a
schema, or execute any bundled code.
