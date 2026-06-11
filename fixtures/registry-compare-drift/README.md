# MCP Registry Drift Example

This reduced fixture demonstrates `SG013` without network access.

Run from the repository root:

```bash
skillgate mcp registry compare fixtures/registry-compare-drift/local \
  --server io.example.registry-drift \
  --registry-url fixtures/registry-compare-drift/registry.json
```

The local metadata intentionally declares a different repository URL, package
identifier, remote endpoint, transport type, version, and secret header than
the registry index. The compare command reports those mismatches as
`SG013` findings. The examples are synthetic and reduced; they are not copied
from an upstream MCP server.

Interpret the result as drift between two declared metadata sources, not as
proof that either side is malicious. The mismatch is expected in this fixture
because every comparable field is intentionally different. In a real review,
expected drift should have a release, migration, rename, or endpoint-cutover
reason in the PR. Unexpected repository, package, remote URL, transport, or
secret-header drift should be treated as a blocker until the intended source of
truth is confirmed.
