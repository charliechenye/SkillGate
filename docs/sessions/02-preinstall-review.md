# Session 02 — Pre-install review

## Goal

Inspect an artifact before installing it, while preserving its source identity
and keeping execution out of the review path.

## Review a public GitHub source

Use a pinned ref when one is available:

```bash
skillgate github scan https://github.com/OWNER/REPOSITORY \
  --ref COMMIT_OR_TAG \
  --format json \
  --manifest-output test-outputs/remote-manifest.json
```

Review the resolved commit, downloaded paths, file hashes, skipped files, and
resource limits in the manifest before interpreting the findings. The sparse
scan downloads only supported agent files and referenced local scripts.

## Review an MCP bundle

Use the packaged deterministic demo if you want a completely local session:

```bash
skillgate demo mcpb \
  --output test-outputs/reviewable-node.mcpb \
  --scan
skillgate mcpb scan test-outputs/reviewable-node.mcpb \
  --manifest-output test-outputs/reviewable-node-manifest.json \
  --format json \
  --output test-outputs/reviewable-node-report.json
```

The manifest records the archive hash, startup entry point, members, endpoints,
secret references, and embedded-artifact inventory. `--fail-on high` can make
the same inspection a blocking gate after the review decision is established.

## Decision checkpoint

Record the immutable source identity, expected endpoints, credential names,
startup command, and any bundled executable or nested archive. If any of those
are unexplained, stop before installation and request clarification from the
publisher.
