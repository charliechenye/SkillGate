# Session 03 — Approval and CI

## Goal

Move from an exploratory scan to an explicit, reviewable approval that can be
rechecked when a skill or MCP configuration changes.

## Generate a starting policy

```bash
skillgate policy init --profile preinstall --output skillgate.yaml
skillgate check . --policy skillgate.yaml --dry-run
```

Use the dry run to understand the suggested approvals. Keep allowlists narrow:
approve the exact host, secret name, command, or path that the artifact needs.

## Capture the reviewed baseline

After the capability set is understood and the policy is intentionally edited:

```bash
skillgate baseline create . --output skillgate.lock
skillgate provenance create \
  --policy skillgate.yaml \
  --baseline skillgate.lock \
  --output skillgate.provenance.json
skillgate provenance verify --manifest skillgate.provenance.json
```

On future changes, compare the new capability surface:

```bash
skillgate diff . --baseline skillgate.lock --fail-on-drift
skillgate review summary . \
  --baseline skillgate.lock \
  --policy skillgate.yaml \
  --output test-outputs/review-summary.md \
  --json-output test-outputs/review-summary.json
```

## Decision checkpoint

The approval is complete only when the policy, baseline, and provenance file are
reviewed together. A changed MCP command, endpoint, environment name, or helper
script should reopen the review instead of being silently absorbed by a broad
allowlist.

For CI wiring, start with the [minimal GitHub Action examples](../examples/github-action-minimal.md)
and keep SARIF, review summaries, and policy enforcement as separate artifacts.
