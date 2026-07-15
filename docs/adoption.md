# SkillGate Adoption Guide

Use SkillGate as a staged trust review for agent tooling. Start with advisory
review packets, then add CI summaries, policy enforcement, and baseline drift
only after the team understands the expected capability surface.

## 1. Pre-Install Review

Run the unified review command before installing or approving an agent artifact:

```bash
skillgate review preinstall SOURCE --json-output skillgate-review.json
```

`SOURCE` can be a local directory, a public GitHub repository or subtree URL, or
a local `.mcpb` bundle. Local sources stay local. GitHub sources make bounded
requests to fetch the requested source for static review.

The review packet is advisory by default. Add `--fail-on high` only when the
team is ready for the command to return a failing status for high or critical
review signals.

## 2. Pull Request Review

Use review summaries when maintainers need readable artifacts in CI:

```bash
skillgate review summary . \
  --output skillgate-summary.md \
  --json-output skillgate-review.json
```

For GitHub repositories, the composite Action can retain Markdown, JSON, and
SARIF artifacts. Pull-request SARIF should remain a review artifact until the
repository owner intentionally chooses Code Scanning publication or blocking
policy checks.

## 3. Policy Enforcement

After reviewers know which capabilities are expected, create a policy:

```bash
skillgate policy init --profile strict --output skillgate.yaml
skillgate check . --policy skillgate.yaml
```

Use durable capability approvals for expected behavior such as known network
hosts, generated file paths, reviewed shell commands, approved secret names, and
reviewed MCP baselines. Use expiring finding waivers only for specific risky
findings that remain risky but have been reviewed.

## 4. Baseline Drift

Use baselines when the current capability set is approved and future drift
should be reviewed:

```bash
skillgate baseline create . --output skillgate.lock
skillgate diff . --baseline skillgate.lock
skillgate diff . --baseline skillgate.lock --fail-on-drift
```

The nonblocking diff is best for the first rollout. Add `--fail-on-drift` when
unreviewed file, capability, or MCP drift should block CI.

## 5. SARIF And Code Scanning

Any scanner path that supports SARIF can write a local SARIF file:

```bash
skillgate scan . --format sarif --output skillgate.sarif
skillgate check . --policy skillgate.yaml --format sarif --output skillgate.sarif --dry-run
skillgate mcpb scan bundle.mcpb --format sarif --output skillgate-mcpb.sarif
```

Writing SARIF locally does not upload anything. GitHub upload is a separate
workflow decision.

## 6. MCPB Review

Review local MCP bundles before installation or execution:

```bash
skillgate review preinstall bundle.mcpb --json-output mcpb-review.json
skillgate mcpb scan bundle.mcpb --manifest-output bundle-manifest.json
```

SkillGate inspects the bundle archive, startup metadata, member inventory,
endpoints, secret references, embedded executables, and nested archives without
starting the server or installing dependencies.

## Suggested Rollout

```text
review preinstall -> review summary -> check with policy -> diff with baseline
```

Keep the first rollout advisory. Turn on blocking thresholds only after expected
capabilities have been reviewed and written into policy or baseline files.

## Boundaries

SkillGate reports static review signals and capability surfaces. It does not
execute scanned content, install packages, start MCP servers, call LLMs, upload
findings automatically, or prove that an artifact is safe.
