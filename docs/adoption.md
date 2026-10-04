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

JSON packets include a redacted source manifest and packet digest so reviewers
can retain exactly which files were inspected:

```bash
skillgate review preinstall SOURCE --format json --output skillgate-review.json
skillgate review schema --output skillgate-review.schema.json
```

### Review Coverage And Exit Codes

The packet's `metadata.coverage` records a status, scope, and deterministic
reason list. Markdown includes the same coverage status and skipped paths.
Finding counts and review coverage are separate:

| Coverage | Meaning |
| --- | --- |
| `complete` | At least one supported file was scanned, with no reported gaps within the static discovery scope. |
| `incomplete` | Supported content was scanned, but files, declared MCP Apps assets, or declarations could not be fully reviewed. |
| `empty` | No files were selected for source scanning and no skipped files were reported. |
| `unsupported` | Files were present but no supported source coverage was obtained, or an explicitly supplied file has an unrecognized type or is a plugin manifest. |

Local directories list files omitted by discovery without reading their
contents. GitHub reviews use their skipped-file manifest. MCPB reviews list
unscanned members; the separately parsed `manifest.json` is not counted as a
skipped member. Native executables and nested archives remain review gaps.
Explicitly supplied unrecognized files and `plugin.json` may still produce
generic text findings; that does not provide format-aware or aggregate review.

Standard discovery exclusions such as `.git`, `node_modules`, `.venv`, `dist`,
and `build` define the review scope and do not alone make coverage incomplete.
Local discovery prunes those directories; GitHub and MCPB manifests retain
their excluded-file records. Declared MCP Apps assets that are skipped still
count as gaps, including assets under excluded paths. Dependencies, external
content, and runtime behavior remain unreviewed. A declared MCPB entry point
that was not scanned also counts as a gap, even under an excluded path.
`complete` is not a safety verdict or proof that all capabilities were extracted.

Unscanned files outside those exclusions count as gaps even when they look
like documentation or package metadata. Review the skipped-path list; selecting
a narrower source changes the scope and does not approve omitted content.

An empty, unsupported, or incomplete packet uses `review_required` even with
zero findings. Default execution stays advisory. CI can opt into both checks:

```bash
skillgate review preinstall SOURCE --require-complete --fail-on high \
  --output skillgate-review.md --json-output skillgate-review.json
```

- Exit `0`: the requested gates passed, or no gate was requested.
- Exit `1`: `--require-complete` rejected coverage, or `--fail-on` rejected findings.
  The review packet is still written, including when `--format json` is used.
- Exit `2`: source, download, archive, or processing errors prevented a packet.

`--fail-on` continues to check only finding severity. Review Packet v2 keeps
its existing decision values and schema version; coverage is an optional
metadata extension, so older v2 packets remain valid.

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
