# Minimal GitHub Action Examples

These examples use the stable `charliechenye/SkillGate@v0` Action tag. Teams
that require immutable Action references should pin a full commit SHA instead.
SkillGate generates SARIF when `sarif-output` is supplied.

For pull requests, retain SARIF as an artifact so intentional demo and test
findings remain reviewable without creating a blocking Code Scanning status.
Publish SARIF to Code Scanning on protected branches or manual runs, or use the
blocking policy example below when the repository is ready to enforce reviewed
behavior.

The copyable [pre-install starter repository](../../examples/preinstall-starter/)
contains this review-only workflow with Markdown, JSON, and SARIF artifacts.
On protected branches and manual runs, GitHub's upload action publishes the
SARIF artifact to Code Scanning and uploads that SARIF file for durable review.

These Action examples are optional GitHub integrations. They do not change the
local-only behavior of SkillGate commands, which write reports locally and do
not upload findings.

## Nonblocking Scan With SARIF

Use this as the lightest adoption path. Without `policy`, the Action runs a
nonblocking scan, and SARIF upload gives reviewers visibility in GitHub code
scanning.

```yaml
name: SkillGate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  skillgate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.11"

      - uses: charliechenye/SkillGate@v0
        with:
          path: .
          sarif-output: skillgate.sarif
          step-summary: "true"
          summary-output: skillgate-summary.md
          json-output: skillgate-review.json

      - uses: github/codeql-action/upload-sarif@v4
        if: github.event_name != 'pull_request' && always()
        with:
          sarif_file: skillgate.sarif

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: skillgate-review
          path: |
            skillgate-summary.md
            skillgate-review.json
            skillgate.sarif
```

## Blocking Policy Check With Policy-Aware SARIF

Use this once the repository has a reviewed `skillgate.yaml`. With `policy`, the
Action blocks unapproved behavior. When `policy` and `sarif-output` are both
provided, SkillGate generates policy-aware SARIF that includes waiver and
suppression metadata.

```yaml
name: SkillGate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  skillgate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.11"

      - uses: charliechenye/SkillGate@v0
        with:
          path: .
          policy: skillgate.yaml
          sarif-output: skillgate.sarif
          step-summary: "true"
          summary-output: skillgate-summary.md
          json-output: skillgate-review.json

      - uses: github/codeql-action/upload-sarif@v4
        if: github.event_name != 'pull_request' && always()
        with:
          sarif_file: skillgate.sarif

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: skillgate-review
          path: |
            skillgate-summary.md
            skillgate-review.json
            skillgate.sarif
```

## Baseline Drift Blocking

Use this when you want capability drift to block CI before adopting a full policy
file. Without `fail-on-drift: "true"`, baseline-only diff remains advisory.

```yaml
name: SkillGate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  skillgate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.11"

      - uses: charliechenye/SkillGate@v0
        with:
          path: .
          baseline: skillgate.lock
          sarif-output: skillgate.sarif
          step-summary: "true"
          summary-output: skillgate-summary.md
          json-output: skillgate-review.json
          fail-on-drift: "true"

      - uses: github/codeql-action/upload-sarif@v4
        if: github.event_name != 'pull_request' && always()
        with:
          sarif_file: skillgate.sarif

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: skillgate-review
          path: |
            skillgate-summary.md
            skillgate-review.json
            skillgate.sarif
```

## Repository Plus Committed MCPB Bundle

Use this when a repository commits or builds an MCPB artifact that should be
reviewed separately from the source tree. Upload the repository SARIF and MCPB
SARIF as two files so GitHub code scanning can preserve the distinct run
categories.

```yaml
name: SkillGate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  skillgate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.11"

      - uses: charliechenye/SkillGate@v0
        with:
          path: .
          sarif-output: skillgate.sarif
          mcpb-path: dist/server.mcpb
          mcpb-fail-on: high
          mcpb-sarif-output: skillgate-mcpb.sarif
          step-summary: "true"
          summary-output: skillgate-summary.md
          json-output: skillgate-review.json

      - uses: github/codeql-action/upload-sarif@v4
        if: github.event_name != 'pull_request' && always()
        with:
          sarif_file: skillgate.sarif

      - uses: github/codeql-action/upload-sarif@v4
        if: github.event_name != 'pull_request' && always()
        with:
          sarif_file: skillgate-mcpb.sarif

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: skillgate-review
          path: |
            skillgate-summary.md
            skillgate-review.json
            skillgate.sarif
            skillgate-mcpb.sarif
```
