# Minimal GitHub Action Examples

These examples use the stable `charliechenye/SkillGate@v0` Action tag. Teams
that require immutable Action references should pin a full commit SHA instead.
SkillGate generates SARIF when `sarif-output` is supplied; GitHub's upload action
uploads that SARIF file to code scanning.

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
        if: always()
        with:
          sarif_file: skillgate.sarif

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: skillgate-review
          path: |
            skillgate-summary.md
            skillgate-review.json
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
        if: always()
        with:
          sarif_file: skillgate.sarif

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: skillgate-review
          path: |
            skillgate-summary.md
            skillgate-review.json
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
        if: always()
        with:
          sarif_file: skillgate.sarif

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: skillgate-review
          path: |
            skillgate-summary.md
            skillgate-review.json
```
