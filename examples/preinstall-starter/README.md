# SkillGate pre-install review starter

This small repository is a copyable starting point for reviewing an Agent Skill
before it is installed or merged. It contains one intentionally boring Skill and
no helper scripts, package hooks, servers, or network configuration.

## Local review

From a SkillGate source checkout, run:

```bash
uv sync --locked --group dev
uv run skillgate review preinstall examples/preinstall-starter/skills/safe-greeting \
  --json-output test-outputs/safe-greeting-review.json
```

Or, from this starter repository after installing SkillGate, run:

```bash
skillgate review preinstall skills/safe-greeting \
  --json-output safe-greeting-review.json
```

The review is advisory by default. Add `--fail-on high` when a local check should
return a failing status for high or critical review signals.

## GitHub Actions

The workflow in `.github/workflows/skillgate-review.yml` keeps Markdown, JSON,
and SARIF review files as pull-request artifacts. It does not upload pull-request
SARIF to Code Scanning, so intentional fixture or demo findings remain visible
without becoming a blocking Code Scanning status. Pushes to `main` and manual
runs publish SARIF to Code Scanning.

When the repository has reviewed behavior to enforce, add a `policy` or
`baseline` to the Action and use `fail-on-drift: "true"` as documented in the
[Action examples](../../docs/examples/github-action-minimal.md).

SkillGate does not execute the Skill, install packages, start servers, or call an
agent during this review.
