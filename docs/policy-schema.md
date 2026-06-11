# SkillGate Policy Schema

SkillGate policy files are YAML documents with a schema version and a `policy` mapping.
The current policy schema version is `1`.

The machine-readable JSON Schema is available at
[`schemas/skillgate-policy.schema.json`](../schemas/skillgate-policy.schema.json).
You can also print or write the same schema from the CLI:

```bash
skillgate policy schema
skillgate policy schema --output skillgate-policy.schema.json
```

For schema-aware editor integration, see
[`docs/editor-setup.md`](editor-setup.md).

Starter policies are available through template profiles:

```bash
skillgate policy init --profile audit
skillgate policy init --profile preinstall --output skillgate.yaml
skillgate policy init --profile strict
skillgate policy init --profile mcp
```

```yaml
version: 1

policy:
  shell:
    allow: false
    commands:
      allow:
        - "python samples/*"

  filesystem:
    read:
      - "docs/**"
    write:
      - "generated/**"

  network:
    allow:
      - "api.github.com"
    allow_categories:
      - "source_control"
      - "package_registry"
    deny_categories:
      - "cloud_metadata"

  secrets:
    deny:
      - "*"
    env:
      allow:
        - "GITHUB_TOKEN"

  mcp:
    require_review_on_change: true

  risk_threshold:
    block: high
```

Policy loading validates known sections, field types, unknown keys, and severity threshold values. YAML syntax and schema errors include file, line, and column details when PyYAML provides them.

## `version`

The top-level `version` field identifies the policy schema version. It must be the integer `1`.

```yaml
version: 1
```

## `policy.shell.allow`

Set `policy.shell.allow` to `false` to block shell and process execution capabilities, including remote-download execution capabilities.

```yaml
policy:
  shell:
    allow: false
```

## `policy.shell.commands.allow`

`policy.shell.commands.allow` is a list of POSIX-style glob patterns for
allowed shell command strings. It applies to `shell_execution` capabilities
only; it does not approve `remote_download_execution`.

```yaml
policy:
  shell:
    commands:
      allow:
        - "python samples/*"
```

## `policy.filesystem.read`

`policy.filesystem.read` is a list of POSIX-style glob patterns for allowed read paths. SkillGate validates this field so policies can adopt it early, but read enforcement is reserved for a future scanner capability.

```yaml
policy:
  filesystem:
    read:
      - "docs/**"
      - "fixtures/**"
```

## `policy.filesystem.write`

`policy.filesystem.write` is a list of POSIX-style glob patterns for allowed write targets. Detected filesystem write capabilities outside these patterns block `skillgate check`.

```yaml
policy:
  filesystem:
    write:
      - "generated/**"
      - "tmp/*.json"
```

If a write target cannot be extracted confidently, SkillGate treats the resource as unknown and blocks it when a write allowlist is configured.

## `policy.network.allow`

`policy.network.allow` is a list of allowed hostnames. Detected network egress to any other hostname blocks `skillgate check`.

```yaml
policy:
  network:
    allow:
      - "api.github.com"
      - "registry.npmjs.org"
```

Host matching is exact. If a network host cannot be extracted confidently, SkillGate treats the resource as unknown and blocks it when a network allowlist is configured.

## `policy.network.allow_categories`

`policy.network.allow_categories` allows built-in host categories in addition
to exact hosts from `policy.network.allow`.

Allowed categories:

- `ai_api`
- `cloud_metadata`
- `localhost`
- `package_registry`
- `private_network`
- `public_internet`
- `source_control`

```yaml
policy:
  network:
    allow_categories:
      - "source_control"
      - "package_registry"
```

## `policy.network.deny_categories`

`policy.network.deny_categories` blocks built-in host categories. Deny
categories take precedence over exact host and category allowlists.

```yaml
policy:
  network:
    deny_categories:
      - "cloud_metadata"
```

## `policy.secrets.deny`

`policy.secrets.deny` is a list of denied secret patterns. The current enforced form is `["*"]`, which blocks all detected secret or credential access.

```yaml
policy:
  secrets:
    deny:
      - "*"
```

SkillGate reports secret names such as `GITHUB_TOKEN`; it does not report likely secret values.

## `policy.secrets.env.allow`

`policy.secrets.env.allow` is a list of POSIX-style glob patterns for detected
secret environment variable names that are allowed even when
`policy.secrets.deny` is `["*"]`.

```yaml
policy:
  secrets:
    deny:
      - "*"
    env:
      allow:
        - "GITHUB_TOKEN"
```

## `policy.mcp.require_review_on_change`

Set `policy.mcp.require_review_on_change` to `true` to block MCP capability drift found by `skillgate diff --policy`.

```yaml
policy:
  mcp:
    require_review_on_change: true
```

This applies to `SG010` findings generated from baseline diffs, including MCP command, args, env variable name, and endpoint changes.

## `policy.risk_threshold.block`

`policy.risk_threshold.block` blocks findings at or above the configured severity.

Allowed values:

- `informational`
- `low`
- `medium`
- `high`
- `critical`

```yaml
policy:
  risk_threshold:
    block: high
```

For example, `block: high` blocks high and critical findings while allowing informational, low, and medium findings unless another policy section blocks their detected capability.

## Policy Template Profiles

- `audit`: minimal high-risk threshold policy for early visibility without broad capability allowlists.
- `preinstall`: blocks shell execution, secret access, high findings, and unreviewed MCP drift; network and write allowlists start empty for review.
- `strict`: blocks shell execution, secret access, unallowlisted network, unallowlisted writes, unreviewed MCP drift, and medium-or-higher findings.
- `mcp`: focuses on MCP drift, remote endpoint review, secret access, and high findings.
