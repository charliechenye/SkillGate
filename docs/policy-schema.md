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
  capabilities:
    allow:
      - "network.package_registry"
      - "shell.local_script"
    deny:
      - "network.cloud_metadata"

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

## `policy.capabilities.allow`

`policy.capabilities.allow` accepts named capability groups for common review
decisions that span lower-level fields.

Supported groups:

- `mcp.remote_http`
- `network.ai_api`
- `network.any`
- `network.cloud_metadata`
- `network.localhost`
- `network.package_registry`
- `network.private_network`
- `network.public_internet`
- `network.source_control`
- `secrets.cloud`
- `shell.local_script`

```yaml
policy:
  capabilities:
    allow:
      - "network.package_registry"
      - "shell.local_script"
```

Capability groups suppress matching capability-based policy violations, but
they do not suppress severity threshold findings or remote download execution.
Exact allowlists still work and are preferred when the expected resource is
known. Treat these groups and exact allowlists as durable capability approvals:
they describe expected behavior that should remain permitted until policy
owners change the file.

## `policy.capabilities.deny`

`policy.capabilities.deny` blocks named capability groups. Deny groups take
precedence over allow groups, exact host allowlists, and category allowlists.

```yaml
policy:
  capabilities:
    deny:
      - "network.cloud_metadata"
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

## Capability Approvals

Capability approvals are durable policy-as-code allowlists for expected
behavior. Prefer these for known-good capabilities instead of finding waivers:

```yaml
version: 1
policy:
  shell:
    commands:
      allow:
        - "bash scripts/build.sh"
  filesystem:
    write:
      - "generated/**"
  network:
    allow:
      - "api.github.com"
  mcp:
    require_review_on_change: true
```

For MCP drift, review the `SG010` diff and update the approved baseline when
the server command, args, env names, or endpoints are expected.

## `policy.waivers`

`policy.waivers` contains rare, expiring finding waivers for specific risky
findings that remain risky after review. Waivers are finding-only; they do not
approve capability-based violations such as unallowlisted network hosts or
filesystem writes.

```yaml
version: 1
policy:
  waivers:
    allow_broad_selectors: false
    entries:
      - id: reviewed-installer-2026-01
        owner: security@example.com
        reason: Reviewed pinned installer script before migration.
        created_on: 2026-01-01
        expires_on: 2026-02-01
        ticket: SEC-123
        finding:
          fingerprint: "sha256:..."
```

Each entry requires `owner`, `reason`, `created_on`, `expires_on`, and a
`finding` selector. Prefer `fingerprint` selectors for reviewed findings because
they are stable across unrelated line shifts while changing when the evidence
changes. The selector also supports glob matching for `id`, `rule_id`,
`capability`, `file_path`, `title`, and `evidence`; `fingerprint` must be an
exact `sha256:<64 lowercase hex>` value and never supports wildcards. By
default, broad selectors such as only `rule_id: SG004` are rejected. Broad
selectors are not recommended for production and should be used only for
controlled fixtures or exceptional review workflows with explicit review.
Expired waivers block `skillgate check` until renewed or removed.

## Dry-Run Suggestions

`skillgate check --dry-run` evaluates the policy and prints the violations that
would block without exiting with code `1`. Text output includes concise `why`
and `approve by` lines when SkillGate can propose a narrow approval. JSON output
includes `policy_result`, `scan_report`, and a `suggestions` array with
structured policy additions.

Dry-run suggestions are advisory. SkillGate does not suggest approving
`remote_download_execution`; review, pin, or remove remote execution separately.
For MCP baseline drift, update the approved baseline after review rather than
disabling `policy.mcp.require_review_on_change` by default.

## Policy Template Profiles

- `audit`: minimal high-risk threshold policy for early visibility without broad capability allowlists.
- `preinstall`: blocks shell execution, secret access, high findings, and unreviewed MCP drift; network and write allowlists start empty for review.
- `strict`: blocks shell execution, secret access, unallowlisted network, unallowlisted writes, unreviewed MCP drift, and medium-or-higher findings.
- `mcp`: focuses on MCP drift, remote endpoint review, secret access, and high findings.
