# Schema-Aware Editor Setup

SkillGate publishes its policy JSON Schema in the repository at
[`schemas/skillgate-policy.schema.json`](../schemas/skillgate-policy.schema.json).
You can also export the same schema from the CLI:

```bash
skillgate policy schema --output skillgate-policy.schema.json
```

## VS Code

Install the YAML extension from Red Hat, then add a schema association in
`.vscode/settings.json`:

```json
{
  "yaml.schemas": {
    "./schemas/skillgate-policy.schema.json": [
      "skillgate.yaml",
      "skillgate.example.yaml"
    ]
  }
}
```

For a per-file association, add this modeline near the top of a policy file:

```yaml
# yaml-language-server: $schema=./schemas/skillgate-policy.schema.json
```

## JetBrains IDEs

Open **Settings > Languages & Frameworks > Schemas and DTDs > JSON Schema
Mappings**, add a new schema mapping, and point it at
`schemas/skillgate-policy.schema.json`. Add `skillgate.yaml` and
`skillgate.example.yaml` as file patterns.

## Neovim And yaml-language-server

Configure `yaml-language-server` with a schema association:

```lua
require("lspconfig").yamlls.setup({
  settings = {
    yaml = {
      schemas = {
        ["./schemas/skillgate-policy.schema.json"] = {
          "skillgate.yaml",
          "skillgate.example.yaml",
        },
      },
    },
  },
})
```
