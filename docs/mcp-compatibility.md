# MCP compatibility review

SkillGate statically inventories explicit MCP protocol and extension
declarations so reviewers can see compatibility surface changes before enabling
an MCP server or client configuration. It does not contact a server, negotiate
extensions, resolve schemas, or inspect extension settings.

## Transition support

The inventory supports both protocol eras in parallel. It labels the final
`2024-10-07` through `2025-11-25` revisions as `legacy`, and `2026-07-28` as
`modern`. A configuration may advertise both eras during migration; SkillGate
retains both declarations and does not require a 2026 upgrade. Other valid
date-form revisions and `DRAFT-*` values remain visible as `unclassified` or
`draft` evidence rather than becoming security findings. An absent declaration
means only that no explicit protocol revision was found.

The inventory recognizes declared protocol revisions from `protocolVersion`,
`protocolVersions`, `supportedVersions`, the 2026 per-request
`_meta.io.modelcontextprotocol/protocolVersion` value, and an
`MCP-Protocol-Version` header. It recognizes extension maps from `extensions`,
`capabilities.extensions`, and 2026 client capability metadata.

```bash
skillgate review preinstall path/to/mcp-source --json-output review.json
skillgate baseline create path/to/mcp-source --output skillgate.lock
skillgate diff path/to/mcp-source --baseline skillgate.lock
skillgate mcp registry compare path/to/registry --server example.server
```

`review preinstall` adds an optional `metadata.mcp_compatibility` record without
changing the Review Packet schema version. The same declarations appear as
`mcp_protocol_version`, `mcp_extension`, or
`mcp_unknown_declaration` capabilities in scan output and baselines.
Protocol capabilities and packet evidence also carry the normalized `era`
label, while existing `protocol_versions` lists retain the declared strings for
stable comparisons.

## Reviewer guidance

- Confirm the declared legacy, modern, or mixed protocol revisions are expected
  for the configured client or server. Mixed declarations are a migration
  surface to review, not a failure verdict.
- Review newly added extension IDs and their declared versions before enabling
  them. Extension settings are intentionally not interpreted by this inventory.
- Treat malformed IDs, malformed versions, and non-object extension settings as
  explicit review surfaces, not security verdicts.
- Use `diff` or registry comparison to approve changes after review. This first
  compatibility slice is advisory and adds no policy controls.

## Boundaries

SkillGate does not infer a protocol revision from a software `version`, a
transport type, or package metadata. It does not start MCP servers, negotiate
extensions, render MCP Apps, execute Tasks, perform OAuth exchanges, or resolve
external references. MCP Apps, Skills over MCP, Tasks, and authorization/schema
analysis remain separate follow-up work.

The field locations follow the MCP 2026-07-28 extension and per-request
metadata model described in the [MCP extensions overview](https://modelcontextprotocol.io/extensions/overview)
and [protocol overview](https://modelcontextprotocol.io/specification/draft/basic/index).
