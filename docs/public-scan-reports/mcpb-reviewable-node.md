# Reviewable MCPB Demo Bundle

## Source

- Input source: packaged `skillgate demo mcpb` source, mirrored at
  `fixtures/mcpb-demo/reviewable-node`
- Built artifact: `test-outputs/reviewable-node.mcpb`
- Archive SHA-256: `6948b641f88671717de7142ce075f21f9710621392b115a311eee05831fe5a1c`
- Scanner version: `0.1.1`

## Commands

```bash
skillgate demo mcpb --output test-outputs/reviewable-node.mcpb --scan
skillgate mcpb scan test-outputs/reviewable-node.mcpb --format json
```

## Demo Transcript

```text
Built deterministic demo MCPB: test-outputs/reviewable-node.mcpb
SHA-256: 6948b641f88671717de7142ce075f21f9710621392b115a311eee05831fe5a1c

SkillGate MCPB scan completed
Entry point: server/index.js
Endpoint: https://api.example.invalid/v1
Secret reference: SERVICE_TOKEN
```

## Capability Inventory

- `mcpb_startup`: `server/index.js`
- `network_egress`: `https://api.example.invalid/v1`
- `network_egress`: `api.example.invalid` from first-party source
- `secret_access`: `SERVICE_TOKEN`
- `secret_access`: `api_key`

## Findings Summary

- Findings: `4`
- High findings: `2`
- Medium findings: `2`
- Rule IDs: `SG003`, `SG005`
- Archive members: `4`
- Scanned members: `2`
- Embedded executables: `0`
- Nested archives: `0`

## Finding Classification

- `SG003` runtime endpoint in `manifest.json`: expected behavior for this demo,
  and a review item for a real bundle because startup configuration reaches a
  remote API.
- `SG003` endpoint in `server/index.js`: expected behavior for this demo, and a
  review item because first-party source references the same host.
- `SG005` `SERVICE_TOKEN`: expected behavior for this demo, and a review item
  because startup environment names imply credential access.
- `SG005` `api_key`: expected behavior for this demo, and a review item because
  sensitive user configuration is referenced.

## Suggested Policy Direction

For a real MCPB with this shape, reviewers should confirm the endpoint owner,
credential scope, installation source, and archive hash before installation.
Policy should approve the specific host and secret names only after that review.

## Limitations

The demo uses `.invalid` domains and does not contain a runnable production MCP
server. It is designed to show deterministic bundle inspection, startup parsing,
member inventory, source selection, and review findings.

## What SkillGate Cannot Conclude

SkillGate does not execute the bundle, start the MCP server, install packages,
resolve dependencies, validate remote service ownership, or prove that the
server behavior matches its stated purpose.
