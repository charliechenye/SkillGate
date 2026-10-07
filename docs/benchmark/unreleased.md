> Unreleased development snapshot; version text reflects the checkout, not a release.

# SkillGate Benchmark Report

- Scanner version: `0.1.5`
- Fixture root: `fixtures/benchmark`
- Fixtures: 41
- Passed: 41
- Failed: 0

## Rule Coverage

| Rule | Expected fixtures | Actual fixtures | Coverage status |
| --- | ---: | ---: | --- |
| SG001 | 9 | 9 | covered |
| SG002 | 2 | 2 | covered |
| SG003 | 28 | 28 | covered |
| SG004 | 2 | 2 | covered |
| SG005 | 7 | 7 | covered |
| SG006 | 10 | 10 | covered |
| SG007 | 3 | 3 | covered |
| SG008 | 1 | 1 | covered |
| SG009 | 12 | 12 | covered |
| SG010 | 1 | 1 | covered |
| SG011 | 4 | 4 | covered |
| SG012 | 3 | 3 | covered |
| SG013 | 0 | 0 | not covered |
| SG014 | 0 | 0 | not covered |
| SG015 | 0 | 0 | not covered |

## Fixture Results

| Fixture | Status | Expected rules | Actual rules | Attribution |
| --- | --- | --- | --- | --- |
| `01-safe-documentation-skill` | **pass** | `none` | `none` | no |
| `02-shell-execution` | **pass** | `SG001` | `SG001` | no |
| `03-destructive-command` | **pass** | `SG001, SG002` | `SG001, SG002` | no |
| `04-network-egress` | **pass** | `SG003` | `SG003` | no |
| `05-remote-download-execute` | **pass** | `SG001, SG003, SG004` | `SG001, SG003, SG004` | no |
| `06-secret-access` | **pass** | `SG005` | `SG005` | no |
| `07-filesystem-write` | **pass** | `SG006` | `SG006` | no |
| `08-prompt-override` | **pass** | `SG007` | `SG007` | no |
| `09-unicode-obfuscation` | **pass** | `SG008` | `SG008` | no |
| `10-mcp-config` | **pass** | `SG003, SG005, SG009` | `SG003, SG005, SG009` | no |
| `11-mcp-capability-drift-before` | **pass** | `SG003, SG005, SG009` | `SG003, SG005, SG009` | no |
| `12-mcp-capability-drift-after` | **pass** | `SG001, SG003, SG005, SG009, SG010` | `SG001, SG003, SG005, SG009, SG010` | no |
| `13-public-pattern-python-node-extraction` | **pass** | `SG003, SG006` | `SG003, SG006` | yes |
| `14-public-pattern-shell-powershell-extraction` | **pass** | `SG001, SG002, SG003, SG006` | `SG001, SG002, SG003, SG006` | yes |
| `15-public-pattern-mcp-remote-config` | **pass** | `SG003, SG005, SG009` | `SG003, SG005, SG009` | yes |
| `16-public-pattern-mcp-http-remote` | **pass** | `SG003, SG009` | `SG003, SG009` | yes |
| `17-public-pattern-agent-skill-plugin` | **pass** | `SG003, SG009` | `SG003, SG009` | yes |
| `18-public-pattern-mcp-nested-profile` | **pass** | `SG003, SG005, SG009` | `SG003, SG005, SG009` | yes |
| `19-public-pattern-plugin-hooks` | **pass** | `SG001, SG003, SG004, SG006` | `SG001, SG003, SG004, SG006` | yes |
| `20-public-pattern-marketplace-mcp-package` | **pass** | `SG003, SG009` | `SG003, SG009` | yes |
| `21-public-pattern-agent-command-pack` | **pass** | `SG003, SG006` | `SG003, SG006` | yes |
| `22-public-pattern-mcp-local-bridge` | **pass** | `SG003, SG009` | `SG003, SG009` | yes |
| `23-public-pattern-skill-tool-metadata` | **pass** | `SG007` | `SG007` | yes |
| `24-public-pattern-mcp-tool-metadata-risk` | **pass** | `SG003, SG007, SG011` | `SG003, SG007, SG011` | yes |
| `25-public-pattern-mcp-app-web-surface` | **pass** | `SG003, SG011` | `SG003, SG011` | yes |
| `26-public-pattern-mcp-dangerous-transport` | **pass** | `SG001, SG003, SG012` | `SG001, SG003, SG012` | yes |
| `27-public-pattern-mcp-registry-package-metadata` | **pass** | `SG003, SG012` | `SG003, SG012` | yes |
| `28-mcp-compatibility-inventory` | **pass** | `SG003, SG009` | `SG003, SG009` | no |
| `29-mcp-protocol-transition` | **pass** | `SG003, SG009` | `SG003, SG009` | no |
| `30-public-pattern-mcp-apps-static-adapter` | **pass** | `SG011` | `SG011` | yes |
| `31-mcp-tasks-capability` | **pass** | `SG003, SG009` | `SG003, SG009` | no |
| `32-capability-noise-negative` | **pass** | `none` | `none` | no |
| `33-capability-syntax-positive` | **pass** | `SG001, SG003, SG006` | `SG001, SG003, SG006` | no |
| `34-request-target-and-redirect` | **pass** | `SG003, SG006` | `SG003, SG006` | no |
| `35-command-secret-redaction` | **pass** | `SG003, SG005` | `SG003, SG005` | no |
| `36-xml-parser-alias` | **pass** | `SG003` | `SG003` | no |
| `37-python-write-modes` | **pass** | `SG006` | `SG006` | no |
| `38-file-target-binding` | **pass** | `SG006` | `SG006` | no |
| `39-python-shell-context` | **pass** | `SG001, SG006` | `SG001, SG006` | no |
| `40-network-connection-peers` | **pass** | `SG003` | `SG003` | no |
| `41-registry-template-urls` | **pass** | `SG003, SG011, SG012` | `SG003, SG011, SG012` | no |

## Reproduce

```bash
skillgate fixtures summary fixtures/benchmark --format markdown
```

## Attribution

Public-pattern fixtures retain source URLs, retrieval dates, and reduction notes in their expected-findings metadata.

## Limitations

This report verifies deterministic fixture expectations and rule coverage. It is not a real-world detection accuracy benchmark, malware verdict, or completeness claim.
Fixtures are intentionally reduced examples and may not represent the behavior, context, or security posture of their source projects.
