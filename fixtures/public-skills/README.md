# Pinned Public Skill Acceptance Samples

`catalog.json` records ten public Agent Skills at immutable commits, with
license locations and digests, expected supported-file hashes, explicit skipped
paths, validation results, selected static evidence, and known signals that must
remain absent after rule fixes. It stores metadata;
upstream source and license text are not vendored.

These samples cover instruction-only skills, delegated Markdown, unlinked
references, nested Python/JavaScript helpers, generated filenames, and
unsupported HTML, PDF, XML, and package files. Nine samples are from Anthropic
and one from Vercel. This is a small acceptance corpus with publisher bias,
not a representative accuracy benchmark.

Run the explicit network check after installing the repository environment:

```bash
uv run python tools/evaluate_public_skills.py \
  --output test-outputs/public-skill-acceptance.json
```

The tool uses the existing bounded GitHub adapter and deletes materialized
files after checking. It never invokes sample scripts, package commands, MCP
servers, browser examples, or API clients. It checks repeatability and compares
local/GitHub scans of the downloaded supported files. That parity check does
not recreate skipped files or establish full-checkout coverage. The output's
coverage gate exit is derived from packet status; CLI gate behavior is verified
separately by the normal test suite.

The ordinary test suite remains offline. It verifies the catalog contract and
the acceptance tool with authored input. Reduced layout and filename fixtures
live in `fixtures/github-review`; changes to real observations should also get
a focused offline regression when they alter scanner behavior.

`expected.evidence` records capabilities that must remain visible;
`expected.absent_evidence` records known misclassifications that must stay absent.
Each probe matches its listed capability fields. Six negative probes cover the
reproduced list appends, comparison, namespace map, installer placeholder, and
error-message prose. These are selected regression expectations, not complete
human-reviewed labels for each artifact.

Codex inspected the source evidence and selected probes. Independent human
adjudication is pending. Finding counts describe current behavior and include
known noise; they are not vulnerability labels, precision, or recall. Two
zero-finding samples still have coverage gaps, which must remain visible.

Vercel's sample is MIT-licensed. Seven selected Anthropic examples declare
Apache-2.0; PDF and DOCX declare a separate source-available license. The
[upstream description](https://github.com/anthropics/skills/blob/8a1541c4a3ffa5a20a5a91de0dcf3f0bab1d1ef4/README.md)
distinguishes document skills from its open-source examples. Read each
cataloged license before reusing upstream contents; this repository publishes
only source identities, hashes, paths, and derived observations.

See the [acceptance findings](../../docs/public-scan-reports/pinned-skills-acceptance.md)
for results and known limitations.
