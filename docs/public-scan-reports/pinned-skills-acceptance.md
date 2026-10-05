# Pinned Public Skill Acceptance

Recorded October 4, 2026 with scanner version `0.1.5`. The first table preserves
the published release's results. The development replay below uses unreleased
rule fixes; its package version string is still `0.1.5`. This report records
acceptance behavior; it does not measure detection accuracy.

The [catalog](../../fixtures/public-skills/catalog.json) contains ten immutable
skill inputs from two publishers. Each records a license location and digest,
supported-file paths and hashes, expected skipped paths, validation rule IDs,
and selected evidence. Source code is fetched temporarily and never executed
or vendored. Independent human adjudication is pending.

Reproduce:

```bash
uv run python tools/evaluate_public_skills.py \
  --output test-outputs/public-skill-acceptance.json
```

All ten acceptance checks passed: immutable source and license digests, expected
supported files and gaps, selected evidence, repeat scans, and local/GitHub
parity on the materialized supported input. This is 70 scanned files and 59
skipped files. Parity does not recreate skipped upstream files or approve them.
The normal offline test suite separately verifies actual CLI exit behavior.

Only one source has complete static coverage. Nine retain explicit coverage
gaps. The last column is the expected coverage gate exit derived from packet
status, before any severity threshold. Finding counts below exclude separate
skill-validation findings and include known noise.

| Sample | Scanned files | Skipped files | Scanner findings | Coverage | Coverage gate exit |
| --- | --- | --- | --- | --- | --- |
| `vercel-find-skills` | 1 | 0 | 6 | `complete` | 0 |
| `anthropic-frontend-design` | 1 | 1 | 2 | `incomplete` | 1 |
| `anthropic-brand-guidelines` | 1 | 1 | 0 | `incomplete` | 1 |
| `anthropic-theme-factory` | 11 | 2 | 0 | `incomplete` | 1 |
| `anthropic-algorithmic-art` | 2 | 2 | 6 | `incomplete` | 1 |
| `anthropic-webapp-testing` | 5 | 1 | 25 | `incomplete` | 1 |
| `anthropic-mcp-builder` | 7 | 3 | 173 | `incomplete` | 1 |
| `anthropic-skill-creator` | 15 | 3 | 238 | `incomplete` | 1 |
| `anthropic-pdf` | 11 | 1 | 82 | `incomplete` | 1 |
| `anthropic-docx` | 16 | 45 | 340 | `incomplete` | 1 |

The zero-finding branding and theme skills still require review because their
license or PDF files remain unscanned. `complete` is scoped static coverage,
never an artifact safety verdict. Unscanned license files count as gaps under
the current conservative contract; the evaluator does not silently exempt them.

## Issues Reproduced And Fixed

- Anthropic PDF previously selected 11 files through GitHub and only one
  through local discovery. Local pre-install review now selects the same
  bundled Markdown and supported scripts, with exclusions and boundaries.
- The skill-creator JSON example path was truncated to a `.js` filename and
  caused a missing-file error. Script references now require the complete
  extension. Real missing script paths still fail with source evidence.

## Six Noise Regressions Fixed In Development

Codex inspected these concrete cases; independent reviewer labels and a
representative precision/recall corpus have not been collected.

| Evidence location | Published v0.1.5 signal | Development correction |
| --- | --- | --- |
| `algorithmic-art/templates/generator_template.js:155` | Filesystem write with resource `max` | Source comparisons and return annotations are distinguished from shell command strings. |
| `webapp-testing/examples/console_logging.py:15` | Filesystem write | Collection `.append()` methods do not supply write evidence. |
| `docx/scripts/comment.py:129` | Filesystem write | Appending an identifier to a list does not supply write evidence. |
| `docx/scripts/comment.py:43` | Network egress to `schemas.microsoft.com` | Namespace map literals have explicit XML consumers; variable names alone cannot suppress endpoints. |
| `find-skills/SKILL.md:100` | Filesystem write with resource `-g` | Markdown angle-bracket placeholders are distinguished from redirection. |
| `pdf/scripts/fill_fillable_fields.py:35` | Network egress with unknown resource | The English word `got` requires client call syntax to supply network evidence. |

These observations are not vulnerability reports about the upstream projects.
The original six `expected.absent_evidence` probes each match the published
scanner and are absent with the development rules. The catalog now contains
fourteen negative probes, including inline installer placeholders, HTML markup,
XML relationship types, XML xmlns attributes, and Markdown fence delimiters.
The former shell-positive probe at `docx/SKILL.md:39` was a fence delimiter;
it is replaced by the real `subprocess.run` invocation at
`docx/scripts/accept_changes.py:68` and retained as a negative probe.
Selected positive evidence must still match. Authored benchmark fixtures
`32-capability-noise-negative`, `33-capability-syntax-positive`, and
`34-request-target-and-redirect` cover both physical-line and format-aware
scanning. They retain real requests and writes, adjacent input/output redirects,
process API aliases, and unknown targets. Policy regressions verify that header
URLs, namespace variable names, and dynamic targets cannot bypass allowlists.
The [development fixture report](../benchmark/unreleased.md) records all 34
authored benchmark cases; the published version's 31-case report is retained.

## Unreleased Development Replay

Replayed locally on October 4, 2026 from the previously fetched immutable
sources and licenses, with unchanged source and file digests. Ten of ten
acceptance checks passed, including all fourteen negative probes, selected
positive probes, repeat scans, and local/sparse-input parity. This replay did
not perform new network fetches or execute sample code. Coverage remains 70
scanned and 59 skipped files: one complete input and nine incomplete inputs.

| Sample | Published v0.1.5 findings | Development findings |
| --- | --- | --- |
| `vercel-find-skills` | 6 | 3 |
| `anthropic-frontend-design` | 2 | 2 |
| `anthropic-brand-guidelines` | 0 | 0 |
| `anthropic-theme-factory` | 0 | 0 |
| `anthropic-algorithmic-art` | 6 | 2 |
| `anthropic-webapp-testing` | 25 | 20 |
| `anthropic-mcp-builder` | 173 | 36 |
| `anthropic-skill-creator` | 238 | 90 |
| `anthropic-pdf` | 82 | 25 |
| `anthropic-docx` | 340 | 68 |
| **Total** | **872** | **246** |

These are output counts, not independently adjudicated false-positive counts.
Overlapping logical spans contribute to the reduction. The concrete regressions
above are covered. XML namespace constants with unsupported or ambiguous
consumers still produce network signals; this is preferable to hiding real
endpoints based on their variable names. Broad write/append instruction wording
can still produce signals. Suppressing installer placeholders does not inventory
every installation side effect. Counts may rise when a conservative fix restores
previously suppressed evidence or reports multiple destinations separately.

The common output-directory fix is also in development. Regressions cover
pre-install packets, summaries, scan JSON/SARIF, and schema output, including
sidecar reports when a review gate fails. Published `v0.1.5` and `v0` still
require callers to create nested output directories before invocation.

## Limits And Next Product Check

Nine inputs come from Anthropic and one from Vercel. The corpus deliberately
covers different file layouts, but it is publisher-biased and excludes MCP
bundles, registry metadata, live behavior, private artifacts, and adversarial
accuracy evaluation. License checks record declarations, not reuse permission.
PDF and DOCX are source-available; their contents are not copied into this repo.

The [maintainer pilot](../maintainer-pilot.md) is prepared for three real review
sessions. Participants and invitations are pending owner selection and explicit
messaging authorization. Acceptance results alone do not demonstrate adoption.
