# Pinned Public Skill Acceptance

Recorded October 4, 2026 with scanner version `0.1.5`. All checks were replayed
in the release environment. This report records acceptance behavior; it does
not measure detection accuracy.

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

## Known Noise Requiring Follow-Up

Codex inspected these concrete cases; independent reviewer labels and a
representative precision/recall corpus have not been collected.

| Evidence location | Current signal | Why it needs work |
| --- | --- | --- |
| `algorithmic-art/templates/generator_template.js:155` | Filesystem write with resource `max` | A numeric comparison is treated as redirection. |
| `webapp-testing/examples/console_logging.py:15` | Filesystem write | Appending to an in-memory list does not write a file. |
| `docx/scripts/comment.py:129` | Filesystem write | Appending an identifier to a list is not a filesystem operation. |
| `docx/scripts/comment.py:43` | Network egress to `schemas.microsoft.com` | An XML namespace identifier does not establish a network request. |
| `find-skills/SKILL.md:100` | Filesystem write with resource `-g` | An installation option is reported as a concrete path. |
| `pdf/scripts/fill_fillable_fields.py:35` | Network egress with unknown resource | Error-message prose is treated as network evidence. |

These observations are not vulnerability reports about the upstream projects.
They justify the next narrow rule work: suppress source-language comparisons
and in-memory collection operations, distinguish identifier URLs from request
contexts, and leave uncertain write paths unknown. Each change needs an authored
regression and rule documentation; this acceptance PR does not retune rules.

## Limits And Next Product Check

Nine inputs come from Anthropic and one from Vercel. The corpus deliberately
covers different file layouts, but it is publisher-biased and excludes MCP
bundles, registry metadata, live behavior, private artifacts, and adversarial
accuracy evaluation. License checks record declarations, not reuse permission.
PDF and DOCX are source-available; their contents are not copied into this repo.

The [maintainer pilot](../maintainer-pilot.md) is prepared for three real review
sessions. Participants and invitations are pending owner selection and explicit
messaging authorization. Acceptance results alone do not demonstrate adoption.
