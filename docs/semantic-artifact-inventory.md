# Semantic Artifact Inventory Contract

This document records the Stage 0 decisions for semantic artifact linting and
the boundary of the first implementation slice. It supplements the
[semantic artifact linting roadmap](roadmaps/semantic-artifact-linting.md).

The initial implementation is a local, deterministic text inventory. It does
not emit semantic findings, make a safety verdict, execute content, fetch
remote inputs, or change the existing scanner's file discovery.

## Compatibility decision

The current pre-install review packet remains schema version `2`. The first
inventory is a library-level building block, so it is not included in review
packets, scan reports, SARIF, policies, baselines, waivers, or GitHub Actions.

`scan`, `check`, `diff`, `review summary`, and `review preinstall` therefore
retain their current output and exit behavior. In particular:

- `SG007` remains the only rule for its existing explicit prompt-override and
  concealment phrases;
- no `SA###` IDs exist in this slice;
- semantic text does not participate in `--fail-on`, policy evaluation,
  baseline drift, or SARIF; and
- no semantic CLI or report format is available yet; and
- a future review-packet integration must deliberately bump the packet schema,
  publish a matching JSON Schema, update snapshots, and document migration.

## Existing-rule overlap matrix

| Existing signal | What it reports today | Semantic inventory treatment | Future semantic rule boundary |
| --- | --- | --- | --- |
| `SG003` | An observed network endpoint or egress capability | Inventory can preserve an instruction that names an outbound destination | A future `SA###` may report an instruction to transmit specified data; it must not claim that transmission occurred. |
| `SG005` | A secret reference or secret-bearing path | Inventory redacts assignment values while retaining the secret name | A future `SA###` may report an agent-directed request to access sensitive data; it is distinct from mere reference presence. |
| `SG007` | Narrow explicit override or concealment language | Text remains inventory evidence only | Do not create a duplicate `SA###` for the same explicit phrase. Any later richer context must cross-link `SG007`. |
| `SG008` | Unicode controls, large Base64-like blobs, or encoded execution | Inventory preserves only source-selected text and never renders or decodes it | Do not treat obfuscation as a semantic instruction finding. |

The first planned semantic categories remain reserved until benchmark gates are
met: `SA001` for active sensitive-data access instructions and `SA002` for an
explicit request to transmit specified data to a named destination. SkillGate
maintainers own both categories and the `SG007` compatibility decision.

## Source-role allowlist

The inventory assigns role and applicability from a source adapter, never from
the wording it encounters.

| Source | Selected fields | Source role | Agent consumption |
| --- | --- | --- | --- |
| `SKILL.md` in a discovered skill layout | YAML frontmatter `description`; Markdown body | `tool_description`; `agent_instruction` | `direct` |
| `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Copilot instructions, discovered command and agent Markdown | Markdown body | `agent_instruction` | `direct` |
| MCP configuration and registry JSON | Explicit `description`, `instruction`, `instructions`, `prompt`, `system_prompt`, and `template` fields | `tool_description`, `agent_instruction`, or `prompt_template` | `direct` |
| MCPB `manifest.json` | The same explicit fields | `manifest_metadata`, `agent_instruction`, or `prompt_template` | `possible` |
| Explicit `agent*` and `prompts*` YAML/TOML configuration files | The same explicit fields | `tool_description`, `agent_instruction`, or `prompt_template` | `direct` |

Ordinary `README.md` prose, arbitrary comments, binaries, rendered HTML/CSS,
unclassified files, and arbitrary YAML/TOML files remain out of the inventory.
`documentation`, `test_fixture`, `source_comment`, and `unknown` are reserved
source roles for explicit future adapters; none is inferred from text.

## Bounds and evidence handling

The initial extractor uses a 256 KiB source-file limit, 64 KiB text-block
limit, 1 MiB aggregate text limit, and 200-block limit. It skips an entire
source file when adding any of its blocks would cross a bound. Inventory text
uses the existing evidence redaction convention, retaining secret names such
as `SERVICE_TOKEN` while replacing assignment values.

Repository inventory reuses normal discovery and adds only the explicit
`agent*`, `prompts*`, and `mcp*` YAML/TOML filenames in the allowlist above.
It does not broaden the ordinary scanner's discovery behavior.

Archive integrations must pass only files selected by the existing archive
safety layer. The inventory must not independently walk an extracted archive.

## Benchmark and release gates

The existing owned fixtures are the reviewed benign seed set for this stage:

| Fixture | Role | Provenance and license |
| --- | --- | --- |
| `fixtures/benchmark/01-safe-documentation-skill` | Safe Agent Skill input | Repository-authored fixture; MIT with this repository |
| `fixtures/format-aware/benign-prose` | Benign direct-instruction wording | Repository-authored fixture; MIT with this repository |

The committed [`fixtures/semantic-artifacts/`](../fixtures/semantic-artifacts)
corpus adds 24 repository-owned cases: six `SA001` candidates, six `SA002`
candidates, six benign controls, four `SG007` compatibility controls, and two
deferred categories. Its internal test harness validates fixed labels, source
selection, inventory blocks, and category-isolated future metrics. It does not
emit semantic findings or calculate detector accuracy yet.

Existing prompt-override fixtures remain regression inputs for `SG007`; they
are not semantic-rule positives. Before an `SA###` rule is added, maintainers
must evaluate the rule pack against the committed corpus and the stated gates.
Do not add a semantic CLI, including `review preinstall --semantic`, until that
evaluation produces useful advisory evidence.

The provisional go/no-go gates are: at least 90% precision on high-confidence
production-context fixtures, at least 70% reviewer actionability from two
independent reviewers, no more than 10% category disagreement, at most 0.5
non-actionable high-confidence findings per representative repository or
bundle per category, and p95 semantic overhead below two seconds and 25% of
normal review duration. These are evaluation gates, not real-world accuracy
claims. Semantic policy enforcement remains deferred until documented review of
at least 20 representative repositories or bundles.

## Stage checklist

- [x] Preserve existing `SG003`, `SG005`, `SG007`, and `SG008` behavior.
- [x] Define source roles, applicability, explicit field allowlists, output
  bounds, and redaction behavior.
- [x] Keep the Review Packet v2 and existing output contracts unchanged.
- [x] Record benchmark provenance, false-positive budget, and termination
  gates.
- [x] Add a bounded, deterministic inventory with no findings.
- [x] Add the synthetic semantic corpus, inventory validation, and future-rule
  metric harness.
- [ ] Add narrow advisory `SA###` findings only after that benchmark is ready.
- [ ] Add line-movement-stable semantic drift before review-packet integration.
- [ ] Add a semantic CLI, version the packet, and add `review preinstall
  --semantic` only after representative-repository evidence is published.
