# Product Direction and Future Steps

This is the canonical product-direction and roadmap document. README pages,
discovery notes, and recommendation guidance should describe the current
repository consistently and link here for planned work. Detailed v0.2
artifact-admission design lives in the subordinate [Agent Artifact Admission
roadmap](docs/roadmaps/agent-artifact-admission.md).

## Product direction

SkillGate is deterministic, no-execution admission control for agent artifacts
before install, merge, or approval. Its core review question remains:

> What new capability surface does this artifact introduce before I trust it?

The product turns materialized artifacts into reviewable evidence:

- artifact identity and provenance;
- static capability evidence and capability drift;
- reviewer-facing findings and approval state;
- policy-as-code and CI admission control; and
- explicit no-execution boundaries.

SkillGate may be used as a static security scanner, but it is not a runtime MCP
gateway, sandbox, malware verdict engine, LLM-first scanner, hosted security
platform, generic agent framework, or runtime watchdog. Runtime enforcement,
isolation, least-privilege credentials, and monitoring remain complementary
controls.

## Current baseline and shipped status

The current stable release is `v0.1.5`. It adds explicit pre-install coverage
and an opt-in completeness gate, aligns local and GitHub skill supporting-file
selection, and fixes truncated script references. Ten pinned public skill
samples provide repeatable acceptance checks and document known rule noise;
independent human adjudication and three maintainer pilots remain pending.
The `v0.1.4` release improved GitHub skill validation and supporting-file
coverage, added advisory MCP Apps and Tasks evidence and bounded
Agent Skill ZIP validation, and patched development-toolchain dependencies.
The `v0.1.3` release established Review Packet v2, deterministic packet and
source-manifest evidence, and MCP protocol/extension inventory. Capability
baselines and drift, provenance, policy-as-code, and the no-execution boundary
remain supported. Historical release details remain in `CHANGELOG.md`; do not
rewrite release-note history to make the roadmap current.

PyPI and npm publication remain deferred; GitHub tags and GitHub Release assets are the
supported distribution paths for the current release line.

The current repository baseline includes:

- local and sparse GitHub static review for Agent Skills, instruction files,
  scripts, MCP metadata, MCP registry metadata, and MCP bundles;
- advisory [MCP Apps static review](docs/mcp-apps-static-review.md), including
  bounded local web-asset evidence;
- explicit MCP Tasks capability inventory documented in
  [MCP compatibility review](docs/mcp-compatibility.md);
- bounded ZIP validation for packaged Agent Skills;
- review summaries, SARIF, policy checks, baselines, drift, and provenance;
- deterministic demos, public scan-report examples, and adoption workflows; and
- internal semantic artifact inventory, `SA001`/`SA002` analysis, and semantic
  instruction drift helpers.

MCP Skills and Agent Plugins support are not shipped CLI capabilities today.
The semantic CLI is not shipped, and runtime MCP inspection is outside the
product boundary. Planned work must not make any of these appear implemented.

## Milestones at a glance

| Milestone | User problem | Required evidence | Exit criteria |
| --- | --- | --- | --- |
| **v0.2 — Agent Artifact Admission** | Review compound agent artifacts as one approval decision without losing component membership or provenance. | Deterministic aggregate fixtures, immutable identity evidence, capability deltas, content/capability drift cases, and incomplete-coverage cases. | Static aggregate review is reproducible; meaningful content/resource changes invalidate exact approval; capability changes remain distinct; unknown and dynamic surfaces are explicit. |
| **v0.2A — Agent Plugins 1.0** | Review a materialized plugin containing skills, MCP configuration, and extensions as one trust artifact. | Valid, malformed, compound, partial, client-extension, provenance, and aggregate-drift fixtures. | A reviewer sees every discovered component, observed lower-bound capabilities, blind spots, and the required policy decision without execution. |
| **v0.2B — MCP Skills snapshots** | Review a captured MCP Skills resource set without starting or querying a live server. | An approved materialized-input contract, complete/incomplete captures, resource digests and sizes, nested/dynamic cases, and exact-approval invalidation. | Snapshot admission is deterministic and origin-bound; content approval, capability drift, policy, and coverage are separate. |
| **Follow-up — Evidence & Benchmarking** | Learn whether extraction and drift evidence help reviewers on real public artifacts. | Licensed representative corpus, synthetic regression fixtures, provenance, methodology, and repeatable evaluation reports. | Accuracy claims are limited to defensible evidence; false positives, blind spots, incomplete scans, and reviewer actionability are published. |
| **Parallel — Distribution & Discoverability** | Let users find and reproduce original SkillGate evidence through familiar installation and technical-search paths. | Reproducible public reports, schemas, compatibility matrices, immutable sources, and synchronized documentation. | Distribution identity is coherent; public evidence is inspectable and refreshable without changing the local/no-upload default. |
| **Later — Evidence-gated semantic review** | Expose semantic instruction concerns only if reviewers can act on them reliably. | Existing semantic corpus plus representative artifacts, defensible precision/recall, and actionability review. | Public semantic output has a deliberate schema and migration story, or remains internal/advisory. |

## v0.2 implementation order

The order is part of the roadmap, not an implementation detail:

1. [v0.2A — Agent Plugins 1.0 aggregate admission](docs/roadmaps/agent-artifact-admission.md#v02a--agent-plugins-10-aggregate-admission)
   comes first because plugins are already materialized compound artifacts.
2. [v0.2B — MCP Skills static snapshot admission](docs/roadmaps/agent-artifact-admission.md#v02b--mcp-skills-static-snapshot-admission)
   comes second and requires an explicit static input/capture contract before
   any parser or adapter is designed.

The [Agent Artifact Admission roadmap](docs/roadmaps/agent-artifact-admission.md)
defines the review-layer separation, aggregate identity, provenance,
partial-coverage semantics, and evidence/exit criteria. It is planning only:
MCP Skills and Agent Plugins are not implemented by this document.

## Evidence and benchmarking

Keep two kinds of coverage separate:

1. **Synthetic regression fixtures** provide deterministic checks for known
   formats, malformed inputs, boundaries, redaction, and stable output.
2. **Representative public artifacts** measure real-world usefulness. Each
   artifact needs an immutable source identity, license/attribution record,
   scan date, adapter/tool version, and human-reviewed expected evidence where
   labels are required.

Evaluation should report, by artifact type and separately for incomplete scans:

- format and contract correctness;
- capability extraction and provenance accuracy;
- stable versus noisy drift behavior;
- true capability-change detection and false positives;
- semantic `SA001`/`SA002` precision and recall only where defensible;
- reviewer actionability and reviewer agreement; and
- skipped, invalid, unknown, and incomplete accounting.

The existing 24-case semantic corpus remains useful synthetic regression
coverage. It is not enough evidence for broad real-world semantic scanner
quality and must not be marketed as such. Publish methodology, corpus
boundaries, known blind spots, per-artifact-type results, thresholds, and exact
commands before making public accuracy claims.

## Distribution and discoverability

Treat distribution as a parallel workstream, with this explicit sequence:

`brand/package identity → Python distribution identity → simple PyPI/uvx installation → Node/npm wrapper decision → broader discoverability`

The sequence prevents a public package or search push from hardening an
ambiguous identity. The current repository name, brand, and
`openevalgate-skillgate` distribution plan remain unchanged in this planning
round. Do not publish or rename as part of this roadmap cleanup.

Public review reports and an evidence observatory may later support maintainers,
benchmarks, search engines, and answer engines. They must preserve immutable
source identity, scan limits, skipped/incomplete accounting, findings,
capability deltas, attribution, and redaction. This is not a hosted scanner and
does not change the local command's upload behavior.

Keep `llms.txt` as answer-engine orientation, not the primary SEO mechanism.
Prioritize high-intent technical documentation, compatibility matrices,
benchmark reports, schemas, public review reports, and example capability
diffs. Avoid generic content marketing and unsupported “safe” or “detects all
attacks” claims.

## Decision gate — brand and package identity

There is another project using the `SkillGate` name in the same broad
AI-agent-security space. Resolve the brand/package question before:

- a major public v0.2 launch;
- a PyPI or other public package push; or
- a major SEO/AEO and broader discoverability push.

This gate does not block internal v0.2A Agent Plugins model work. The decision
should compare:

1. retaining `SkillGate`, preserving recognition while accepting search and
   package ambiguity;
2. using `OpenEvalGate SkillGate` / `SkillGate by OpenEvalGate`, adding a
   differentiator at the cost of presentation complexity; or
3. renaming while adoption is still relatively small, accepting migration cost
   for cleaner long-term identity.

Consider GitHub discoverability, search and answer-engine ambiguity,
Python/npm/package names, website/domain identity, and community recognition.

## Later semantic review

The repository already contains an internal bounded semantic inventory,
`SA001`/`SA002` advisory helpers, and line-movement-stable semantic drift. They
remain library-only because representative-repository evidence and reviewer
actionability have not yet justified a public semantic CLI or Review Packet
integration.

Use the detailed [semantic artifact linting roadmap](docs/roadmaps/semantic-artifact-linting.md)
as a subordinate design record. Its next decision is an evidence gate, not an
immediate implementation task. Preserve current `SG007` compatibility and
Review Packet schema migration discipline.

## Maintenance rules and non-goals

- Keep this file as the canonical direction; link to it instead of copying
  roadmap prose into every documentation page.
- Keep release history in `CHANGELOG.md`; mark work as released only when it is
  actually released.
- Preserve stable CLI, JSON, SARIF, policy, Review Packet, and rule semantics
  unless a future milestone explicitly includes a migration plan.
- The composite Action can enforce a supplied `baseline` plus `fail-on-drift`
  when a repository explicitly opts into that gate.
- Keep findings deterministic, static, reproducible, redacted, and local-first.
- Do not start arbitrary MCP servers as the default review path. Runtime MCP
  behavior, runtime enforcement, sandboxing, and watchdogs remain outside this
  product boundary.
- This round adds no MCP Skills parser, Agent Plugins implementation, public
  semantic CLI, new rule, benchmark corpus implementation, package
  publication, package rename, website, CI behavior, or release.

This round stops at the planning/documentation patch. Implementation begins
only after review of the v0.2 contract, evidence requirements, and the brand
decision gate.
