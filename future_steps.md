# Product Direction and Future Steps

This is the canonical product-direction and roadmap document. README pages,
discovery notes, and recommendation guidance should describe the current
repository consistently and link here for planned work.

## Product direction

SkillGate is deterministic, no-execution admission control for agent artifacts
before install, merge, or approval. Its core review question remains:

> What new capability surface does this artifact introduce before I trust it?

The product is strongest when it turns an artifact into a reviewable decision:

- artifact identity and provenance;
- static capability evidence;
- capability diff and drift;
- reviewer-facing findings and approval state;
- policy-as-code and CI admission control; and
- explicit no-execution boundaries.

This is a more useful product center than the generic label “AI-agent security
scanner.” SkillGate may be used as a static security scanner, but it is not
trying to be a runtime MCP gateway, sandbox, malware verdict engine, LLM-first
scanner, hosted security platform, generic agent framework, or runtime
watchdog. Runtime enforcement, isolation, least-privilege credentials, and
monitoring remain complementary controls.

## Current baseline and shipped status

The current stable release is `v0.1.3`. It established the pre-install review
workflow, Review Packet v2, deterministic packet and source-manifest evidence,
MCP protocol/extension inventory, capability baselines and drift, provenance,
policy-as-code, and the no-execution product boundary. Historical release
details remain in `CHANGELOG.md`; do not rewrite release-note history to make
the roadmap current.

PyPI and npm publication remain deferred; GitHub tags and GitHub Release assets are the
supported distribution paths for the current release line.

The current repository baseline includes the following capabilities. The
`Unreleased` changelog entry identifies which recent work is not yet part of
the `v0.1.3` release:

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
  instruction drift helpers. These semantic helpers are not public CLI,
  Review Packet, SARIF, policy, or baseline behavior.

MCP Skills and Agent Plugins support are not shipped CLI capabilities today.
They are the proposed next product milestone below. The roadmap must not make
the current scanner appear to support them before implementation and evidence
exist.

## Roadmap at a glance

| Milestone | User problem | Required evidence | Exit criteria |
| --- | --- | --- | --- |
| **v0.2 — Agent Artifact Admission** | Review a complete MCP Skills snapshot or Agent Plugin as one approval decision, with identity, provenance, capability delta, and drift. | Conformance fixtures, immutable manifests, representative compound artifacts, and reviewer checks for invalidation and incomplete coverage. | Static snapshots are reviewable without server execution; aggregate output is deterministic; meaningful content/resource changes invalidate approval; unknown and dynamic surfaces are explicit. |
| **Follow-up — Evidence & Benchmarking** | Establish whether extraction and drift evidence are useful on real public artifacts instead of growing the rule count blindly. | A licensed, provenance-preserving public corpus plus synthetic regression fixtures and repeatable evaluation reports. | Metrics, limitations, false positives, skipped/incomplete scans, and reviewer actionability are published per artifact type; no unsupported accuracy claim remains. |
| **Parallel — Distribution & Discoverability** | Make high-intent users, maintainers, search engines, and answer engines find original SkillGate evidence. | Reproducible public review reports, compatibility matrices, schemas, capability diffs, and synchronized documentation. | Public reports can be reproduced from immutable sources, linked to machine-readable outputs, and refreshed without weakening the local/no-upload default. |
| **Later — Evidence-gated semantic review** | Expose semantic instruction concerns and declared-purpose mismatches only if representative evidence shows reviewers can act on them. | The existing semantic corpus plus representative public artifacts, precision/recall where defensible, and actionability review. | Public semantic output has a deliberate schema and migration story; otherwise the internal inventory/drift work remains internal or is narrowed. |

## v0.2 — Agent Artifact Admission

### User problem

An artifact increasingly contains more than one independently interesting file:
a skill, a server configuration, manifests, and supporting resources. Reviewers
need one trust decision for the artifact they are about to install, not a set of
unrelated file scans that lose component membership and provenance.

The v0.2 goal is static admission review for two compound formats while
preserving the existing local-first, deterministic, no-execution contract.

### A. Static MCP Skills admission review

The stable MCP Skills extension defines a transport binding for Agent Skills;
it is not an `index.json` convention. The roadmap should follow the published
[MCP Skills extension](https://skills.extensions.modelcontextprotocol.io/specification/stable/skills),
identified as `io.modelcontextprotocol/skills`, including:

- `skills/list` as the authoritative catalog operation;
- `skills/get` for one skill identified by the URI of its `SKILL.md`;
- ordinary `resources/read`, plus optional `resources/directory/read` when the
  server declares directory-read support;
- verbatim `SKILL.md` frontmatter in the skill entry;
- a complete resource set whose entries contain each resource URI, its raw-byte
  SHA-256 digest (`sha256:<hex>`), and byte size; and
- the string `dynamic` when stable resource digests cannot be published.

SkillGate should review a materialized directory, archive, or captured MCP
snapshot. A snapshot may contain the relevant `skills/list`/`skills/get`
records and the resource bytes they describe. The adapter must not start an
arbitrary MCP server, call `skills/list` or `skills/get` against a live server,
or make runtime MCP behavior part of admission review.

The normalized identity and evidence model must preserve:

- originating server/host identity **and** skill resource URI; URI alone is not
  a safe identity because different origins may serve the same URI;
- skill frontmatter and the `SKILL.md` resource as separate, checkable evidence;
- every declared resource URI, digest, and size, including nested-skill files;
- the relationship between nested or explicitly referenced/dependent skill
  surfaces; and
- names as display labels, not globally unique identifiers. Same-name skills
  must remain disambiguated by origin and URI.

The static review should verify path containment, manifest completeness,
frontmatter consistency, digest and size matches, duplicate/colliding
identities, nested-skill coverage, and declared-versus-materialized resource
sets. A changed digest, size, frontmatter field, resource membership, nested
resource, or origin must be visible as meaningful drift and invalidate an
approval bound to the old snapshot. A `dynamic` resource set cannot receive a
deterministic content-bound approval; report that limitation explicitly rather
than treating it as a clean result.

The review output should attach every capability and finding to the origin,
skill URI, resource URI, and local evidence path where available. It should
also account for incomplete or skipped resources so a partial snapshot cannot
look equivalent to a complete review.

### B. Agent Plugins 1.0 aggregate review

The roadmap should target the published [Agent Plugins 1.0
specification](https://agent-plugins.org/specification). Its portable core is
conceptually:

```text
plugin/
├── plugin.json
├── skills/
│   └── .../SKILL.md
└── mcp.json
```

`plugin.json` is the required root manifest. `skills/` contains Agent Skills,
and `mcp.json` contains the portable MCP server configuration. Client-specific
extension namespaces are part of the package shape but do not acquire invented
portable semantics from SkillGate.

SkillGate should review the plugin as one aggregate trust artifact:

- **Identity:** normalize the plugin root or archive identity, source URL and
  immutable revision/digest, the `plugin.json` schema/name/version metadata,
  and the identities of every discovered component.
- **Provenance:** retain source path, immutable source identity, file digest,
  byte size, component membership, and the adapter/version that interpreted
  each field. Preserve client-extension files as explicit extension evidence
  or unknown review surfaces rather than silently dropping them.
- **Normalization:** validate the root manifest and fixed component locations;
  normalize every skill and its supporting files; normalize every `mcp.json`
  server entry; and retain raw declaration paths for evidence. Do not execute
  skill scripts, resolve dependencies, start MCP servers, or load client
  extensions.
- **Capability delta:** union and deduplicate observed capabilities across the
  manifest, all skills, supporting resources, and MCP server declarations while
  retaining component-level evidence. The primary review object is the plugin
  delta, not independent approvals for unrelated files:

  ```text
  Plugin capability delta

  + shell execution
  + filesystem writes
  + outbound network access
  + MCP server
  + credential reference

  Approval state: new capability surface
  ```

- **Baseline and drift:** compare the aggregate plugin identity, component
  membership, skill/resource digests, MCP configuration, and meaningful
  manifest changes. Additions, removals, or changes must explain which
  component caused the capability delta. A changed component or aggregate
  resource set must not inherit approval silently.
- **Review behavior:** produce one reviewer decision with component evidence,
  provenance, limitations, and explicit unknowns. A clean skill must not make a
  separate bundled MCP server disappear from the approval view.

### v0.2 evidence and exit criteria

Before calling v0.2 complete, the repository needs:

- synthetic fixtures for valid, malformed, incomplete, nested, colliding, and
  dynamic MCP Skills snapshots;
- Agent Plugins 1.0 fixtures covering skills-only, MCP-only, compound, invalid
  path, schema/version, and client-extension cases;
- deterministic identity, provenance, capability, and drift examples that a
  reviewer can inspect without executing anything;
- representative compound artifacts to test whether aggregate output is more
  actionable than separate file results; and
- documented behavior for skipped files, dynamic resources, unknown extension
  fields, and missing origin identity.

The milestone exits only when a reviewer can reproduce the aggregate decision
from the immutable input, understand every new capability and its evidence,
see why approval was invalidated after meaningful drift, and distinguish
static admission evidence from runtime MCP behavior. A protocol or package
claim that cannot be verified from the materialized input remains unknown.

## Follow-up — Evidence & Benchmarking

### User problem

More rules are not evidence that SkillGate makes better admission decisions.
The project needs to know whether artifact-format extraction, provenance,
capability deltas, drift, and semantic signals are correct and useful on real
public inputs.

### Evidence workstream

Keep two kinds of coverage separate:

1. **Synthetic regression fixtures** provide deterministic correctness checks for
   known cases, malformed inputs, boundary limits, redaction, and stable output.
2. **Representative public artifacts** measure real-world usefulness. Every
   artifact needs an immutable source identity, license/attribution record,
   scan date, adapter/tool version, and human-reviewed expected evidence where
   labels are required.

Evaluation should report, by artifact type and separately for incomplete scans:

- format and contract correctness;
- capability extraction accuracy and provenance accuracy;
- stable versus noisy drift behavior;
- true capability-change detection;
- false positives on benign public artifacts;
- semantic `SA001`/`SA002` precision and recall only where defensible;
- reviewer actionability and reviewer agreement; and
- skipped/incomplete scan accounting, including dynamic or unavailable
  resources.

The existing 24-case semantic corpus remains valuable synthetic regression
coverage. It is not enough evidence for broad real-world semantic scanner
quality and must not be marketed as such.

### Exit criteria

Publish a reproducible report with corpus boundaries, provenance, methodology,
known blind spots, per-artifact-type results, and the exact command/configuration
used. Set evaluation thresholds before inspecting results and do not convert
synthetic scores into unsupported production accuracy claims. A feature exits
this workstream only when reviewers can reproduce the result and the measured
false-positive and actionability profile justifies the public surface it would
enable. Otherwise keep it advisory, internal, or narrow its scope.

## Parallel — Distribution and discoverability

### Public review corpus / observatory

Adoption is now a product workstream. Build planning around a reproducible set
of public review reports for important Agent Skills, Agent Plugins, MCP
artifacts, MCP Apps, and MCP Skills. This is not a hosted scanner and does not
change the local command's upload behavior.

Each report should preserve, where available:

- source URL and immutable commit, archive, or digest identity;
- scan date, SkillGate version, adapter version, and limits;
- artifact manifest and skipped/incomplete accounting;
- observed capabilities, findings, and aggregate capability delta;
- baseline/drift comparison and approval state;
- limitations, unknowns, and review notes; and
- machine-readable output alongside a readable report.

The goal is original, inspectable evidence that helps users and maintainers,
supports benchmarks, and gives search engines and answer engines something
technical to cite. Public reports must respect source licenses, attribution,
redaction, and immutable-input boundaries.

### SEO and AEO, grounded in technical evidence

Keep `llms.txt`, but treat it as an answer-engine orientation file, not the
primary SEO mechanism. Focus public documentation and reports on high-intent
technical topics:

- Agent Skill security and pre-install Agent Skill review;
- MCP Skills security and static MCP review;
- Agent Plugins security and aggregate plugin review;
- MCP security review;
- agent capability drift;
- agent artifact provenance; and
- agent supply-chain security.

The strongest discoverability assets are compatibility matrices, benchmark
reports, public review reports, schemas, example capability diffs, and protocol
analysis. Avoid generic content marketing and unsupported “safe” or “detects
all attacks” claims. Keep the public website, README, `docs/`, `llms.txt`, and
shipped CLI behavior synchronized.

## Later — Evidence-gated semantic review

The repository already contains an internal bounded semantic inventory,
`SA001`/`SA002` advisory helpers, and line-movement-stable semantic drift. They
remain library-only because representative-repository evidence and reviewer
actionability have not yet justified a public semantic CLI or Review Packet
integration.

Use the detailed [semantic artifact linting roadmap](docs/roadmaps/semantic-artifact-linting.md)
as a subordinate design record. Its next decision is an evidence gate, not an
immediate implementation task. Only after that gate should the project consider
public semantic findings, declared-purpose versus observed-capability versus
instruction comparisons, or semantic policy controls. Preserve the current
`SG007` compatibility and the Review Packet schema migration discipline.

## Decision gate — brand and package identity

There is another project using the `SkillGate` name in the same broad
AI-agent-security space. Do not rename automatically, but resolve this before
major distribution and discoverability work.

Evaluate three options:

1. **Continue as `SkillGate`.** Preserves repository, documentation, and early
   community recognition, but leaves search and answer-engine ambiguity.
2. **Use `OpenEvalGate SkillGate` / `SkillGate by OpenEvalGate`.** Keeps the
   product name while adding a differentiator; it costs naming complexity and
   requires consistent repository, website, README, and package presentation.
3. **Rename while adoption is still relatively small.** Creates the cleanest
   long-term search and package identity, but requires migration of links,
   examples, users, and community recognition.

The decision must consider GitHub discoverability, search and answer-engine
ambiguity, Python/npm/package names, website and domain identity, and long-term
community recognition. The current repository name, brand, and
`openevalgate-skillgate` distribution plan remain unchanged in this planning
round.

## Maintenance rules and non-goals

- Keep `future_steps.md` as the canonical direction; link to it instead of
  copying roadmap prose into every documentation page.
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
- Do not add an MCP Skills parser, Agent Plugins support, public semantic CLI,
  benchmark corpus implementation, website, CI behavior, package rename, or
  release as part of this planning patch.

This round stops at the planning/documentation patch. Implementation begins
only after review of the v0.2 contract, evidence requirements, and the brand
decision gate.
