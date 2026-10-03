# Agent Artifact Admission Roadmap

This is the subordinate design record for the v0.2 Agent Artifact Admission
milestone in [`future_steps.md`](../../future_steps.md). It is planning only.
It does not define a new CLI, parser, rule, snapshot format, or approval
implementation.

The implementation order is deliberate:

1. **v0.2A — Agent Plugins 1.0 aggregate admission**
2. **v0.2B — MCP Skills static snapshot admission**

Agent Plugins come first because they are already materialized compound
filesystem artifacts and compose capability surfaces SkillGate largely
understands today. MCP Skills come second because the protocol's live
operations require an explicit materialized-input contract before static
admission can be implemented.

## Separate review layers

SkillGate must keep three different questions separate:

| Layer | Question | Evidence | Meaning of change |
| --- | --- | --- | --- |
| **Artifact/content identity** | Is this the exact material reviewed? | Source identity, scanned-file manifest, artifact/archive digest, resource URI, origin, resource digest, and size. | Exact reviewed material changed. Content-bound approval may be stale. |
| **Capability identity** | Did the normalized capability surface change? | Normalized capability type, resource, and details; source-line movement is review context, not identity. | Capability approval/baseline may require review. |
| **Policy decision** | Is the current observed surface allowed? | Policy rules, capability approvals, finding waivers, reviewer decision, and any required baseline review. | The policy or reviewer decides whether the current surface is acceptable. |

These layers are related but not interchangeable:

```text
Artifact/content drift
    Exact reviewed material changed.

Capability drift
    Normalized capability surface changed.

Policy decision
    A policy or reviewer decides whether the current capability surface is allowed.
```

A harmless text edit may produce:

```text
Content changed: YES
Capability changed: NO
```

That is valid evidence. It must not be relabeled as generic `SG010`-style
capability drift.

The current implementation provides the compatibility boundary that future
adapters must preserve:

- `ScannedFile.sha256` and `BaselineLock.files` represent exact scanned-file
  identity; `DiffReport.modified_files` reports changed file bytes.
- `canonical_capability()` omits `source_line` and compares normalized
  capability records, so harmless line movement does not create a capability
  delta.
- `SG010` currently reports changed MCP server capability details. It is not a
  generic finding for every changed artifact digest.
- `check` and `diff --policy` evaluate the current observed surface against
  policy. `diff --fail-on-drift` is an explicit gate over reported baseline
  changes; a failing gate does not prove that every modified file changed
  capability.

Future aggregate reports should expose these states independently, for example:

```text
content_approval: stale
capability_baseline: unchanged
policy_decision: review_required
coverage: complete
```

If a team requires exact content approval, unchanged capability approval does
not silently make stale content approved. If a team only approves normalized
capabilities, content drift can remain visible without manufacturing a
capability change. The review contract must state which approval is being made.

## v0.2A — Agent Plugins 1.0 aggregate admission

### Scope

Review a published [Agent Plugins 1.0 package](https://agent-plugins.org/specification)
as one aggregate trust artifact. The portable core is:

```text
plugin/
├── plugin.json
├── skills/
│   └── .../SKILL.md
└── mcp.json
```

`plugin.json` is the required root manifest. `skills/` contains Agent Skills,
and `mcp.json` contains portable MCP server configuration. Client-specific
extension namespaces remain explicit package surfaces, but SkillGate must not
invent portable semantics for a client extension it does not understand.

This stage must not execute skill scripts, resolve dependencies, start MCP
servers, load client extensions, or treat a clean component as evidence that
its siblings are clean.

### Normalized identity and provenance

The aggregate identity should preserve:

- plugin root or archive identity;
- source URL and immutable commit, archive, or content digest when available;
- `plugin.json` schema, name, version, and relevant manifest fields;
- component membership and fixed component locations;
- per-file path, digest, byte size, and component ownership; and
- the adapter/version and source declaration path used to interpret each field.

A plugin approval is not a loose collection of file approvals. Every capability
and finding must retain its plugin, component, and source-file context.

### Aggregate capability review

Normalize and aggregate:

- manifest-declared metadata that affects review;
- each discovered Agent Skill and its supporting files;
- every portable MCP server entry in `mcp.json`; and
- client extension files as understood evidence or explicit unknown surfaces.

Deduplicate the aggregate capability surface while retaining component-level
evidence. The primary review object is the plugin delta:

```text
Plugin capability delta

+ shell execution
+ filesystem writes
+ outbound network access
+ MCP server
+ credential reference

Approval state: new capability surface
```

The aggregate result must not hide a bundled MCP server because its sibling
skill is clean, and it must not claim capabilities for an uninterpreted
component. Uninterpreted components create unknown or incomplete coverage, not
invented values.

### Partial and incomplete coverage

Plugin review is not an all-or-nothing `valid`/`invalid` result. The output must
separate component status from aggregate coverage.

A required coverage shape is:

```text
Plugin review coverage

Manifest             valid

Skills
  discovered         3
  reviewed           2
  invalid/skipped    1

MCP servers
  discovered         2
  reviewed           1
  invalid/skipped    1

Client extensions
  discovered         1
  understood         0
  unknown            1

Coverage              INCOMPLETE
```

The review model should retain at least these distinctions:

- `reviewed`: the component was found, interpreted, and included in evidence;
- `invalid`: the component was found but violates its applicable contract;
- `skipped`: the component could not be safely or completely inspected;
- `unknown`: the component or extension was found but its semantics are not
  understood; and
- `incomplete`: aggregate coverage is insufficient for a complete approval.

Required behavior:

1. Preserve observed capabilities and evidence from reviewable components.
2. Keep invalid, skipped, and unknown siblings visible in the same aggregate
   report.
3. Mark aggregate coverage `INCOMPLETE` whenever relevant components are not
   reviewed, even if all observed capabilities look acceptable.
4. Do not represent incomplete observed capabilities as the complete plugin
   capability surface; they are a lower bound with explicit blind spots.
5. Do not silently convert unknown client-extension behavior into portable
   capabilities or a clean result.
6. Do not issue a complete approval for a partial review. The aggregate state
   should remain `review_required`, `incomplete`, or an equivalent explicit
   non-approval state.

Preserve the Agent Plugins specification's component/error boundaries rather
than adding a package-wide all-or-nothing rule. In particular, a missing root
manifest is a package-level failure; an invalid discovered skill can remain an
invalid or skipped skill while other skills are reviewed; and an invalid MCP
server entry must not erase evidence from other server entries. Path escape and
unsafe archive conditions remain fail-closed under the existing archive-safety
boundaries.

### Aggregate drift and approval

Compare both aggregate content identity and normalized capability identity:

- plugin manifest and component membership changes are content drift;
- skill/supporting-file digest changes are content drift;
- MCP declaration changes may be both content drift and capability drift;
- extension additions or changes remain component-level evidence, even when
  their semantics are unknown; and
- added, removed, modified, invalid, or newly skipped components must identify
  the component that caused the aggregate change.

A plugin capability baseline can remain unchanged when a content change does not
alter normalized capabilities. Conversely, a capability delta must be visible
even when the changed file is not itself executable. Exact content approval and
capability approval must never be updated implicitly by the other.

### v0.2A evidence and exit criteria

Before v0.2A exits, provide:

- skills-only, MCP-only, and compound Agent Plugins 1.0 fixtures;
- valid and malformed `plugin.json` and `mcp.json` cases;
- invalid and skipped skill/server entries that coexist with reviewable siblings;
- client-extension cases with understood and unknown coverage;
- aggregate identity, provenance, capability, and drift examples;
- content-only changes that leave capability identity unchanged; and
- reviewer output showing observed evidence, coverage, unknowns, and approval
  state separately.

The milestone exits only when a reviewer can answer all of these without
execution:

- What is the exact plugin artifact being reviewed?
- Which components were discovered, reviewed, invalid, skipped, or unknown?
- What capabilities were observed, and which surfaces remain unreviewed?
- Did content change, capability change, or both?
- What policy/reviewer decision is required?

## v0.2B — MCP Skills static snapshot admission

### Contract design comes first

The stable [MCP Skills extension](https://skills.extensions.modelcontextprotocol.io/specification/stable/skills)
defines live operations such as `skills/list`, `skills/get`, `resources/read`,
and optional `resources/directory/read`. SkillGate intentionally does not start
arbitrary MCP servers or call those operations during a normal local review.

Before implementing an MCP Skills adapter, define the static input/capture
contract as a separate design step. The project must not quietly turn a
temporary internal representation into a permanent bespoke snapshot standard.

Potential materialized inputs include:

- a directory containing captured skill metadata and resource files;
- an archive with a manifest and resource bytes;
- captured protocol records plus the resource bytes they describe; or
- another portable representation if the ecosystem standardizes one.

The contract decision must define:

- how the originating server/host identity is captured;
- how `skills/list` pagination and `skills/get` records are represented;
- how resource URIs map to local materialized bytes;
- how raw bytes, encoding, digest, and size are preserved;
- how incomplete captures, protocol errors, and unavailable resources are
  represented;
- whether the representation is an interchange format or only a local
  review input; and
- how the contract is versioned without claiming ecosystem standardization.

No MCP Skills parser implementation starts before this design step has an
approved input contract.

### Static identity and resource evidence

The adapter design must preserve the stable extension's distinctions:

- extension identity `io.modelcontextprotocol/skills`;
- skill identity as originating server/host identity plus the skill URI, not URI
  alone;
- `SKILL.md` frontmatter and its resource URI;
- every resource URI, raw-byte SHA-256 digest (`sha256:<hex>`), and byte size;
- `resources: "dynamic"` as an explicit inability to publish stable content
  digests;
- nested skills and their resource-set relationships; and
- same-name skills disambiguated by origin and URI.

A materialized snapshot review should verify declared-versus-materialized
resource membership, digest and size matches, frontmatter consistency, path
containment, nested-skill coverage, and duplicate or colliding identities. A
resource-set, digest, size, frontmatter, or origin change must invalidate an
approval bound to the old exact content.

Dynamic resources do not receive a deterministic content-bound approval. The
review should report the limitation and any incomplete coverage explicitly. It
must not treat a server-supplied digest or a dynamic resource declaration as
proof of trust.

### MCP Skills approval and capability drift

MCP Skills content-bound approval is exact-resource approval. It answers:

> Is this origin-bound resource set the one that was reviewed?

It does not replace capability-level approval. A change to `SKILL.md` or a
supporting resource can invalidate content approval while leaving the normalized
capability surface unchanged. If the materialized skill contains scripts,
network declarations, secrets, or other reviewable surfaces, those capabilities
must be compared through the normal capability model.

The result should be able to state:

```text
Content changed: YES
Capability changed: NO
Content approval: stale
Capability baseline: unchanged
Policy decision: depends on the configured approval requirement
```

A capability change should remain a capability change even if content approval
is already stale. The two deltas must be reported separately and policy must
decide how they combine.

### v0.2B evidence and exit criteria

Before v0.2B exits, provide:

- an approved static input/capture contract;
- complete, incomplete, malformed, nested, same-name, and dynamic-resource
  fixtures;
- origin-plus-URI identity and resource digest/size verification examples;
- content-only changes that preserve capability identity;
- resource-set changes that invalidate exact approval;
- explicit incomplete-capture and runtime-out-of-scope evidence; and
- a reviewer-facing result that separates content approval, capability drift,
  policy decision, and coverage.

The milestone exits only when the adapter can review a materialized input without
starting a server, reproduce its identity and evidence, show why exact approval
is stale, and avoid treating content drift as automatic capability drift.

## Shared v0.2 review contract

Both adapters should expose a common aggregate vocabulary without forcing their
inputs into one protocol format:

```text
artifact_identity
component_membership
provenance
coverage
content_drift
capability_drift
observed_capabilities
unknown_surfaces
content_approval
capability_baseline
policy_decision
```

The common contract must preserve:

- deterministic ordering and redacted evidence;
- source and component attribution;
- explicit skipped/incomplete accounting;
- no-execution behavior;
- unknown rather than guessed host, command, path, or capability values; and
- compatibility with existing capability baseline, policy, Review Packet, and
  provenance semantics.

No new rule ID, public CLI, policy field, or packet schema is implied by this
design document. Those are later implementation decisions requiring their own
compatibility and evidence review.
