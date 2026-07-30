# Future Steps

## Product Direction

SkillGate is a local-first, deterministic trust gate for AI-agent skills, MCP
configurations, MCP bundles, and agent-tooling supply chains. Its clearest job
is to answer this question before install, merge, or approval:

> What new capability surface does this artifact introduce?

The roadmap prioritizes complete review workflows, low-friction distribution,
and public evidence over a large number of loosely connected rules. SkillGate
should not become a hosted dashboard, runtime gateway, malware scanner, or
generic agent framework without a deliberate product decision.

## Current Baseline

The current stable release is `v0.1.3`. The shipped baseline includes:

- local and sparse GitHub static scans;
- deterministic findings for agent instructions, scripts, MCP metadata, and
  capability risks;
- policy-as-code, waivers, baselines, capability drift, and provenance checks;
- text, JSON, SARIF, Markdown review summaries, and GitHub Step Summary output;
- MCP registry comparison and MCPB pre-install inspection without execution;
- a composite GitHub Action with policy, baseline, review artifact, and MCPB
  support;
- a checksummed GitHub-first Node wrapper;
- `skillgate skills validate` and deterministic Agent Skill/MCPB demos; and
- guided review sessions for local review, pre-install review, and approval;
- deterministic pre-install packet digests, source manifests, and a public
  Review Packet JSON Schema; and
- static MCP protocol-version and extension inventory through scan, baseline,
  registry comparison, and advisory pre-install evidence.

These are release history, not future work. Keep detailed records in
`CHANGELOG.md`.

## 0.1.3 Release Status

`v0.1.3` was released on 2026-07-29. It delivered the adoption workflow,
review-evidence foundations, and first MCP compatibility inventory. PyPI and npm
publication remain deferred; GitHub tags and GitHub Release assets are the
supported distribution paths. The next implementation work is the MCP
compatibility sequence below.

## MCP 2026-07-28 Compatibility TODO

Support the legacy MCP protocol revisions and `2026-07-28` in parallel during
the ecosystem transition. This is a compatibility and review-surface workstream,
not a change to SkillGate's local-first,
deterministic, no-execution product boundary. The release makes stateless
requests, extension negotiation, MCP Apps, Tasks, stronger authorization
guidance, and full JSON Schema 2020-12 part of the ecosystem. SkillGate should
review what those declarations introduce without implementing an MCP client,
gateway, renderer, or runtime policy engine.

### Near-term implementation order

1. **Version and extension inventory (implemented).** SkillGate now inventories
   explicit declared legacy and modern protocol revisions, reverse-DNS extension
   IDs/versions, and malformed declarations without inferring behavior. A mixed
   declaration is retained as advisory migration evidence, never an upgrade
   requirement. The capability data flows through reports, baselines, registry
   comparison, and optional pre-install packet metadata without a packet-schema
   bump. See
   [`docs/mcp-compatibility.md`](docs/mcp-compatibility.md) for the review and
   migration boundary.

2. **MCP Apps static adapter (implemented).** SkillGate now recognizes modern
   and legacy MCP Apps resource declarations, UI MIME types, CSP origins,
   browser permissions, app-callable tools, host bridge markers, local/GitHub
   referenced HTML/CSS/JS assets, and bounded MCPB web assets without rendering,
   importing, executing, or dereferencing declared URLs. See
   [`docs/mcp-apps-static-review.md`](docs/mcp-apps-static-review.md).

3. **Skills over MCP adapter (next).** Accept a local materialized snapshot, index, or
   archive of MCP-delivered skills. Validate `index.json` name/description/URI
   metadata against `SKILL.md`, verify declared digests, preserve archive
   provenance, and pass the resulting files through existing Agent Skill,
   semantic-inventory, and archive-safety checks. Do not require live server
   introspection or make a remote MCP server part of scanning.

4. **Tasks capability signal.** Detect opt-in Tasks declarations and tools that
   can create, poll, update, or cancel durable work. Record long-running or
   deferred execution as a capability requiring review; do not infer runtime
   behavior or execute a task.

5. **Schema and authorization metadata checks.** Add bounded checks for full
   JSON Schema constructs, external `$ref` references, unrestricted output
   schemas, OAuth/OIDC issuer and resource metadata, and declared credential or
   scope requirements. Never dereference schemas, call authorization endpoints,
   or retain secret values.

### Policy and evidence follow-up

- Add fixtures for Skills index/digest mismatch, Tasks, external `$ref`, and
  OAuth issuer drift.
- Extend MCP baselines and policy templates only after the normalized capability
  model is stable. Candidate controls include allowed extension IDs, UI origins,
  protocol revisions, task capability, and authorization issuers.
- Publish benchmark and migration notes with the first compatibility release;
  keep findings advisory until representative-repository review demonstrates
  reviewer actionability.
- Keep semantic CLI exposure, blocking semantic policy, and declared-purpose
  mismatch enforcement behind the existing evidence gates.

### Explicit non-goals

Do not add MCP server startup or introspection, a stateful MCP proxy/gateway,
browser/UI rendering, task execution, OAuth exchanges, automatic schema
resolution, telemetry, or a generic extension-specific rule family. Unknown
extension behavior should remain an explicit review surface rather than an
invented verdict.

## Later Work

### Semantic artifact linting

Explore semantic artifact linting only as an opt-in, local-first extension to
pre-install and pre-merge review. The goal is to surface suspicious
agent-directed instructions that are already shipped in skills, MCP configs,
MCPB bundles, manifests, prompt templates, and explicitly agent-facing static
text artifacts. Ordinary README prose, arbitrary comments, binaries, rendered
pages, and unclassified bundled assets are not semantic inputs by default.

This is not a pivot into runtime prompt-injection protection. Runtime web
content, email, RAG stores, MCP server execution, hosted prompt firewalls,
sandboxing, and action approval enforcement remain out of scope unless the
project makes a separate product decision.

Use the staged roadmap in
[`docs/roadmaps/semantic-artifact-linting.md`](docs/roadmaps/semantic-artifact-linting.md)
before implementing any semantic scanner. Rebase implementation work onto the
current Review Packet schema and preserve existing `SG007`/`SG008` behavior.
The initial compatibility, source-role, and inventory decisions are recorded
in [`docs/semantic-artifact-inventory.md`](docs/semantic-artifact-inventory.md).
The staged sequence is:

```text
contract and SG007 compatibility
→ bounded text inventory
→ narrow advisory rules and adversarial evaluation
→ semantic instruction drift
→ opt-in review integration and public evidence
→ declared-purpose/capability/instruction comparison
→ policy and suppression support
```

The first milestone is a bounded deterministic text inventory followed by a
small, high-precision, library-only advisory rule pack. Semantic policy remains
gated on representative repository evidence. This is not a classifier or
blocking-policy commitment.

The committed synthetic semantic-artifact corpus and its internal evaluation
harness now validate source selection, labels, actual `SA001`/`SA002` rule-pack
observations, and category metrics. The library-only pack meets its synthetic
24-case gate (100% recall, zero false positives). The library-only semantic
baseline also produces redacted, line-movement-stable instruction drift for
internal callers. These remain internal tooling rather than public product
surfaces. A semantic CLI, including `review preinstall --semantic` or a
standalone semantic command, is explicitly delayed
until representative-repository and reviewer-actionability evidence justifies
it.

### Declared purpose, capability, and instruction comparison

After semantic review and drift have real usage, add an explainable comparison of
what an artifact claims to do, what its code/configuration can do, and what its
agent-facing instructions request. Report potential mismatches with evidence;
do not infer maintainer intent or label a mismatch malicious without proof.

### Targeted MCPB and Agent Skills expansion

Expand MCPB policy controls and Agent Skills validation only in response to
real adoption evidence. Do not add new rule families or rule IDs merely to make
the roadmap look larger.

## Maintenance Requirements

Keep the documented Action behavior stable for advisory scans, blocking policy
checks, baseline drift blocking, GitHub Step Summary, Markdown summaries, JSON
artifacts, and SARIF review artifacts. Preserve copy-pasteable examples for:

- nonblocking scan with SARIF retained as a pull-request artifact;
- blocking policy check with policy-aware SARIF;
- baseline drift blocking; and
- review-summary artifact upload.

The composite Action can enforce a supplied `baseline` plus `fail-on-drift` when
a repository explicitly opts into that gate.

Do not add telemetry without an explicit privacy design and opt-in decision.

## Release Checklist References

The release checklist records the `v0.1.3` publication and binary verification
procedure. Use it with `uv sync --locked`, the generated benchmark report, the
starter-repository smoke test, and the final no-execution review.
