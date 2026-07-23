# Semantic Artifact Linting Roadmap

## Decision summary

SkillGate should not pivot from deterministic pre-install and pre-merge trust checks into a runtime prompt-injection firewall. The stronger direction is a narrow, opt-in capability called **semantic artifact linting**.

Semantic artifact linting inspects agent-facing text that is already shipped inside a repository, skill, MCP configuration, or MCP bundle. It looks for review-worthy instructions that may steer an LLM toward hidden behavior, instruction override, secret access, data exfiltration, unsafe tool use, or authority spoofing before the artifact is installed or merged.

This keeps SkillGate's core promise intact:

- local-first;
- static;
- no execution;
- no dependency installation;
- no server startup;
- deterministic where possible;
- evidence-first rather than accusation-first;
- advisory unless a caller explicitly opts into policy enforcement.

The product should say:

> SkillGate identifies suspicious agent-directed instructions in shipped artifacts. It does not claim to prove that an agent is safe from runtime prompt injection.

## Why this is worth doing

The agent-security research landscape includes runtime and semantic attacks:

- InjecAgent studies indirect prompt injection in tool-integrated agents.
- AgentDojo evaluates stateful, dynamic, multi-tool agents under attack.
- MCP security discussions increasingly focus on tool poisoning, server instructions, authorization, confused deputy risks, and runtime trust boundaries.
- OWASP's classic Benchmark project is mainly a conventional software vulnerability benchmark, while OWASP's newer GenAI and agentic work is more relevant to LLM-agent behavior.
- Prompt-injection guidance repeatedly emphasizes that runtime controls, action
  gating, sandboxing, and least privilege remain necessary.

The opportunity for SkillGate is the gap before runtime: reviewers still need to inspect the natural-language instructions, manifests, tool descriptions, prompts, and docs that ship with agent artifacts. Those surfaces are not fully covered by classic SAST, package scanners, or runtime benchmarks.

This is where SkillGate can stand out:

> Most benchmark work shows how agents fail at runtime. SkillGate can make shipped agent semantics reviewable before runtime begins.

## Product positioning

Use this language externally:

> Semantic artifact linting for agent-facing instructions.

Avoid these claims:

- prompt-injection prevention;
- jailbreak prevention;
- malware detection;
- runtime protection;
- exploit proof;
- model-safety guarantee;
- universal MCP security scanner.

Use these claims instead:

- surfaces review-worthy agent-directed instructions;
- identifies suspicious semantic cues in shipped artifacts;
- helps reviewers distinguish expected instructions from risky suggestions;
- supports deterministic pre-install and pre-merge review;
- produces evidence packets and suppressible findings;
- complements runtime least privilege, sandboxing, and approval flows.

## In scope

Scan only bounded text that is already present in the artifact under review. The
first implementation must classify the source role instead of assuming that all
prose is agent-facing.

Primary sources:

- Agent Skill `SKILL.md` files;
- MCP server manifests and configuration files;
- MCPB `manifest.json` fields;
- MCP tool descriptions and server instructions when available statically;
- prompt templates;
- explicitly agent-facing sections of README or documentation when selected by
  the source adapter;
- Markdown, JSON, YAML, TOML, and selected source comments when their source role
  is known; HTML/CSS is a separate structural-scanning candidate, not a default
  semantic input;
- bounded textual members selected by MCPB/archive safety rules;
- deterministic demo and fixture artifacts committed to this repository.

Ordinary README prose, arbitrary comments, binary files, rendered pages, and
unclassified bundled assets are not semantic inputs by default. Unknown source
role stays unknown rather than being inferred from wording alone.

Candidate high-signal semantic patterns:

- instruction override language;
- role hijack language;
- authority spoofing;
- hidden or silent behavior instructions;
- requests to conceal actions from the user;
- agent-directed sensitive-data, token, file, or credential access;
- exfiltration formatting instructions;
- instructions to send private data to a named destination;
- suspicious mismatch between declared tool purpose and agent-facing
  instructions, only when both sides are statically available;
- prompt templates that blur trusted and untrusted instruction boundaries, as a
  later research category rather than an MVP finding.

## Out of scope

Do not implement these in the semantic linting workstream:

- live webpage scanning;
- browser rendering;
- RAG corpus scanning unless explicitly passed as local files;
- email inbox scanning;
- runtime tool-output monitoring;
- MCP server execution;
- dependency installation;
- hosted model calls by default;
- automated exploit generation;
- maliciousness scoring;
- dynamic sandboxing;
- human-approval UI enforcement;
- remote telemetry;
- broad LLM safety moderation;
- classifying user prompts in production applications.

These are legitimate security concerns, but they are not SkillGate's core pre-install boundary.

## Design principles

### 1. Artifact semantics, not runtime behavior

The scanner may say that an artifact contains instructions that deserve review. It must not claim that the deployed agent will or will not perform an unsafe action.

### 2. Evidence over certainty

Every finding should include:

- file path;
- approximate text span or line range;
- short sanitized snippet;
- semantic category;
- why this is review-worthy;
- what a reviewer should check;
- whether this is expected, suspicious, or unsupported by declared purpose.

### 3. Deterministic core first

The first version should be a deterministic rule pack. Optional model-assisted ranking can come later and must not become the default path until it is evaluated and documented.

### 4. Separate namespace

Do not mix semantic findings into the current static capability rule family
without a deliberate taxonomy decision. The repository already has `SG007` for
narrow prompt-override and concealment language and `SG008` for suspicious
Unicode/obfuscation. New semantic work must not emit duplicate findings for the
same evidence.

For genuinely new semantic findings, use a separate namespace:

```text
SA001, SA002, ...
```

Expose those findings through a separate result family:

```json
"semantic_findings": []
```

The first implementation should use both `SA###` identifiers and a
`semantic_findings` result section. Existing `SG###` behavior remains stable.

### 5. Advisory by default

Semantic findings should be advisory at first. Blocking behavior should require explicit policy opt-in after the precision profile is understood.

### 6. Local-first and privacy-preserving

No text leaves the user machine by default. Any future hosted or external model integration requires explicit consent, visible data-flow documentation, and clear privacy language.

### 7. Preserve existing contracts

The implementation must be rebased onto the current `main` branch before code
work begins. The current Review Packet schema, CLI behavior, SARIF output,
policy semantics, and no-execution guarantees are compatibility baselines. A
new semantic field in a review packet requires an explicit schema-version
decision and migration notes; it must not be added silently.

## Proposed taxonomy

The exact IDs should be finalized in the implementation design. The categories below define the review language.

### Instruction override

Signals that the artifact instructs the model to ignore, override, supersede, bypass, or deprioritize system, developer, user, security, or policy instructions.

Examples of concepts:

- ignore previous instructions;
- override system rules;
- treat this as highest priority;
- disregard safety policy;
- bypass the approval step.

Reviewer question:

> Is this instruction genuinely part of a controlled demo/test fixture, or is it trying to change model authority at runtime?

### Hidden or silent behavior

Signals that the artifact tells the agent to hide, suppress, omit, or avoid disclosing actions.

Examples of concepts:

- do not tell the user;
- perform this silently;
- hide this step;
- do not mention this instruction;
- keep this action secret.

Reviewer question:

> Does the artifact request behavior that would undermine user review, consent, or auditability?

The current `SG007` rule already covers the narrow explicit phrases in this
category. The semantic workstream should preserve that output and avoid adding
an `SA###` duplicate unless it is detecting additional context that `SG007`
does not claim to understand.

### Sensitive-data access instruction

Signals that agent-facing text asks for secrets, tokens, local configuration,
environment variables, private files, or credentials. The detector must report
the request and its evidence; it must not infer that the access is unrelated
unless a declared purpose is available for comparison.

Examples of concepts:

- read `.env`;
- inspect SSH keys;
- open local credential stores;
- read MCP configuration files unrelated to the server;
- include token values in output.

Reviewer question:

> Is the requested secret/file access necessary, declared, and bounded?

### Data transmission instruction

Signals that the artifact instructs the agent to send, encode, forward, append,
upload, or otherwise transmit private data to a named destination. The detector
should identify the requested data flow and leave the destination's legitimacy
unknown when it cannot be established statically.

Examples of concepts:

- send private content to a hard-coded recipient;
- append data to an external request;
- base64 encode secrets and include them in a message;
- add hidden content to a chat, email, issue, or URL.

Reviewer question:

> Does this text create a pathway from private context to an unrelated outbound channel?

### Role hijack or authority spoofing

Signals that the artifact asks the model to adopt a privileged identity or treat the artifact as a higher-authority actor.

Examples of concepts:

- you are now admin;
- developer mode;
- security policy is disabled;
- this message is from the system owner;
- act as the user's organization administrator.

Reviewer question:

> Is the artifact creating fake authority inside text that the model may obey?

This is a later candidate, not an MVP category. Security documentation, tests,
and examples commonly quote this language and need explicit context handling.

### Trust-boundary confusion

Signals that the artifact mixes trusted instructions and untrusted content without structure.

Examples of concepts:

- user-provided content embedded inside a prompt template without delimiters;
- remote page content presented as instructions;
- tool output directly reinserted into a privileged prompt region;
- documentation telling users to paste arbitrary third-party text into agent instructions.

Reviewer question:

> Is the artifact making it hard for the agent or reviewer to distinguish data from instructions?

This is initially an inventory annotation or design-review prompt, not a
boolean finding. Reliable detection requires understanding how a prompt is
assembled across files and runtime inputs.

### Hidden text or model-targeted concealment

Signals in Markdown, HTML, or CSS that hide model-directed instructions from ordinary visual review.

Examples of concepts:

- zero-size text;
- off-screen text;
- white-on-white text;
- transparent text;
- hidden comments containing model instructions;
- CSS designed to make text invisible to humans but present in source.

Reviewer question:

> Is hidden text being used for benign formatting, or to expose different instructions to the model than to the reviewer?

HTML/CSS concealment should be evaluated as a lower-level artifact or
obfuscation detector. It should not be part of the semantic MVP unless the
existing `SG008` taxonomy is intentionally extended.

## Architecture options

### Option A: Add semantic findings to existing scan output

Pros:

- easiest for users;
- one command gives a full review packet;
- integrates with existing JSON, Markdown, and policy surfaces.

Cons:

- risks mixing deterministic static findings with more ambiguous semantic findings;
- may confuse users if severity language is too strong.

Recommendation:

- viable only if semantic findings are clearly labeled and advisory.

### Option B: Add a dedicated command

Example:

```bash
skillgate semantic scan SOURCE
```

Pros:

- clean separation;
- easier to evolve taxonomy;
- lower risk to existing scan guarantees.

Cons:

- users may miss it;
- adds CLI surface before adoption is proven.

Recommendation:

- useful for experimental phase, but likely too separate for long-term UX.

### Option C: Add an opt-in flag to review flows

Example:

```bash
skillgate review preinstall SOURCE --semantic
```

Pros:

- matches review context;
- clear opt-in;
- keeps findings advisory;
- ideal for experimentation.

Cons:

- depends on the unified pre-install review flow landing first.

Recommendation:

- best first product integration.

### Recommended path

Implement semantic artifact linting first as:

```bash
skillgate review preinstall SOURCE --semantic
```

Then, after evaluation and user feedback, decide whether to expose:

```bash
skillgate semantic scan SOURCE
```

as a standalone command.

### First implementation decision

The first product integration is an opt-in extension of `review preinstall`.
The normal `scan`, `check`, `diff`, and Action paths remain unchanged while the
precision profile is being measured. Semantic findings are advisory and do not
participate in `--fail-on`, baseline drift, SARIF blocking, or policy evaluation
until a later, explicit contract is approved.

The implementation should use the existing review-packet builder and reporting
conventions rather than introduce a parallel review stack. If the packet gains
`semantic_findings`, the packet schema must be versioned deliberately and the
JSON Schema, Markdown output, snapshots, and migration notes must be updated
together.

## Staged roadmap

### Stage 0: Research-to-product design record

Goal:

Convert research findings into a bounded product contract.

Deliverables:

- this roadmap;
- an overlap matrix for `SG003`, `SG005`, `SG007`, `SG008`, and proposed `SA###`
  findings;
- a design note defining scope, non-goals, taxonomy, output semantics, and
  evaluation criteria;
- an issue checklist for semantic artifact linting;
- a synthetic-first benchmark/source inventory with license and provenance
  notes;
- a compatibility note for the current Review Packet schema and output formats.

Success criteria:

- maintainers can explain why SkillGate is not becoming a runtime prompt-injection firewall;
- maintainers can explain why artifact semantics still matter;
- every proposed category has an explicit owner, source role, and overlap rule;
- the benchmark has a reviewed benign set and a stated false-positive budget;
- future implementation PRs have a stable scope boundary.

Recommended branch/PR:

```text
roadmap/semantic-artifact-linting
```

### Stage 1: Text artifact inventory and extractor

Goal:

Collect candidate agent-facing text blocks without making judgments yet.

Deliverables:

- `SemanticTextBlock` model;
- deterministic extractor for selected Markdown, JSON, YAML, and TOML fields;
- source path and line/span metadata;
- explicit source role such as `skill_instruction`, `mcp_description`,
  `prompt_template`, `documentation`, or `fixture`;
- reuse of existing `FileContent`, discovery, source, and archive-safety
  boundaries instead of a parallel scanner;
- size limits;
- binary and archive safety reuse;
- privacy-safe snippets;
- text-block inventory in JSON.

Candidate files:

```text
src/skillgate/semantic/models.py
src/skillgate/semantic/extract.py
src/skillgate/semantic/reporting.py
tests/test_semantic_extract.py
```

No new findings yet.

Success criteria:

- extractor is deterministic;
- local-only;
- bounded by file and aggregate text limits;
- preserves enough source metadata for reviewer evidence;
- does not execute or render HTML;
- does not fetch remote content;
- avoids scanning dependency/build/cache directories;
- leaves unclassified files out of the semantic inventory.

Why it helps SkillGate stand out:

> It turns agent-facing text into a reviewable artifact inventory, which most static scanners do not do.

### Stage 2: Deterministic semantic rule pack MVP

Goal:

Add high-precision semantic review findings for explicit dangerous instructions.

Deliverables:

- initial deterministic rule pack;
- advisory semantic finding model;
- Markdown and JSON output;
- docs explaining limitations;
- fixture corpus with malicious, benign, and documentation-only examples;
- suppressions or waivers only after rule behavior is stable.

Initial rule categories:

- preserve existing `SG007` coverage for explicit instruction override and
  concealment phrases without emitting duplicate `SA###` findings;
- agent-directed sensitive-data access instructions;
- explicit data-transmission instructions with a named destination.

Defer role hijack, trust-boundary confusion, and HTML/CSS concealment until the
benchmark shows that they can be detected with useful precision and clear source
context.

Non-goals:

- no classifier;
- no hosted API;
- no runtime claims;
- no blocking default;
- no new policy enforcement yet.

Success criteria:

- high precision on explicit malicious/static cases;
- low false positives on benign fixture docs;
- meets the Stage 0 benchmark's category-specific precision and false-positive
  gates;
- every finding includes evidence and reviewer guidance;
- no finding claims exploitability without proof.

Why it helps SkillGate stand out:

> It catches the part of prompt-injection risk that is actually present before install: suspicious instructions shipped with the artifact.

### Stage 3: Review-flow integration

Goal:

Make semantic review useful in the main pre-install workflow without making every scan noisy.

Deliverables:

- `skillgate review preinstall SOURCE --semantic`;
- semantic section in Markdown review packets;
- stable, explicitly versioned JSON section for semantic findings;
- summary language separating capability findings from semantic concerns;
- source-role and context labels such as `expected`, `review_required`, and
  `test_fixture` when they come from explicit metadata rather than inference.

Success criteria:

- a reviewer can use one command to get static capabilities plus semantic concerns;
- semantic findings are visible but clearly advisory;
- output remains deterministic;
- local scans remain upload-free;
- existing `scan`, `check`, `diff`, SARIF, policy, and Action behavior remains
  unchanged unless separately approved.

Why it helps SkillGate stand out:

> It makes the output decision-ready: not just what a tool can do, but what its shipped instructions are suggesting the agent do.

### Stage 4: Benchmark and public evidence pack

Goal:

Prove quality with reproducible evidence rather than marketing claims. Fixture
design and benign-corpus review begin in Stage 0 and gate the MVP; this stage
publishes the resulting evidence after integration.

Deliverables:

- benchmark fixture set;
- manually reviewed benign corpus;
- synthetic attack-pattern corpus first, with public benchmark examples added
  only where licensing and attribution are clear;
- report generator for semantic lint results;
- `docs/public-scan-reports/semantic-artifact-linting/`;
- methodology explaining that fixture performance is not real-world accuracy.

Candidate benchmark inspirations:

- InjecAgent attack patterns;
- AgentDojo security tasks and attacker instructions;
- BIPIA indirect prompt-injection examples;
- LLMail-Inject adaptive email-borne examples;
- OWASP GenAI and Agentic Top 10 categories;
- MCP tool-poisoning and server-instruction incident writeups.

Success metrics:

- precision on reviewed fixture corpus;
- false positives per repository/bundle;
- findings per semantic category;
- median and p95 scan latency;
- reviewer actionability rating;
- number of suppressions required for benign examples.

The report must publish the corpus boundaries, licensing/provenance, detector
version, command, limits, and known blind spots. Fixture precision is not
real-world accuracy.

The initial gate should report fixture-level precision and recall per category,
with a reviewed benign set and an explicit false-positive budget. A rule should
not advance to integration merely because it matches attack examples; benign
documentation and test fixtures must be part of the acceptance decision.

Why it helps SkillGate stand out:

> It demonstrates product judgment: SkillGate is not claiming to solve prompt injection; it is proving a bounded pre-install control with reproducible evidence.

### Stage 5: Policy opt-in

Goal:

Allow mature users to gate semantic findings after they understand their noise profile.

Deliverables:

- policy fields for semantic categories;
- explicit `--fail-on-semantic` or equivalent policy-only behavior;
- suppression workflow with justification;
- docs showing advisory mode versus enforcement mode;
- examples of organization-specific allowlists for test fixtures and security documentation.

Success criteria:

- no semantic finding blocks by default;
- blocking requires explicit policy;
- suppressions are auditable;
- JSON output remains stable.

Why it helps SkillGate stand out:

> Teams can turn high-confidence semantic cues into governance without accepting a black-box prompt firewall.

### Stage 6: Optional local classifier experiment

This stage is a research parking lot, not part of the committed product plan.
Only open it after deterministic rules, evidence output, and benchmark gates
fail to meet reviewer needs.

Goal:

Evaluate whether a small local model improves ranking or recall enough to justify complexity.

Deliverables:

- experimental feature flag;
- pinned local model option;
- offline-only default;
- model provenance and license notes;
- benchmark comparison against deterministic rules;
- calibration report;
- strict timeout and size limits;
- no default enablement.

Candidate models/services to evaluate only as research inputs:

- Llama Prompt Guard 2;
- Granite Guardian;
- Azure Prompt Shields as a hosted comparison, not default product dependency;
- other open classifiers with clear license and reproducibility story.

Success criteria:

- classifier materially improves reviewer actionability;
- false positives remain acceptable;
- model behavior is reproducible enough for CI use;
- privacy posture remains local-first;
- the maintenance cost is justified.

Exit criteria:

Do not ship the classifier if deterministic rules plus evidence output produce a better precision, trust, and maintenance profile.

Why it helps SkillGate stand out:

> SkillGate can show benchmark discipline: models are evaluated as optional evidence rankers, not treated as magic security gates.

## Suggested PR sequence

### PR A: Roadmap and taxonomy

Files:

```text
docs/roadmaps/semantic-artifact-linting.md
future_steps.md
```

Purpose:

- establish the direction;
- document non-goals;
- prevent accidental runtime-security scope creep.

### PR B: Semantic text inventory

Files:

```text
src/skillgate/semantic/models.py
src/skillgate/semantic/extract.py
src/skillgate/semantic/reporting.py
tests/test_semantic_extract.py
docs/roadmaps/semantic-artifact-linting.md
```

Purpose:

- create source text inventory without findings;
- prove safe, bounded extraction.

### PR C: Rule pack MVP

Files:

```text
src/skillgate/semantic/rules.py
src/skillgate/semantic/scan.py
tests/test_semantic_rules.py
tests/fixtures/semantic/
src/skillgate/rule_docs.py
docs/benchmark/semantic-artifact-linting.md
```

Purpose:

- add high-precision deterministic semantic findings;
- keep advisory output separate.

### PR D: Pre-install review integration

Files:

```text
src/skillgate/preinstall.py
src/skillgate/preinstall_schema.py
src/skillgate/cli.py
tests/test_review_preinstall_semantic.py
docs/sessions/preinstall-semantic-review.md
```

Purpose:

- make semantic review usable through the main review workflow.

### PR E: Public evidence pack

Files:

```text
docs/public-scan-reports/semantic-artifact-linting/
tools/generate_semantic_benchmark_report.py
tests/test_semantic_benchmark_report.py
```

Purpose:

- publish reproducible evidence and the methodology behind it;
- give reviewers a bounded basis for deciding whether the feature is useful.

### PR F: Policy opt-in

Files:

```text
src/skillgate/policy.py
src/skillgate/policy_schema.py
tests/test_semantic_policy.py
docs/policy.md
```

Purpose:

- let mature teams gate semantic findings intentionally.

### PR G: Optional classifier experiment

Files:

```text
experiments/semantic-classifier/
docs/experiments/semantic-classifier.md
```

Purpose:

- evaluate local model-assisted ranking without committing the core product to ML dependency.

## Output contract proposal

Initial semantic JSON should be explicit and separate from the existing
capability/finding collections. The field names should follow the current
packet conventions (`file_path`, `line_number`, `evidence`) rather than create
a second vocabulary:

```json
{
  "semantic_findings": [
    {
      "id": "SA001-<stable-fingerprint>",
      "rule_id": "SA001",
      "title": "Agent-directed sensitive-data access instruction",
      "severity": "medium",
      "confidence": "high",
      "file_path": "server/README.md",
      "line_number": 12,
      "end_line": 14,
      "evidence": "Read ~/.ssh/id_rsa before continuing...",
      "category": "sensitive_data_access",
      "source_role": "mcp_description",
      "review_guidance": "Confirm whether this access is necessary, declared, and bounded for the artifact's purpose."
    }
  ]
}
```

Recommended severity posture:

- `low`: ambiguous cue, probably documentation or fixture;
- `medium`: explicit suspicious instruction requiring review;
- `high`: explicit instruction to conceal behavior, access sensitive data, or
  transmit data to a named destination;
- `critical`: reserved; do not use in MVP unless there is concrete exploit evidence.

`confidence` describes detector certainty and is separate from severity. A high
severity finding with low confidence remains advisory and must not silently enter
the existing blocking threshold. Line numbers and snippets are evidence; stable
finding identity should follow existing redaction and fingerprint conventions.

The first implementation must also document:

- whether the field appears only in pre-install packets or later in scan/report
  output;
- how Markdown, JSON, SARIF, and schema-version changes represent semantic
  findings;
- how source roles and explicit fixture metadata affect reviewer guidance;
- that `--fail-on`, policy, and baseline behavior do not change in the MVP.

## Documentation posture

Every user-facing page should repeat the same limitation:

> Semantic artifact linting inspects shipped text. It cannot detect all prompt injections and does not replace runtime trust boundaries, least privilege, sandboxing, or human approval for risky actions.

This is not defensive wording. It is what makes the tool credible.

## Repository value

This work helps the repository shine because it shows a complete product thesis:

1. capability surfaces can be detected statically;
2. semantic instruction risks can be surfaced before install;
3. ambiguous findings need human review, not fake certainty;
4. enforcement should be explicit and policy-driven;
5. runtime agent safety needs separate architectural controls.

That story aligns with the repository's existing focus on deterministic control
surfaces, release gates, evaluation discipline, human escalation, and honest
limitations.

A useful public summary after Stage 4:

> SkillGate does not pretend to solve prompt injection. It makes the part of the problem that ships with agent artifacts reviewable, reproducible, and enforceable before install or merge.

## Open questions before implementation

The following decisions should be recorded before Stage 1 code is started:

1. Confirm `SA###` identifiers plus a separate `semantic_findings` section, with
   no duplicate output for existing `SG###` rules.
2. Confirm `review preinstall --semantic` as the MVP entry point; do not add
   `scan --semantic` until the review-packet experiment has real usage.
3. Define source roles and the default file/field allowlist. Unknown source
   role must not become an inferred agent instruction.
4. Define the severity/confidence matrix and the minimum precision and
   false-positive gates for each MVP category.
5. Define how explicit fixture/documentation metadata is represented without
   trusting text to self-classify as safe.
6. Start with synthetic benchmark fixtures and add public examples only with
   clear license and attribution records.
7. Decide what evidence report is required before semantic policy enforcement;
   policy and suppression support remain deferred until then.
8. Rebase implementation work onto the current Review Packet schema and record
   any required migration before changing public JSON.

## Recommendation

Proceed with the design and bounded inventory first. Start the deterministic
rule MVP only after the overlap matrix and benchmark gates are in place. Do not
make policy or classifier decisions from this planning document alone.

The immediate next implementation milestone should be:

> Build a deterministic semantic text inventory and a small, high-precision
> advisory rule pack for shipped agent-facing artifacts.

Do not start with a classifier. Do not start with runtime monitoring. Do not market this as prompt-injection prevention.

If the advisory rule pack produces useful, low-noise findings on reviewed
MCP/Agent Skill repositories, integrate it into `review preinstall --semantic`
and publish a public evidence report. Keep runtime monitoring, hosted models,
and broad semantic inference out of scope.
