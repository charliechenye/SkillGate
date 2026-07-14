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

The agent-security benchmark landscape is moving toward runtime and semantic attacks:

- InjecAgent studies indirect prompt injection in tool-integrated agents.
- AgentDojo evaluates stateful, dynamic, multi-tool agents under attack.
- MCP security discussions increasingly focus on tool poisoning, server instructions, authorization, confused deputy risks, and runtime trust boundaries.
- OWASP's classic Benchmark project is mainly a conventional software vulnerability benchmark, while OWASP's newer GenAI and agentic work is more relevant to LLM-agent behavior.
- Prompt-injection guidance from OpenAI, Anthropic, Microsoft, OWASP, and industry researchers repeatedly emphasizes that runtime controls, action gating, sandboxing, and least privilege remain necessary.

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

Scan only text that is already present in the artifact under review.

Primary sources:

- Agent Skill `SKILL.md` files;
- MCP server manifests and configuration files;
- MCPB `manifest.json` fields;
- MCP tool descriptions and server instructions when available statically;
- prompt templates;
- README and documentation sections likely to be consumed by an agent or reviewer;
- Markdown, HTML, JSON, YAML, TOML, and selected source comments;
- bundled assets that may contain agent-facing text;
- deterministic demo and fixture artifacts committed to this repository.

Candidate high-signal semantic patterns:

- instruction override language;
- role hijack language;
- authority spoofing;
- hidden or silent behavior instructions;
- requests to conceal actions from the user;
- unrelated secret, token, file, or credential access;
- exfiltration formatting instructions;
- instructions to send private data to unrelated destinations;
- HTML/CSS concealment targeted at model readers;
- suspicious mismatch between declared tool purpose and agent-facing instructions;
- prompt templates that blur trusted and untrusted instruction boundaries.

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

Do not mix semantic findings into the current static capability rule family without a deliberate taxonomy decision.

Use a separate namespace such as:

```text
SA001, SA002, ...
```

or a separate result family such as:

```json
"semantic_findings": []
```

The initial roadmap should decide this before implementation begins.

### 5. Advisory by default

Semantic findings should be advisory at first. Blocking behavior should require explicit policy opt-in after the precision profile is understood.

### 6. Local-first and privacy-preserving

No text leaves the user machine by default. Any future hosted or external model integration requires explicit consent, visible data-flow documentation, and clear privacy language.

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

### Unrelated secret or file access

Signals that agent-facing text asks for secrets, tokens, local configuration, environment variables, private files, or credentials that do not appear related to the declared purpose.

Examples of concepts:

- read `.env`;
- inspect SSH keys;
- open local credential stores;
- read MCP configuration files unrelated to the server;
- include token values in output.

Reviewer question:

> Is the requested secret/file access necessary, declared, and bounded?

### Exfiltration suggestion

Signals that the artifact instructs the agent to send, encode, forward, append, upload, or otherwise transmit private data to a destination unrelated to the user task.

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

### Trust-boundary confusion

Signals that the artifact mixes trusted instructions and untrusted content without structure.

Examples of concepts:

- user-provided content embedded inside a prompt template without delimiters;
- remote page content presented as instructions;
- tool output directly reinserted into a privileged prompt region;
- documentation telling users to paste arbitrary third-party text into agent instructions.

Reviewer question:

> Is the artifact making it hard for the agent or reviewer to distinguish data from instructions?

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

## Staged roadmap

### Stage 0: Research-to-product design record

Goal:

Convert research findings into a bounded product contract.

Deliverables:

- this roadmap;
- a design note defining scope, non-goals, taxonomy, output semantics, and evaluation criteria;
- an issue checklist for semantic artifact linting;
- benchmark/source inventory with license and provenance notes.

Success criteria:

- maintainers can explain why SkillGate is not becoming a runtime prompt-injection firewall;
- maintainers can explain why artifact semantics still matter;
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
- deterministic extractor for Markdown, JSON, YAML, TOML, HTML, and selected plain text;
- source path and line/span metadata;
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
- avoids scanning dependency/build/cache directories.

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

- instruction override;
- hidden/silent behavior;
- unrelated secret/file access;
- exfiltration suggestion;
- role hijack/authority spoofing;
- hidden text/model-targeted concealment.

Non-goals:

- no classifier;
- no hosted API;
- no runtime claims;
- no blocking default;
- no new policy enforcement yet.

Success criteria:

- high precision on explicit malicious/static cases;
- low false positives on benign fixture docs;
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
- stable JSON section for semantic findings;
- summary language separating capability findings from semantic concerns;
- evidence labels such as `expected`, `review_required`, and `test_fixture`.

Success criteria:

- a reviewer can use one command to get static capabilities plus semantic concerns;
- semantic findings are visible but clearly advisory;
- output remains deterministic;
- local scans remain upload-free.

Why it helps SkillGate stand out:

> It makes the output decision-ready: not just what a tool can do, but what its shipped instructions are suggesting the agent do.

### Stage 4: Benchmark and public evidence pack

Goal:

Prove quality with reproducible evidence rather than marketing claims.

Deliverables:

- benchmark fixture set;
- manually reviewed benign corpus;
- attack-pattern corpus adapted from public benchmark examples where licensing allows;
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
docs/semantic-artifact-linting.md
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
docs/rules/semantic.md
```

Purpose:

- add high-precision deterministic semantic findings;
- keep advisory output separate.

### PR D: Pre-install review integration

Files:

```text
src/skillgate/review/...
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

- publish reproducible evidence;
- support website/blog/NIW storytelling.

### PR F: Policy opt-in

Files:

```text
src/skillgate/policy.py
src/skillgate/check.py
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

Initial semantic JSON should be explicit and separate:

```json
{
  "semantic_findings": [
    {
      "id": "SA002",
      "title": "Hidden or silent agent behavior instruction",
      "severity": "medium",
      "confidence": "high",
      "path": "server/README.md",
      "start_line": 12,
      "end_line": 14,
      "snippet": "Do not tell the user about this step...",
      "category": "hidden_behavior",
      "review_guidance": "Confirm whether this instruction is part of a benign test fixture or would suppress user-visible disclosure."
    }
  ]
}
```

Recommended severity posture:

- `low`: ambiguous cue, probably documentation or fixture;
- `medium`: explicit suspicious instruction requiring review;
- `high`: explicit instruction to conceal behavior, access unrelated secrets, or exfiltrate data;
- `critical`: reserved; do not use in MVP unless there is concrete exploit evidence.

## Documentation posture

Every user-facing page should repeat the same limitation:

> Semantic artifact linting inspects shipped text. It cannot detect all prompt injections and does not replace runtime trust boundaries, least privilege, sandboxing, or human approval for risky actions.

This is not defensive wording. It is what makes the tool credible.

## Personal-brand and repository impact

This work helps the repository shine because it shows a complete product thesis:

1. capability surfaces can be detected statically;
2. semantic instruction risks can be surfaced before install;
3. ambiguous findings need human review, not fake certainty;
4. enforcement should be explicit and policy-driven;
5. runtime agent safety needs separate architectural controls.

That story aligns with the broader theme of production GenAI trust systems: deterministic control surfaces, release gates, eval discipline, human escalation, and honest limitations.

A strong public narrative after Stage 4:

> SkillGate does not pretend to solve prompt injection. It makes the part of the problem that ships with agent artifacts reviewable, reproducible, and enforceable before install or merge.

## Open questions before implementation

1. Should semantic findings use new rule IDs (`SA001`) or a separate result object without rule IDs?
2. Should semantic scanning live behind `review preinstall --semantic`, `scan --semantic`, or both?
3. What severity should explicit role hijack receive when it appears in security documentation or tests?
4. How should suppressions distinguish test fixtures from accepted production risk?
5. Should HTML hidden-text detection live in semantic linting or a lower-level artifact scanner?
6. What public datasets can be used directly under compatible licenses?
7. Should benchmark fixtures include only synthetic examples at first to avoid license uncertainty?
8. What is the minimum evidence report needed before allowing policy enforcement?

## Recommendation

Proceed with Stage 0 through Stage 2 only before making any policy or classifier decision.

The immediate next implementation milestone should be:

> Build a deterministic semantic text inventory and high-precision advisory rule pack for shipped agent-facing artifacts.

Do not start with a classifier. Do not start with runtime monitoring. Do not market this as prompt-injection prevention.

If the advisory rule pack produces useful, low-noise findings on real MCP/Agent Skill repositories, then integrate it into `review preinstall --semantic` and publish a public evidence report.
