# Maintainer Pilot: Pre-Install Review

The next product check is three maintainer sessions, each using one skill the
maintainer already owns or intends to review. Participants have not been
recruited. The owner must choose recipients and authorize invitations before
any messages are sent.

Allow 20 minutes per session. After `v0.1.5` is published, start with:

```bash
python -m pip install "git+https://github.com/charliechenye/SkillGate.git@v0.1.5"
skillgate --version
skillgate review preinstall SOURCE --output review.md --json-output review.json
skillgate review preinstall SOURCE --require-complete --fail-on high \
  --output gated-review.md
```

Use a local materialized directory or a GitHub subtree URL pinned to its full
commit SHA. Reviewing a skill never requires installing or running that skill.
Keep packets local unless the participant explicitly agrees to share them.

Record these observations without coaching the participant through the report:

1. Can they identify the source revision and reviewed files?
2. Can they explain each coverage gap and the gate's exit code?
3. Which capability evidence is useful, irrelevant, or misleading?
4. What concrete change or approval would they make after reading the packet?
5. Can they reproduce the review and understand that `complete` is not safety?

For each session, record the artifact's immutable identity, scanner version,
time to first useful decision, confusing output, concrete next action, and
consented follow-up. Use anonymous session IDs in public notes. There is no
automatic upload or collection.

Advance adoption docs when all three maintainers can explain coverage and make
a concrete decision. A failed session should produce a small usability or
detection issue with authored reproduction input. Do not infer a detection
accuracy percentage from three sessions.

Invitation draft, to be personalized and sent only after authorization:

> I'm testing SkillGate's static pre-install review for agent skills. Could you
> try a 20-minute review of one skill you maintain? It reads files without
> running the skill, and reports capabilities, findings, and coverage gaps.
> The useful feedback is whether the report changes a real review decision and
> where it wastes your time. Your files and reports can stay local.
