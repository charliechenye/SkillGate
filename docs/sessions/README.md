# SkillGate Review Sessions

These sessions are short, copy-pasteable workflows for the three moments where
SkillGate is most useful: before installing an agent artifact, before merging a
change, and when approving a capability for ongoing use.

They use deterministic local demos where possible. SkillGate does not execute
the demo helper, install packages, start MCP servers, or send telemetry.

Sessions:

- [01 — First local review](01-first-local-review.md): connect skill metadata,
  observed capabilities, and reviewer output.
- [02 — Pre-install review](02-preinstall-review.md): inspect a public skill or
  MCP bundle before it enters a workstation.
- [03 — Approval and CI](03-approval-and-ci.md): turn a reviewed capability set
  into a policy, baseline, and pull-request artifact.

Each session ends with a decision checkpoint. A finding is a review signal, not
an automatic malware verdict; approve only the specific behavior you understand.
