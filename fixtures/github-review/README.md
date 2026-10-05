# GitHub Skill Review Regression Fixtures

These reduced, nonverbatim fixtures reproduce public skill input shapes found
on October 3, 2026. They are inputs for the mocked GitHub adapter tests, not
claims about the security of their upstream projects.

`review-demo` combines framework/domain names in prose, a Markdown reference,
and bundled references and helpers that are not named in `SKILL.md`. Its helpers deliberately
exits before an inert remote-download command. Tests read it as text and never
execute them. The same fixture verifies local/GitHub pre-install file, finding,
and capability parity. `expected-findings.yaml` records the expected scan signals
and source attribution; it is fixture metadata, not part of the remote artifact.
