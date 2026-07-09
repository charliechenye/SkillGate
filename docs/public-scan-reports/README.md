# Public Scan Reports

These reports are small, reproducible examples of how SkillGate output should be
read before installing or approving agent artifacts.

The reports use committed fixtures or deterministic demo inputs so they can be
reviewed without network access and without copying third-party repositories
verbatim. They are evidence of scanner behavior, not claims that a real upstream
maintainer shipped a vulnerability.

Reports:

- [Clean documentation skill](clean-documentation-skill.md)
- [Remote download review item](remote-download-review-item.md)
- [Reviewable MCPB demo bundle](mcpb-reviewable-node.md)

The reports marked with scanner version `0.1.1` are intentionally preserved as
historical release evidence. New release documentation and packaged demos use
`0.1.2`.

Each report records the exact command, scanner version, source identity,
capability inventory, findings summary, interpretation, limitations, suggested
policy direction, and what SkillGate cannot conclude.
