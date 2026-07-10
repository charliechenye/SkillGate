# Pre-install starter repository

Copy [`examples/preinstall-starter/`](../examples/preinstall-starter/) when a
new Agent Skill repository needs a safe first review. It demonstrates the full
adoption path without requiring a real third-party package or executing any
repository content.

The starter workflow has two deliberate modes:

- Pull requests retain Markdown, JSON, and SARIF as artifacts. Findings remain
  reviewable but do not create a blocking Code Scanning status.
- Pushes to `main` and manual runs publish SARIF to Code Scanning for durable
  visibility.

After reviewers approve the observed capability surface, add a reviewed policy
to the Action or adopt a baseline with `fail-on-drift: "true"`. Keep that
enforcement decision separate from the advisory pre-install packet.
