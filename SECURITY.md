# Security Policy

SkillGate is a static trust-checking tool for AI-agent skills, MCP configurations, instruction files, and helper scripts. It is designed to help reviewers detect risky capabilities and unapproved changes before installation or merge.

## Reporting A Vulnerability

Please report security issues through GitHub Security Advisories:

https://github.com/charliechenye/SkillGate/security/advisories/new

If advisories are not available, open a minimal GitHub issue that avoids publishing exploit details and ask for a private reporting path.

## What To Report

Please report issues such as:

- Secret values appearing in output where they should be redacted.
- Incorrect handling of policy files that could allow a blocked capability.
- Unsafe behavior in sparse GitHub fetching or temporary file cleanup.
- SARIF, JSON, or text output that misrepresents severity or affected files.
- A parser crash on ordinary skill, MCP, or configuration files.

## Threat Model Boundaries

SkillGate does not execute repository code, run package scripts, start MCP servers, call LLMs, send telemetry, or prove that a skill is safe. It should be used alongside sandboxing, runtime monitoring, least-privilege secrets, and human review.

## Supported Versions

Security fixes target the latest released version unless otherwise noted in the issue or advisory.
