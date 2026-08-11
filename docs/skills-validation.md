# Agent Skills Validation

`skillgate skills validate PATH` is a deterministic, local-first check for
Agent Skills authors. It validates structure and metadata before a skill is
published, installed, or reviewed. It does not execute skill instructions or
scripts.

## Quick Start

Validate a skill directory:

```bash
skillgate skills validate path/to/my-skill
```

Validate one `SKILL.md` directly or produce machine-readable output:

```bash
skillgate skills validate path/to/my-skill/SKILL.md
skillgate skills validate path/to/my-skill.zip
skillgate skills validate . --format json --output skillgate-skills.json
skillgate skills validate skills/ --fail-on medium
```

For a packaged first-run example that can be validated and scanned without
executing helper files:

```bash
skillgate demo skill --output test-outputs/reviewable-demo --validate --scan
```

Exit codes are `0` for a completed validation that does not meet the selected
threshold, `1` when `--fail-on` is met, and `2` for an invalid or unreadable
input path.

## What It Checks

- required `name` and `description` frontmatter fields;
- lowercase slug-style names and matching skill directory names;
- optional `license` and `compatibility` guidance;
- `allowed-tools` as a list of strings, including review findings for broad
  entries such as `*`, `bash`, `shell`, `python`, and `node`;
- local links and script references under `scripts/`, `references/`, and
  `assets/`;
- executable or script-like files outside the `scripts/` directory.

The command discovers a direct `SKILL.md`, a directory containing `SKILL.md`,
and recursive skill layouts such as `skills/**/SKILL.md`,
`.agents/skills/**/SKILL.md`, and `.claude/skills/**/SKILL.md`.

ZIP inputs are inspected through SkillGate's bounded archive layer. The archive
must contain a regular file named `SKILL.md` at its root. SkillGate extracts it
into a temporary directory with traversal, symlink, special-file, compression,
encryption, nested-archive, and resource-limit checks before validating the
contents. The temporary path is never included in the report; JSON instead
includes an `archive` manifest with the archive digest, limits, and sorted
member hashes. The archive root is reported as `.` because the package
directory name is not a reliable source for `SKILL004`.

## Output

Text output is designed for a quick author feedback loop. JSON output includes
`schema_version`, `tool_version`, `root`, `skills`, `findings`, and `summary`,
with stable finding codes from `SKILL001` through `SKILL009`. ZIP reports add
the deterministic `archive` manifest described above.

## Limitations

This is structural validation, not runtime enforcement. SkillGate does not
execute code, resolve packages, start services, make network calls, or make a
malware determination. ZIP validation supports ZIP-compatible stored and
deflated members only; it does not implement TAR/RAR/7z support or an
MCP-delivered `index.json`/digest contract. It also does not compare declared
capabilities with capabilities observed during execution. That
declared-vs-observed diff remains a future workflow.
