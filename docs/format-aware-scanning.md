# Format-Aware Scanning

SkillGate preserves the original source as the canonical input. Format-aware
scanning adds a bounded logical view for content whose meaning continues across
physical line breaks; it never rewrites files, evaluates code, or changes file
hashes.

## Defaults

Existing enforcement commands remain physical-line compatible by default:

```bash
skillgate scan .
skillgate check . --policy skillgate.yaml
skillgate diff . --baseline skillgate.lock
```

Opt in when reviewing an artifact that may have been wrapped or poorly
formatted:

```bash
skillgate scan . --format-aware
skillgate check . --policy skillgate.yaml --format-aware
skillgate diff . --baseline skillgate.lock --format-aware
```

`skillgate review preinstall SOURCE` enables format-aware analysis automatically
because its purpose is advisory inspection of an untrusted artifact. Existing
blocking CI can adopt `--format-aware` deliberately after reviewing the new
findings it may expose.

## What is normalized

The derived view supports only bounded, format-specific cases:

- CRLF, CR, BOM, and Unicode line separators;
- explicit shell and language continuations;
- Markdown paragraph wrapping outside headings, lists, blockquotes, and code
  fences;
- local script paths split around a separator or Markdown line break;
- valid multiline JSON and YAML through their normal parsers.

Logical spans are limited to eight physical lines and 4 KiB. The reported line
is the first physical line, and evidence retains the original span. Raw source
hashes and baseline files remain unchanged.

Invalid JSON/YAML is not repaired by deleting line breaks. The parser reports a
stable parse finding, while lexical analysis remains conservative. Workflow and
job YAML is not added to default repository discovery by this feature.

## Local-only behavior

Format-aware scanning does not execute scripts, install packages, start MCP
servers, contact model APIs, or make network requests. The Skill-Inject adapter
uses the same local-only behavior and enforces its coverage gates with:

```bash
uv run python tools/benchmark_skill_inject.py /path/to/local/skill-inject \
  --format markdown --enforce-gates
```

The benchmark requires an explicitly supplied local checkout. It does not fetch
or update the corpus.

## CI adoption

Use format-aware mode first in advisory review jobs and artifacts. When adopting
it in a blocking job, review the resulting findings and update policy or
baseline deliberately. The existing physical-line command remains available
for compatibility while repositories migrate.
