# Session 01 — First local review

## Goal

In five minutes, see how SkillGate connects an Agent Skill's declared metadata
to capabilities observed in its local helper files.

## Start with a deterministic input

```bash
mkdir -p test-outputs
skillgate demo skill \
  --output test-outputs/reviewable-demo \
  --validate \
  --scan
```

The demo is synthetic and uses `downloads.example.invalid`. The helper is
never executed and no network request is made.

## Inspect the two views

Validate the skill's structure and declared metadata:

```bash
skillgate skills validate test-outputs/reviewable-demo
```

Scan the files that carry behavior:

```bash
skillgate scan test-outputs/reviewable-demo
skillgate review summary test-outputs/reviewable-demo \
  --output test-outputs/reviewable-demo-summary.md
```

You should see a broad `allowed-tools` declaration in validation output and
shell, network, and remote-download findings in the scan. The point is not that
the synthetic skill is malicious; the point is that a reviewer can see what the
skill would make possible before allowing it into a real environment.

## Decision checkpoint

Ask:

1. Is the helper script needed for the skill's stated purpose?
2. Is the remote host owned and expected?
3. Should a shell tool and remote download be approved together?

If the answer is not clear, keep the artifact in review. Do not turn a finding
into an approval merely because the command is short.
